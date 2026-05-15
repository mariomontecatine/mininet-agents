"""
Agente de inyección de anomalías.

Genera ataques sintéticos sobre la topología Mininet activa:
  * port_scan      — un host barre TCP/ICMP a muchos destinos (fan-out)
  * dos_volumetric — un host satura otro con iperf -u a alta tasa
  * ddos_fanin     — varios hosts inundan a una víctima en paralelo

Cada inyección se anota en `tmp/anomaly_injections.jsonl` (un JSON por línea)
para que `anomaly_report.py` pueda correlacionarlas a posteriori con las
acciones tomadas por el resolver.

NO contiene lógica de detección. Las heurísticas de detección viven en
`monitor_agent` y son intencionadamente independientes para poder medir
con honestidad cuántos ataques detecta el bucle completo.
"""

import os
import sys
import json
import time
import random
import threading
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config
from utils.ssh_client import get_ssh_connection, send_tmux_command


TMP_DIR        = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
INJECTION_LOG  = os.path.join(TMP_DIR, "anomaly_injections.jsonl")
HOST_PORT_FILE = os.path.join(TMP_DIR, "host_port_map.json")

ATTACK_TYPES = ("port_scan", "dos_volumetric", "ddos_fanin")

# Estado interno del scheduler — se accede solo desde el hilo del supervisor.
_state = {
    "last_inject_ts": 0.0,    # epoch del último ataque (para cooldown)
    "rng":            random.Random(config.ANOMALY_RNG_SEED),
}


# ── Mapping host → puerto OVS ────────────────────────────────────────────────

def build_host_port_map():
    """
    Construye {host_name: switch_port} usando agents.topology.get_topology_links().
    Lo persiste en tmp/host_port_map.json para que anomaly_report.py pueda
    leerlo sin necesidad de SSH.

    Llamar UNA vez tras el despliegue. Si la topología cambia hay que rellamar.
    """
    from agents.topology import get_topology_links

    links = get_topology_links()
    host_port = {}
    for n1, i1, n2, i2 in links:
        # Conexión host↔switch: una punta empieza por h/srv, la otra por s
        if (n1.startswith("h") or n1.startswith("srv")) and n2.startswith("s"):
            host_port[n1] = f"{n2}-{i2}"
        elif (n2.startswith("h") or n2.startswith("srv")) and n1.startswith("s"):
            host_port[n2] = f"{n1}-{i1}"
    try:
        with open(HOST_PORT_FILE, "w", encoding="utf-8") as f:
            json.dump(host_port, f, indent=2)
    except IOError:
        pass
    return host_port


def load_host_port_map():
    """Carga la última versión persistida. Si no existe → {}."""
    if not os.path.exists(HOST_PORT_FILE):
        return {}
    try:
        with open(HOST_PORT_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


# ── Logging ───────────────────────────────────────────────────────────────────

def _log_injection(record):
    """Anota un ataque en INJECTION_LOG (append-only, una línea JSON)."""
    os.makedirs(TMP_DIR, exist_ok=True)
    try:
        with open(INJECTION_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except IOError:
        pass


def _new_injection_id():
    return "INJ-" + datetime.now().strftime("%Y%m%dT%H%M%S") + f"-{random.randint(100,999)}"


def get_recent_injections(window_sec=300):
    """Lee el log y devuelve las inyecciones cuya ts_start está dentro de window_sec."""
    if not os.path.exists(INJECTION_LOG):
        return []
    cutoff = time.time() - window_sec
    out = []
    try:
        with open(INJECTION_LOG, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = rec.get("ts_start_epoch", 0)
                if ts >= cutoff:
                    out.append(rec)
    except IOError:
        pass
    return out


# ── Lanzadores de ataques (envían comandos vía tmux a mininet>) ──────────────

def _send(ssh, cmd):
    """Envia un comando a la sesión mininet> sin bloquear."""
    send_tmux_command(ssh, cmd)
    time.sleep(0.05)


def _attack_port_scan(ssh, src_host, target_ips, duration):
    """
    Barre target_ips desde src_host con ráfagas cortas de ping.
    50 paquetes a 0.05 s/paquete = ~2.5 s por destino → ~12 destinos en 30 s.
    """
    # Sin escapes para evitar problemas con tmux. Bash conecta con un &.
    ip_list = " ".join(target_ips)
    cmd = (
        f"{src_host} bash -c "
        f"'for ip in {ip_list}; do ping -c 50 -i 0.05 -W 1 $ip >/dev/null 2>&1; done' &"
    )
    _send(ssh, cmd)


def _attack_dos_volumetric(ssh, src_host, victim_host, victim_ip, bw_mbit, duration):
    """Inunda victim_ip desde src_host con iperf UDP a bw_mbit Mbps durante duration s."""
    # Servidor iperf -u en la víctima (puerto 5050, separado del tráfico normal)
    _send(ssh, f"{victim_host} iperf -s -u -p 5050 >/dev/null 2>&1 &")
    time.sleep(0.3)
    _send(ssh,
          f"{src_host} iperf -c {victim_ip} -u -p 5050 "
          f"-b {bw_mbit}M -t {duration} >/dev/null 2>&1 &")


def _attack_ddos_fanin(ssh, attackers, victim_host, victim_ip, bw_each_mbit, duration):
    """attackers (lista de hostnames) inundan en paralelo a victim_ip."""
    _send(ssh, f"{victim_host} iperf -s -u -p 5050 >/dev/null 2>&1 &")
    time.sleep(0.3)
    for a in attackers:
        _send(ssh,
              f"{a} iperf -c {victim_ip} -u -p 5050 "
              f"-b {bw_each_mbit}M -t {duration} >/dev/null 2>&1 &")


# ── Scheduler público ────────────────────────────────────────────────────────

def maybe_inject_anomaly(endpoints, force_type=None):
    """
    Decide estocásticamente si inyectar y, en su caso, lanza un ataque.

    Devuelve el registro de la inyección, o None si no inyectó.
    force_type ∈ {"port_scan","dos_volumetric","ddos_fanin"} fuerza un tipo
    (útil para tests; no respeta probabilidad ni cooldown).
    """
    rng = _state["rng"]
    now = time.time()

    if force_type is None:
        # Cooldown
        if now - _state["last_inject_ts"] < config.ANOMALY_COOLDOWN:
            return None
        if rng.random() >= config.ANOMALY_PROBABILITY:
            return None

    hosts = {n: ip for n, ip in (endpoints or {}).items()
             if (n.startswith("h") or n.startswith("srv")) and ip}
    if len(hosts) < 2:
        return None

    host_port = load_host_port_map()
    attack_type = force_type or rng.choice(ATTACK_TYPES)
    duration = rng.randint(config.ANOMALY_MIN_DURATION, config.ANOMALY_MAX_DURATION)

    try:
        ssh = get_ssh_connection()
    except Exception as e:
        print(f"[ANOMALY] No se pudo abrir SSH: {e}")
        return None

    rec = {
        "id":              _new_injection_id(),
        "type":            attack_type,
        "ts_start":        datetime.now().isoformat(timespec="seconds"),
        "ts_start_epoch":  now,
        "ts_end_planned":  datetime.fromtimestamp(now + duration).isoformat(timespec="seconds"),
        "duration_sec":    duration,
    }

    host_names = list(hosts.keys())
    try:
        if attack_type == "port_scan":
            src = rng.choice(host_names)
            others = [(n, ip) for n, ip in hosts.items() if n != src]
            # Hasta 12 destinos
            sample = others if len(others) <= 12 else rng.sample(others, 12)
            target_ips = [ip for _, ip in sample]
            _attack_port_scan(ssh, src, target_ips, duration)
            rec.update({
                "attacker":      src,
                "attacker_ip":   hosts[src],
                "attacker_port": host_port.get(src),
                "victims":       [n for n, _ in sample],
                "victim_ips":    target_ips,
            })

        elif attack_type == "dos_volumetric":
            src = rng.choice(host_names)
            victim_candidates = [n for n in host_names if n != src]
            victim = rng.choice(victim_candidates)
            bw = rng.randint(150, 300)
            _attack_dos_volumetric(ssh, src, victim, hosts[victim], bw, duration)
            rec.update({
                "attacker":      src,
                "attacker_ip":   hosts[src],
                "attacker_port": host_port.get(src),
                "victim":        victim,
                "victim_ip":     hosts[victim],
                "victim_port":   host_port.get(victim),
                "bw_mbit":       bw,
            })

        elif attack_type == "ddos_fanin":
            if len(host_names) < 4:
                # Necesita ≥3 atacantes + 1 víctima. Si no, fallback a DoS.
                attack_type = "dos_volumetric"
                rec["type"] = "dos_volumetric"
                src = rng.choice(host_names)
                victim_candidates = [n for n in host_names if n != src]
                victim = rng.choice(victim_candidates)
                bw = rng.randint(150, 300)
                _attack_dos_volumetric(ssh, src, victim, hosts[victim], bw, duration)
                rec.update({
                    "attacker": src, "attacker_ip": hosts[src],
                    "attacker_port": host_port.get(src),
                    "victim": victim, "victim_ip": hosts[victim],
                    "victim_port": host_port.get(victim),
                    "bw_mbit": bw,
                    "note": "fallback desde ddos_fanin por hosts insuficientes",
                })
            else:
                victim = rng.choice(host_names)
                pool = [n for n in host_names if n != victim]
                n_attackers = min(3, len(pool))
                attackers = rng.sample(pool, n_attackers)
                bw_each = rng.randint(60, 120)
                _attack_ddos_fanin(ssh, attackers, victim, hosts[victim], bw_each, duration)
                rec.update({
                    "attackers":     attackers,
                    "attacker_ips":  [hosts[a] for a in attackers],
                    "attacker_ports": [host_port.get(a) for a in attackers],
                    "victim":        victim,
                    "victim_ip":     hosts[victim],
                    "victim_port":   host_port.get(victim),
                    "bw_each_mbit":  bw_each,
                })
        else:
            return None

    except Exception as e:
        print(f"[ANOMALY] Fallo al lanzar {attack_type}: {e}")
        return None
    finally:
        try: ssh.close()
        except Exception: pass

    _log_injection(rec)
    _state["last_inject_ts"] = now

    desc = _describe(rec)
    print(f"\n🟠 [ANOMALY INJECTED] {rec['id']} {desc}")
    return rec


def _describe(rec):
    t = rec.get("type")
    if t == "port_scan":
        return (f"port_scan: {rec['attacker']} → {len(rec.get('victims', []))} destinos, "
                f"{rec['duration_sec']}s")
    if t == "dos_volumetric":
        return (f"dos_volumetric: {rec['attacker']} → {rec['victim']} "
                f"@ {rec.get('bw_mbit')}Mbps, {rec['duration_sec']}s")
    if t == "ddos_fanin":
        return (f"ddos_fanin: {', '.join(rec.get('attackers', []))} → {rec['victim']} "
                f"@ {rec.get('bw_each_mbit')}Mbps c/u, {rec['duration_sec']}s")
    return t or "?"


if __name__ == "__main__":
    print(json.dumps(get_recent_injections(window_sec=3600), indent=2, ensure_ascii=False))
