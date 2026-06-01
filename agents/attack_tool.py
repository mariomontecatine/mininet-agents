"""
Agente de inyección de anomalías.

Genera ataques sintéticos sobre la topología Mininet activa:
  * port_scan      — un host barre TCP/ICMP a muchos destinos (fan-out)
  * dos_volumetric — un host satura otro con iperf -u a alta tasa
  * ddos_fanin     — varios hosts inundan a una víctima en paralelo

Cada inyección se anota en `tmp/anomaly_injections.jsonl` (un JSON por línea)
para que `attack_report.py` pueda correlacionarlas a posteriori con las
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
SERVICES_FILE  = os.path.join(TMP_DIR, "server_services.json")

ATTACK_TYPES = ("dos_volumetric", "ddos")


def _load_services():
    """Lee tmp/server_services.json (mapping srv → tipo/puerto/transport)."""
    if not os.path.exists(SERVICES_FILE):
        return {}
    try:
        with open(SERVICES_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

# Estado interno del scheduler — se accede solo desde el hilo del supervisor.
_state = {
    "last_inject_ts": 0.0,    # epoch del último ataque (para cooldown)
    "rng":            random.Random(config.ANOMALY_RNG_SEED),
}


# ── Mapping host → puerto OVS ────────────────────────────────────────────────

def build_host_port_map():
    """
    Construye {host_name: switch_port} usando agents.topology.get_topology_links().
    Lo persiste en tmp/host_port_map.json para que attack_report.py pueda
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


def _service_attack_params(service_info):
    """Devuelve (transport, dport, flag) para el servicio de la víctima.

    - HTTP/HTTPS/SSH/FTP/SMTP → TCP SYN flood contra el puerto del servicio.
    - DNS/SIP                 → UDP flood contra el puerto del servicio.
    - Si no hay info          → UDP flood a un puerto alto aleatorio (genérico).
    """
    if not service_info:
        # Fallback genérico: UDP flood a un puerto alto. Sigue siendo
        # detectable como DoS volumétrico (volumen) aunque sin clasificación.
        return ("udp", 8888, "--udp")
    transport = service_info.get("transport", "udp")
    dport     = service_info.get("port") or 0
    flag      = "--udp" if transport == "udp" else "-S"
    return (transport, dport, flag)


def _attack_port_scan(ssh, src_host, target_ips, duration):
    """
    Barre target_ips en paralelo con ráfagas de ping para que sFlow capture
    suficientes destinos distintos.

    16 destinos × 100 pings × 10 ms = 1 s por barrido completo (en paralelo).
    Repite hasta que se cumple la duración total.

    NOTA: send_tmux_command envuelve el comando en comillas SIMPLES para tmux,
    así que el bash -c usa comillas DOBLES sin ninguna comilla simple dentro.
    """
    ip_list = " ".join(target_ips)
    cmd = (
        f'{src_host} bash -c '
        f'"end=$((SECONDS + {duration})); '
        f'while [ $SECONDS -lt $end ]; do '
        f'for ip in {ip_list}; do '
        f'ping -c 100 -i 0.01 -W 1 $ip >/dev/null 2>&1 & '
        f'done; wait; '
        f'sleep 2; done" &'
    )
    _send(ssh, cmd)


def _attack_dos_volumetric(ssh, src_host, victim_ip, duration, service_info):
    """DoS volumétrico contra el puerto real del servicio víctima vía hping3.

    Tasa: ~20 000 pps · 1 400 B → ~225 Mbps teóricos. En la VM real (WSL2) NO
    se alcanza ese teórico: medido produce ~12-16 MB por flujo en la ventana
    sFlow de 20 s (pico observado 15.75 MB), aún muy por encima del flujo
    legítimo máximo (~1.5 MB) pero por debajo de los 25-40 MB que se asumían.
    Por eso SURGE_BYTES_THRESHOLD se recalibró a 10 MB (ver utils/config.py).
    `-k` mantiene el sport fijo para que sFlow agregue todos los paquetes en UN
    único flujo (sin -k cada paquete usa sport distinto → fragmentación
    masiva). `timeout` asegura que pare al final aunque el proceso siga.
    """
    transport, dport, flag = _service_attack_params(service_info)
    cmd = (
        f'{src_host} bash -c '
        f'"timeout {duration} hping3 {flag} -p {dport} -k -s 12345 '
        f'-i u50 -d 1400 {victim_ip} >/dev/null 2>&1" &'
    )
    _send(ssh, cmd)


def _attack_ddos(ssh, attackers, victim_ip, duration, service_info):
    """DDoS coordinado: N atacantes inundan en paralelo el mismo servicio.

    Cada atacante: ~10 000 pps · 1 500 B → ~120 Mbps. Con 10 atacantes
    ~1.2 Gbps agregados, suficientes para superar FAN_IN_BYTES_THRESHOLD
    (12 MB × 5× multiplicador servidor = 60 MB) con holgura: ~150-300 MB
    agregados hacia la víctima en la ventana sFlow. `-k -s 12345` mantiene
    sport fijo por atacante → cada uno aparece como UN solo flujo en sFlow.
    """
    transport, dport, flag = _service_attack_params(service_info)
    for a in attackers:
        cmd = (
            f'{a} bash -c '
            f'"timeout {duration} hping3 {flag} -p {dport} -k -s 12345 '
            f'-i u100 -d 1500 {victim_ip} >/dev/null 2>&1" &'
        )
        _send(ssh, cmd)


def _ensure_hping3(ssh):
    """Verifica que hping3 está disponible en la VM. Imprime aviso si falta."""
    try:
        _, stdout, _ = ssh.exec_command("which hping3", timeout=5)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        if not out:
            print("[ANOMALY][WARN] hping3 no encontrado en la VM — los ataques "
                  "DoS/DDoS NO se ejecutarán. Instálalo con: sudo apt install hping3")
            return False
        return True
    except Exception as e:
        print(f"[ANOMALY][WARN] No pude comprobar hping3: {e}")
        return False


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
    services  = _load_services()
    attack_type = force_type or rng.choice(ATTACK_TYPES)
    duration = rng.randint(config.ANOMALY_MIN_DURATION, config.ANOMALY_MAX_DURATION)

    try:
        ssh = get_ssh_connection()
    except Exception as e:
        print(f"[ANOMALY] No se pudo abrir SSH: {e}")
        return None

    # Para DoS/DDoS necesitamos hping3 en la VM. Si no está instalado,
    # NO se simula el ataque (no falseamos datos con iperf en puertos inventados).
    needs_hping3 = attack_type in ("dos_volumetric", "ddos")
    if needs_hping3 and not _ensure_hping3(ssh):
        ssh.close()
        # Señalizamos el motivo con una excepción específica para que el endpoint
        # /api/inject del dashboard pueda mostrar un error claro al usuario.
        raise RuntimeError(
            "hping3 no está instalado en la VM Mininet — los ataques DoS/DDoS "
            "no se pueden simular. Ejecuta: sudo apt install hping3"
        )

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
            # Hasta 16 destinos para superar FAN_OUT_THRESHOLD con holgura.
            sample = others if len(others) <= 16 else rng.sample(others, 16)
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
            # Víctima: preferentemente un servidor (servicio real que tumbar);
            # si no hay servidores en endpoints, cualquier host vale.
            srv_candidates = [n for n in host_names
                              if n.startswith("srv") and n != src]
            if srv_candidates:
                victim = rng.choice(srv_candidates)
            else:
                victim = rng.choice([n for n in host_names if n != src])
            svc_info = services.get(victim)
            _attack_dos_volumetric(ssh, src, hosts[victim], duration, svc_info)
            rec.update({
                "attacker":       src,
                "attacker_ip":    hosts[src],
                "attacker_port":  host_port.get(src),
                "victim":         victim,
                "victim_ip":      hosts[victim],
                "victim_port":    host_port.get(victim),
                "victim_service": (svc_info or {}).get("type", "unknown"),
                "victim_dport":   (svc_info or {}).get("port"),
                "method":         "hping3",
            })

        elif attack_type == "ddos":
            # Víctima: siempre un srv* tipado si es posible (HTTP/DNS/SIP/SSH).
            srv_candidates = [n for n in host_names if n.startswith("srv")]
            victim = rng.choice(srv_candidates) if srv_candidates else rng.choice(host_names)
            h_pool = [n for n in host_names if n.startswith("h") and n != victim]
            if len(h_pool) < 2:
                # Fallback a DoS simple si no hay suficientes hosts.
                attack_type = "dos_volumetric"
                rec["type"] = "dos_volumetric"
                src = rng.choice([n for n in host_names if n != victim])
                svc_info = services.get(victim)
                _attack_dos_volumetric(ssh, src, hosts[victim], duration, svc_info)
                rec.update({
                    "attacker": src, "attacker_ip": hosts[src],
                    "attacker_port": host_port.get(src),
                    "victim": victim, "victim_ip": hosts[victim],
                    "victim_port": host_port.get(victim),
                    "victim_service": (svc_info or {}).get("type", "unknown"),
                    "victim_dport":   (svc_info or {}).get("port"),
                    "method": "hping3",
                })
            else:
                n_attackers = min(10, len(h_pool))
                attackers = rng.sample(h_pool, n_attackers)
                svc_info = services.get(victim)
                _attack_ddos(ssh, attackers, hosts[victim], duration, svc_info)
                rec.update({
                    "attackers":      attackers,
                    "attacker_ips":   [hosts[a] for a in attackers],
                    "attacker_ports": [host_port.get(a) for a in attackers],
                    "victim":         victim,
                    "victim_ip":      hosts[victim],
                    "victim_port":    host_port.get(victim),
                    "victim_service": (svc_info or {}).get("type", "unknown"),
                    "victim_dport":   (svc_info or {}).get("port"),
                    "method":         "hping3",
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
    svc = rec.get("victim_service") or "?"
    dport = rec.get("victim_dport")
    target = f"{rec.get('victim')} ({svc}:{dport})" if dport else rec.get('victim', '?')
    if t == "port_scan":
        return (f"port_scan: {rec['attacker']} → {len(rec.get('victims', []))} destinos, "
                f"{rec['duration_sec']}s")
    if t == "dos_volumetric":
        return (f"dos_volumetric: {rec['attacker']} → {target} "
                f"vía hping3, {rec['duration_sec']}s")
    if t == "ddos":
        return (f"ddos: {len(rec.get('attackers', []))} atacantes → {target} "
                f"vía hping3, {rec['duration_sec']}s")
    return t or "?"


if __name__ == "__main__":
    print(json.dumps(get_recent_injections(window_sec=3600), indent=2, ensure_ascii=False))
