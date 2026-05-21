"""
failover.py — Redundancia primario/secundario para servidores Mininet.

Detecta caídas mediante sondas TCP activas e instala reglas OpenFlow en OVS
para redirigir el tráfico al servidor secundario de forma transparente.

Flujos OVS instalados al activar la redirección (en el bridge del par):
  Forward : priority=500, ip, nw_dst=<primary_ip>
            → actions=mod_nw_dst:<secondary_ip>, output:<secondary_ovs_port>
  Return  : priority=500, ip, in_port=<secondary_ovs_port>, nw_src=<secondary_ip>
            → actions=mod_nw_src:<primary_ip>, NORMAL
"""

import os
import re
import json
import socket
import time
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config
from utils.ssh_client import get_ssh_connection, send_tmux_command

TMP_DIR             = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
FAILOVER_STATE_FILE = os.path.join(TMP_DIR, "failover_state.json")
FAILOVER_REQ_FILE   = os.path.join(TMP_DIR, "failover_requests.json")

# Estado en memoria: server_name → {status, fails, redirected_to, redirect_since, last_probe}
_state: dict = {}


# ─── Carga de información de servidores ──────────────────────────────────────

def load_server_info() -> dict:
    """
    Devuelve {srv_name: {type, ip, port, transport, ovs_port}} cruzando
    server_services.json + host_port_map.json.
    """
    services  = {}
    host_port = {}

    try:
        with open(os.path.join(TMP_DIR, "server_services.json"), encoding="utf-8") as f:
            services = json.load(f)
    except (IOError, json.JSONDecodeError):
        pass

    try:
        with open(os.path.join(TMP_DIR, "host_port_map.json"), encoding="utf-8") as f:
            host_port = json.load(f)
    except (IOError, json.JSONDecodeError):
        pass

    result = {}
    for name, svc in services.items():
        result[name] = {
            "type":      svc.get("type"),
            "ip":        svc.get("ip"),
            "port":      svc.get("port"),
            "transport": svc.get("transport"),
            "ovs_port":  host_port.get(name),
        }
    return result


def auto_select_pair(server_info: dict) -> tuple | None:
    """
    Selecciona automáticamente el par (primario, secundario): el primer par de
    servidores del mismo tipo (alfabético) que comparten el mismo bridge OVS.
    """
    by_type: dict = {}
    for name in sorted(server_info):
        t = server_info[name].get("type")
        if t:
            by_type.setdefault(t, []).append(name)

    for t, names in by_type.items():
        if len(names) < 2:
            continue
        # Preferir par en el mismo bridge (necesario para las reglas OVS)
        for i, p in enumerate(names):
            for s in names[i + 1:]:
                p_port = server_info[p].get("ovs_port", "")
                s_port = server_info[s].get("ovs_port", "")
                if p_port and s_port and p_port.split("-")[0] == s_port.split("-")[0]:
                    return (p, s)
        # Si no comparten bridge, devolver el primer par de todas formas
        return (names[0], names[1])
    return None


# ─── Sonda TCP ───────────────────────────────────────────────────────────────

def probe_server(ip: str, port: int) -> bool:
    """TCP health check. True si el servidor responde antes del timeout."""
    try:
        with socket.create_connection((ip, port), timeout=config.FAILOVER_PROBE_TIMEOUT):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ─── Reglas OVS ──────────────────────────────────────────────────────────────

def _bridge(ovs_port: str) -> str:
    return ovs_port.split("-")[0] if ovs_port else ""


def apply_redirect(ssh, primary_ip: str, secondary_ip: str, sec_ovs_port: str):
    """Instala los dos flujos OpenFlow de redirección transparente."""
    br = _bridge(sec_ovs_port)
    if not br:
        return
    send_tmux_command(
        ssh,
        f"sh ovs-ofctl add-flow {br} "
        f"priority=500,ip,nw_dst={primary_ip},"
        f"actions=mod_nw_dst:{secondary_ip},output:{sec_ovs_port}",
    )
    time.sleep(0.2)
    send_tmux_command(
        ssh,
        f"sh ovs-ofctl add-flow {br} "
        f"priority=500,ip,in_port={sec_ovs_port},nw_src={secondary_ip},"
        f"actions=mod_nw_src:{primary_ip},NORMAL",
    )
    time.sleep(0.2)
    print(f"  [FAILOVER] Redirect {primary_ip} → {secondary_ip} instalado en {br}")


def remove_redirect(ssh, primary_ip: str, secondary_ip: str, sec_ovs_port: str):
    """Elimina los flujos OpenFlow de redirección."""
    br = _bridge(sec_ovs_port)
    if not br:
        return
    send_tmux_command(
        ssh,
        f"sh ovs-ofctl del-flows {br} 'ip,nw_dst={primary_ip}' 2>/dev/null; true",
    )
    time.sleep(0.2)
    send_tmux_command(
        ssh,
        f"sh ovs-ofctl del-flows {br} "
        f"'ip,in_port={sec_ovs_port},nw_src={secondary_ip}' 2>/dev/null; true",
    )
    time.sleep(0.2)
    print(f"  [FAILOVER] Redirect {primary_ip} → {secondary_ip} eliminado en {br}")


# ─── Control del proceso servidor ────────────────────────────────────────────

def kill_server(ssh, server_name: str, svc_type: str):
    """Para el proceso del servidor en el host Mininet."""
    # pkill directo en la VM: los hosts Mininet comparten el PID namespace
    # con la VM, así que no hace falta ir a través del CLI de Mininet.
    send_tmux_command(
        ssh,
        f'py net.get("{server_name}").cmd("kill -9 $(pgrep -f service_launchers.py)")',
    )
    time.sleep(0.3)
    print(f"  [FAILOVER] {server_name} ({svc_type}) apagado")


def revive_server(ssh, server_name: str, svc_type: str):
    """Reinicia el proceso del servidor en el host Mininet."""
    send_tmux_command(
        ssh,
        f"{server_name} python3 /tmp/service_launchers.py {svc_type} "
        f"> /tmp/svc_{server_name}.log 2>&1 &",
    )
    time.sleep(0.5)
    print(f"  [FAILOVER] {server_name} ({svc_type}) reiniciado")


# ─── Persistencia de estado ───────────────────────────────────────────────────

def save_state():
    try:
        with open(FAILOVER_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {"ts": datetime.now().isoformat(timespec="seconds"), "servers": _state},
                f, ensure_ascii=False, indent=2,
            )
    except IOError:
        pass


def load_pending_requests() -> list:
    """Lee y borra la cola de peticiones del dashboard."""
    if not os.path.exists(FAILOVER_REQ_FILE):
        return []
    try:
        with open(FAILOVER_REQ_FILE, encoding="utf-8") as f:
            reqs = json.load(f)
        os.remove(FAILOVER_REQ_FILE)
        return reqs if isinstance(reqs, list) else []
    except (IOError, json.JSONDecodeError):
        return []


# ─── Lógica principal ─────────────────────────────────────────────────────────

def check_failover(server_info: dict, pair: tuple | None, ciclo: int) -> list[str]:
    """
    Sonda el servidor primario y gestiona la redirección.
    Procesa primero las peticiones manuales del dashboard (kill/revive).

    Devuelve lista de líneas de telemetría para inyectar en el informe del monitor.
    """
    global _state
    if not pair:
        return []

    primary_name, secondary_name = pair
    pri = server_info.get(primary_name, {})
    sec = server_info.get(secondary_name, {})

    primary_ip     = pri.get("ip")
    primary_port   = pri.get("port")
    primary_type   = pri.get("type", "http")
    secondary_ip   = sec.get("ip")
    sec_ovs_port   = sec.get("ovs_port")

    if not all([primary_ip, primary_port, secondary_ip, sec_ovs_port]):
        return []

    # Inicializar entrada de estado si es la primera vez
    if primary_name not in _state:
        _state[primary_name] = {
            "status":         "up",
            "fails":          0,
            "redirected_to":  None,
            "redirect_since": None,
            "last_probe":     None,
        }
    entry = _state[primary_name]

    # ── Procesar peticiones manuales (kill / revive) ──────────────────────────
    for req in load_pending_requests():
        action = req.get("action")
        target = req.get("server")
        if target != primary_name:
            continue
        try:
            ssh = get_ssh_connection()
            if action == "kill":
                kill_server(ssh, primary_name, primary_type)
                # Forzar threshold para que la próxima sonda active la redirección
                entry["fails"] = config.FAILOVER_FAIL_THRESHOLD
                entry["status"] = "failing"
            elif action == "revive":
                revive_server(ssh, primary_name, primary_type)
                # La sonda detectará la recuperación en el siguiente ciclo
            ssh.close()
        except Exception as e:
            print(f"  [FAILOVER ERROR] Petición {action} en {primary_name}: {e}")

    # ── Sonda TCP ─────────────────────────────────────────────────────────────
    alive = probe_server(primary_ip, primary_port)
    entry["last_probe"] = datetime.now().isoformat(timespec="seconds")

    telemetry: list[str] = []

    if alive:
        entry["fails"] = 0
        if entry["status"] in ("redirected", "failing"):
            # Servidor recuperado → eliminar redirección
            print(f"\n[FAILOVER] {primary_name} recuperado. Eliminando redirección...")
            try:
                ssh = get_ssh_connection()
                remove_redirect(ssh, primary_ip, secondary_ip, sec_ovs_port)
                ssh.close()
            except Exception as e:
                print(f"  [FAILOVER ERROR] {e}")
            entry["status"]         = "up"
            entry["redirected_to"]  = None
            entry["redirect_since"] = None
            telemetry.append(
                f"[FAILOVER RECOVERED] {primary_name} ({primary_ip}) volvió en línea — "
                f"redirección a {secondary_name} eliminada"
            )
        else:
            entry["status"] = "up"
    else:
        entry["fails"] += 1
        if entry["status"] in ("up", "failing") and entry["fails"] >= config.FAILOVER_FAIL_THRESHOLD:
            # Servidor caído → instalar redirección
            print(f"\n[FAILOVER] {primary_name} caído ({entry['fails']} sondas fallidas). "
                  f"Redirigiendo a {secondary_name}...")
            try:
                ssh = get_ssh_connection()
                apply_redirect(ssh, primary_ip, secondary_ip, sec_ovs_port)
                ssh.close()
            except Exception as e:
                print(f"  [FAILOVER ERROR] {e}")
            entry["status"]         = "redirected"
            entry["redirected_to"]  = secondary_name
            entry["redirect_since"] = ciclo
            telemetry.append(
                f"[SERVER DOWN] {primary_name} ({primary_ip}:{primary_port}) — "
                f"{entry['fails']} sondas TCP consecutivas fallidas"
            )
            telemetry.append(
                f"[REDIRECT ACTIVO] tráfico de {primary_name} ({primary_ip}) "
                f"→ {secondary_name} ({secondary_ip}) — redirigido en ciclo {ciclo}"
            )
        elif entry["status"] == "redirected":
            telemetry.append(
                f"[SERVER DOWN] {primary_name} ({primary_ip}) sigue caído — "
                f"redirigido a {secondary_name} desde ciclo {entry['redirect_since']}"
            )

    save_state()
    return telemetry
