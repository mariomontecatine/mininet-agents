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
import threading
import time
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ollama

from utils import config
from utils.ssh_client import get_ssh_connection, send_tmux_command

TMP_DIR             = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
FAILOVER_STATE_FILE = os.path.join(TMP_DIR, "failover_state.json")
FAILOVER_REQ_FILE   = os.path.join(TMP_DIR, "failover_requests.json")

# Estado en memoria: server_name → {status, fails, redirected_to, redirect_since, last_probe}
_state: dict = {}

# Cliente LLM para decidir failover. Sin timeout porque la llamada corre en un
# hilo separado: el supervisor NO bloquea esperando al LLM. La decisión
# determinista se aplica al instante; la respuesta del LLM se loggea cuando
# llega y dispara una corrección si discrepa del estado actual.
_ollama_failover_client = ollama.Client(host="http://localhost:11434")

# Cola de eventos pendientes de log que el hilo LLM produce y el supervisor
# consume al inicio del siguiente ciclo de failover. Evita escribir al audit
# log desde un thread (no es thread-safe en este proyecto).
_llm_log_queue: list[str] = []
_llm_log_lock = threading.Lock()
# Evitamos lanzar más de una consulta concurrente al LLM de failover.
_llm_busy = threading.Lock()

# Historial de eventos de failover (para el timeline del dashboard).
FAILOVER_HISTORY_FILE = os.path.join(TMP_DIR, "failover_history.jsonl")

# Callback que el supervisor inyecta para escribir en el audit log desde
# el hilo de failover. Por defecto print() — el supervisor lo redefine.
_log_callback = print


def set_log_callback(cb):
    """Permite al supervisor inyectar registrar_log() como destino de
    eventos producidos por el hilo de failover."""
    global _log_callback
    _log_callback = cb


def _append_history(event_type: str, **fields):
    """Persiste un evento de failover (down/redirect/recover/llm) en JSONL
    para el panel de timeline del dashboard."""
    rec = {
        "ts":   datetime.now().isoformat(timespec="seconds"),
        "type": event_type,
        **fields,
    }
    try:
        with open(FAILOVER_HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except IOError:
        pass


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
# La sonda DEBE ejecutarse dentro del netns del propio servidor primario:
#   - Desde el host WSL/local, 192.168.1.x sale por la default route y golpea
#     el gateway de la LAN doméstica, que también responde HTTP/80 (falso UP).
#   - Desde un host cliente (p.ej. h1), si hay una redirección OVS activa el
#     SYN se reescribe y va a srv2; el SYN-ACK vuelve con src reescrito a
#     srv1, pero el handshake no completa por desajustes ARP/NORMAL: la sonda
#     daría siempre timeout incluso si srv1 ya está vivo otra vez.
# Sondando desde el netns del propio primario, el tráfico pasa por su stack
# loopback local y NO toca OVS — testa exactamente "¿el proceso escucha?".


def probe_server(ssh, ip: str, port: int, src_host: str,
                 timeout: int = None) -> bool:
    """TCP health check ejecutado dentro del netns de `src_host`.
    True si la conexión TCP completa el handshake antes del timeout."""
    if timeout is None:
        timeout = config.FAILOVER_PROBE_TIMEOUT
    cmd = (
        f"PID=$(pgrep -f 'mininet:{src_host}$' | head -1); "
        f"[ -z \"$PID\" ] && exit 2; "
        f"sudo /usr/bin/mnexec -a $PID "
        f"timeout {timeout} bash -c 'exec 3<>/dev/tcp/{ip}/{port} && exec 3<&-' 2>/dev/null"
    )
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=timeout + 3)
        return stdout.channel.recv_exit_status() == 0
    except Exception:
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
    """Mata el proceso que escucha en el puerto del servicio via `fuser -k`,
    ejecutado dentro del netns del host Mininet."""
    from utils import config as _cfg
    sdef = _cfg.SERVICE_DEFS.get(svc_type, _cfg.SERVICE_DEFS["http"])
    port = sdef["dport"] or 80
    transport = sdef["transport"]
    send_tmux_command(
        ssh,
        f'py net.get("{server_name}").cmd("fuser -k {port}/{transport} 2>/dev/null")',
    )
    time.sleep(0.3)
    print(f"  [FAILOVER] {server_name} ({svc_type}) apagado (fuser -k {port}/{transport})")


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


# ─── Decisión vía LLM ────────────────────────────────────────────────────────

# Solo dos tools: solo se consulta al LLM cuando ya sabemos que hace falta una
# transición. Cualquier respuesta válida será redirect o remove.
_FAILOVER_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "redirect_to_secondary",
            "description": (
                "Instala flujos OpenFlow para redirigir TODO el tráfico del primario al secundario. "
                "Llámalo cuando el primario está CAÍDO."
            ),
            "parameters": {
                "type": "object",
                "properties": {"reason": {"type": "string"}},
                "required": ["reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "remove_redirect",
            "description": (
                "Quita los flujos OpenFlow de redirección y devuelve el tráfico al primario. "
                "Llámalo cuando el primario está VIVO."
            ),
            "parameters": {
                "type": "object",
                "properties": {"reason": {"type": "string"}},
                "required": ["reason"],
            },
        },
    },
]

_FAILOVER_SYSTEM_PROMPT = (
    "Eres el agente de alta disponibilidad. Recibirás el estado de salud de un servidor primario y "
    "debes invocar exactamente UNA herramienta:\n"
    "• Si el primario está CAÍDO → redirect_to_secondary\n"
    "• Si el primario está VIVO → remove_redirect\n"
    "Responde SOLO con la llamada a la herramienta. Sin texto."
)


def _llm_decide_failover(primary_name, primary_ip, secondary_name, secondary_ip,
                         alive, redirect_active, fails):
    """Consulta síncrona al LLM. Devuelve ('redirect'|'remove', reason) o (None, error).
    Solo se usa desde un hilo aparte — el LLM en CPU tarda decenas de segundos."""
    estado = (
        f"PRIMARIO {primary_name} ({primary_ip}): "
        f"{'VIVO' if alive else f'CAÍDO ({fails} sondas TCP fallidas)'}.\n"
        f"SECUNDARIO {secondary_name} ({secondary_ip}).\n"
        f"REDIRECCIÓN ACTUAL: {'activa hacia ' + secondary_name if redirect_active else 'inactiva'}."
    )
    try:
        t0 = time.time()
        response = _ollama_failover_client.chat(
            model=config.MODEL_RESOLVER,
            messages=[
                {"role": "system", "content": _FAILOVER_SYSTEM_PROMPT},
                {"role": "user", "content": estado},
            ],
            tools=_FAILOVER_TOOLS,
            options={"temperature": 0},
        )
        dt = time.time() - t0
        calls = response.get("message", {}).get("tool_calls") or []
        if not calls:
            return (None, f"LLM no invocó tool (dt={dt:.1f}s)")
        name = calls[0]["function"]["name"]
        args = calls[0]["function"]["arguments"] or {}
        reason = args.get("reason", "")
        mapping = {"redirect_to_secondary": "redirect", "remove_redirect": "remove"}
        decision = mapping.get(name)
        if decision is None:
            return (None, f"tool desconocida: {name}")
        return (decision, reason)
    except Exception as e:
        return (None, f"LLM error: {e}")


def _llm_job(primary_name, primary_ip, secondary_name, secondary_ip,
             alive_snap, redirect_snap, fails_snap, det_decision):
    """Trabajo en hilo: pregunta al LLM y registra el resultado en la cola
    para que el supervisor lo loggee en el siguiente ciclo."""
    if not _llm_busy.acquire(blocking=False):
        return  # ya hay una consulta en marcha, no apilamos
    try:
        t0 = time.time()
        llm_dec, llm_reason = _llm_decide_failover(
            primary_name, primary_ip, secondary_name, secondary_ip,
            alive=alive_snap, redirect_active=redirect_snap, fails=fails_snap,
        )
        dt = time.time() - t0
        if llm_dec is None:
            line   = f"[FAILOVER LLM] sin respuesta ({dt:.1f}s): {llm_reason}"
            status = "noop"
        elif llm_dec == det_decision:
            line   = f"[FAILOVER LLM] confirma '{llm_dec}' ({dt:.1f}s) — {llm_reason}"
            status = "confirm"
        else:
            line = (f"[FAILOVER LLM] eligió '{llm_dec}' pero la acción ejecutada "
                    f"fue '{det_decision}' ({dt:.1f}s) — {llm_reason}")
            status = "diverge"
        print(f"  {line}")
        with _llm_log_lock:
            _llm_log_queue.append(line)
        _append_history("llm", primary=primary_name, det=det_decision,
                        llm=llm_dec, status=status, dt=round(dt, 1),
                        reason=llm_reason)
    finally:
        _llm_busy.release()


def drain_llm_messages() -> list[str]:
    """Devuelve (y vacía) los mensajes que el hilo LLM ha producido desde la última llamada."""
    with _llm_log_lock:
        if not _llm_log_queue:
            return []
        out = list(_llm_log_queue)
        _llm_log_queue.clear()
        return out


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
    # No tocamos status/fails: el poll siguiente (≤ 2 s) lo detecta solo.
    for req in load_pending_requests():
        action = req.get("action")
        target = req.get("server")
        if target != primary_name:
            continue
        try:
            ssh = get_ssh_connection()
            if action == "kill":
                kill_server(ssh, primary_name, primary_type)
            elif action == "revive":
                revive_server(ssh, primary_name, primary_type)
            ssh.close()
        except Exception as e:
            print(f"  [FAILOVER ERROR] Petición {action} en {primary_name}: {e}")

    # ── Sonda TCP ─────────────────────────────────────────────────────────────
    try:
        _probe_ssh = get_ssh_connection()
        alive = probe_server(_probe_ssh, primary_ip, primary_port, src_host=primary_name)
        _probe_ssh.close()
    except Exception as e:
        print(f"  [FAILOVER ERROR] probe: {e}")
        alive = False
    entry["last_probe"] = datetime.now().isoformat(timespec="seconds")
    if alive:
        entry["fails"] = 0
    else:
        entry["fails"] += 1

    redirect_active = entry["status"] == "redirected"
    threshold_hit   = (not alive) and entry["fails"] >= config.FAILOVER_FAIL_THRESHOLD

    # ── ¿Hace falta una transición? ───────────────────────────────────────────
    # Solo consultamos al LLM si el estado actual NO es el correcto.
    needs_transition = (
        (alive and redirect_active) or            # vivo pero seguimos redirigiendo → quitar
        (threshold_hit and not redirect_active)   # caído sin redirección → redirigir
    )

    telemetry: list[str] = []

    # Drenar mensajes del LLM (consultas async previas que ya terminaron).
    # Se hace ANTES de cualquier early-return para que aparezcan siempre en el log.
    telemetry.extend(drain_llm_messages())

    if not needs_transition:
        # Sin transición: solo refrescar status. No spammear el audit log con
        # "sigue caído" en cada poll — la caída ya está en el history y el
        # estado actual está en failover_state.json.
        if alive and not redirect_active:
            entry["status"] = "up"
        elif not alive and not redirect_active:
            entry["status"] = "failing" if entry["fails"] > 0 else "up"
        save_state()
        return telemetry

    # ── Acción inmediata (determinista) ───────────────────────────────────────
    # El LLM corre en hilo aparte porque en CPU tarda decenas de segundos y
    # congelaría el supervisor; aquí la sonda ya nos dice qué hacer.
    decision = "remove" if (alive and redirect_active) else "redirect"

    try:
        ssh = get_ssh_connection()
        if decision == "redirect":
            apply_redirect(ssh, primary_ip, secondary_ip, sec_ovs_port)
            entry["status"]         = "redirected"
            entry["redirected_to"]  = secondary_name
            entry["redirect_since"] = ciclo
            telemetry.append(
                f"[SERVER DOWN] {primary_name} ({primary_ip}:{primary_port}) — "
                f"{entry['fails']} sondas TCP consecutivas fallidas"
            )
            telemetry.append(
                f"[FAILOVER] redirigir tráfico de {primary_name} → {secondary_name} "
                f"(ciclo {ciclo}) — consultando LLM en paralelo"
            )
            _append_history("down", primary=primary_name, primary_ip=primary_ip,
                            secondary=secondary_name, secondary_ip=secondary_ip,
                            ciclo=ciclo, fails=entry["fails"])
        else:  # remove
            remove_redirect(ssh, primary_ip, secondary_ip, sec_ovs_port)
            entry["status"]         = "up"
            entry["redirected_to"]  = None
            entry["redirect_since"] = None
            telemetry.append(
                f"[FAILOVER] {primary_name} ({primary_ip}) recuperado — "
                f"redirección a {secondary_name} eliminada. Consultando LLM en paralelo."
            )
            _append_history("recover", primary=primary_name, primary_ip=primary_ip,
                            secondary=secondary_name, ciclo=ciclo)
        ssh.close()
    except Exception as e:
        print(f"  [FAILOVER ERROR] aplicando {decision}: {e}")

    # ── Lanzar consulta LLM en hilo (no bloquea) ──────────────────────────────
    threading.Thread(
        target=_llm_job,
        args=(primary_name, primary_ip, secondary_name, secondary_ip,
              alive, redirect_active, entry["fails"], decision),
        daemon=True,
        name="failover-llm",
    ).start()

    save_state()
    return telemetry


# ─── Bucle independiente del supervisor ─────────────────────────────────────

_loop_stop = threading.Event()


def _failover_poll_loop(pair: tuple, ciclo_provider):
    """Hilo daemon que ejecuta check_failover cada FAILOVER_POLL_INTERVAL
    segundos. Independiente del ciclo NOC del supervisor para detectar caídas
    en segundos (en lugar de cada 10-30 s)."""
    # Cache del server_info; se refresca cada 30 s por si la topología cambia.
    server_info = load_server_info()
    last_refresh = time.time()
    while not _loop_stop.is_set():
        try:
            if time.time() - last_refresh > 30:
                server_info  = load_server_info()
                last_refresh = time.time()
            ciclo = ciclo_provider() if callable(ciclo_provider) else 0
            lines = check_failover(server_info, pair, ciclo)
            for ln in lines:
                _log_callback(ln)
        except Exception as e:
            print(f"  [FAILOVER LOOP] error: {e}")
        _loop_stop.wait(config.FAILOVER_POLL_INTERVAL)


def start_failover_loop(pair: tuple, ciclo_provider) -> threading.Thread:
    """Arranca el hilo daemon de failover si hay par configurado.
    Devuelve el thread o None si no hay par."""
    if not pair:
        return None
    _loop_stop.clear()
    t = threading.Thread(
        target=_failover_poll_loop,
        args=(pair, ciclo_provider),
        daemon=True,
        name="failover-poll",
    )
    t.start()
    return t


def stop_failover_loop():
    """Señala al hilo de failover que termine."""
    _loop_stop.set()
