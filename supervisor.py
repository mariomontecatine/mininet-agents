import sys
import os
import re
import time
import json
import logging
import threading
from collections import deque
from datetime import datetime
from logging.handlers import RotatingFileHandler

from utils import config
from utils.ssh_client import close_persistent_connection
from dashboard.app import start_dashboard

TMP_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")
CACHE_FILE = os.path.join(TMP_DIR, "topology_cache.json")
os.makedirs(TMP_DIR, exist_ok=True)

sys.path.append(os.path.join(os.path.dirname(__file__), "agents"))

from agents.deploy_agent import (
    generate_network_intent,
    build_python_script,
    deploy_unified_in_vm,
    assign_server_types,
    _persist_server_services,
)
from agents.traffic import (
    get_active_endpoints,
    launch_background_traffic,
    stop_background_traffic,
)
from agents.topology import (
    get_topology_links, draw_topology,
    dump_host_interfaces, persist_topology_json,
)
from agents.monitor_agent import collect_telemetry, generate_network_report
from agents.resolver_agent import analyze_and_decide, fast_decide, resolve_multiple, run_desescalado
from agents.sflow import (
    configure_sflow_on_bridges,
    remove_sflow_from_bridges,
    start_sflow_daemon,
    stop_sflow_daemon,
    fetch_flows,
)
from agents.attack_tool import maybe_inject_anomaly, build_host_port_map
from agents.attack_report import generate_report as generate_anomaly_report
from agents.failover import (
    load_server_info, auto_select_pair,
    start_failover_loop, stop_failover_loop, drain_llm_messages, set_log_callback,
    FAILOVER_STATE_FILE,
)

# -------------------------------------------------------
# Auditoría con rotación automática
# -------------------------------------------------------
_audit_logger: logging.Logger | None = None

# Lock SSH: solo para secciones que envían comandos tmux.
# Se libera durante las llamadas LLM para que el colector live pueda actuar.
_live_lock = threading.Lock()

# Estado NOC compartido — leído/escrito por _flow_watcher y el bucle principal.
# _live_lock protege los accesos que implican resolve_multiple (SSH).
_reglas_activas: dict = {}   # port → {"action": ..., "ciclo": ...}
_ciclos_limpios: dict = {}   # port → int
_current_ciclo:  int  = 1    # ciclo actual, actualizado por el bucle principal

# Puertos que acaban de salir de mitigación: el watcher exige más confirmaciones
# antes de re-actuar (anti-flap). Mapping port → ciclo_de_desescalado_completo.
_recently_relaxed: dict = {}

# Cola de alertas de flujo (solo para enriquecer la telemetría del LLM).
_pending_flow_alerts: deque = deque(maxlen=200)


def setup_audit_log():
    global _audit_logger
    log_path = os.path.join(TMP_DIR, "noc_audit.log")
    handler = RotatingFileHandler(
        log_path,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logger = logging.getLogger("noc_audit")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.propagate = False
    _audit_logger = logger


def registrar_log(mensaje):
    if _audit_logger:
        _audit_logger.info(mensaje)


# -------------------------------------------------------
# Caché de topología
# -------------------------------------------------------

def _describe_intent(intent):
    """Devuelve una descripción compacta del intent para mostrársela al usuario."""
    tipo = intent.get("tipo", "?")
    if tipo == "tree":
        return f"árbol (depth={intent.get('depth', '?')}, fanout={intent.get('fanout', '?')})"
    if tipo == "linear":
        return f"lineal ({intent.get('k', '?')} hosts)"
    if tipo == "custom":
        n = len(intent.get("nodes", {}))
        l = len(intent.get("links", []))
        return f"custom ({n} nodos, {l} enlaces)"
    return tipo


def _load_topology_cache():
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def _save_topology_cache(user_request, intent, code):
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {"user_request": user_request, "intent": intent, "code": code},
                f,
                ensure_ascii=False,
                indent=2,
            )
    except IOError:
        pass


# -------------------------------------------------------
# QoS event log
# -------------------------------------------------------

def _write_qos_event(port, action, event_type, ciclo, protocol=None):
    """Persiste un evento QoS (apply/desescalado/remove) en qos_history.json para el dashboard."""
    qos_path = os.path.join(TMP_DIR, "qos_history.json")
    history = []
    if os.path.exists(qos_path):
        try:
            with open(qos_path, encoding="utf-8") as f:
                history = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    history.append({
        "ts":       datetime.now().isoformat(timespec="seconds"),
        "cycle":    ciclo,
        "port":     port,
        "action":   action,
        "event":    event_type,
        "protocol": protocol,
    })
    if len(history) > 300:
        history = history[-300:]
    try:
        with open(qos_path, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False)
    except IOError:
        pass


# -------------------------------------------------------
# Colector de métricas en tiempo real
# -------------------------------------------------------

def _live_collector():
    """
    Hilo background: recolecta métricas cada 5 s vía OVS directo (sin tmux).
    Una sola llamada SSH a ovs-vsctl devuelve todas las interfaces parseables.
    """
    from agents.monitor_agent import collect_port_stats_via_ovs
    from utils.ssh_client import get_ssh_connection

    live_file = os.path.join(TMP_DIR, "live_metrics.json")
    live_prev: dict = {}

    while True:
        time.sleep(5)

        acquired = _live_lock.acquire(blocking=False)
        if not acquired:
            continue

        try:
            ssh = get_ssh_connection()
            current = collect_port_stats_via_ovs(ssh)

            deltas = {}
            for port, vals in current.items():
                if port in live_prev:
                    d_rx   = max(0, vals["rx_bytes"] - live_prev[port]["rx_bytes"])
                    d_tx   = max(0, vals["tx_bytes"] - live_prev[port]["tx_bytes"])
                    d_drop = max(0, vals["drop"]     - live_prev[port]["drop"])
                    if d_rx > 0 or d_tx > 0 or d_drop > 0:
                        deltas[port] = {"rx": d_rx, "tx": d_tx, "drop": d_drop}
            live_prev.update(current)

            if not deltas:
                continue

            live_data = []
            if os.path.exists(live_file):
                try:
                    with open(live_file, encoding="utf-8") as f:
                        live_data = json.load(f)
                except (json.JSONDecodeError, IOError):
                    pass
            live_data.append({
                "ts":    datetime.now().isoformat(timespec="seconds"),
                "ports": deltas,
            })
            live_data = live_data[-2000:]
            with open(live_file, "w", encoding="utf-8") as f:
                json.dump(live_data, f, ensure_ascii=False)

        except Exception:
            pass
        finally:
            _live_lock.release()


FLOWS_HISTORY_CAP = 720   # ~1 h con muestras cada 5 s


def _sflow_collector():
    """
    Hilo background: lee /tmp/sflow_flows.json desde la VM cada 5 s,
    replica el snapshot en tmp/flows.json (vista live) y acumula los
    delta_flows en tmp/flows_history.json (cap FLOWS_HISTORY_CAP).

    No usa el _live_lock: fetch_flows es una sola lectura de fichero
    via SSH, ortogonal a los comandos tmux.
    """
    from utils.ssh_client import get_ssh_connection

    flows_file   = os.path.join(TMP_DIR, "flows.json")
    history_file = os.path.join(TMP_DIR, "flows_history.json")
    last_ts: str = ""

    while True:
        time.sleep(5)
        try:
            ssh = get_ssh_connection()
            snapshot = fetch_flows(ssh)
            if not snapshot:
                continue

            with open(flows_file, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, ensure_ascii=False)

            # Append al historial — solo si la marca temporal cambió (evita
            # duplicar si el daemon aún no ha hecho un nuevo flush).
            ts = snapshot.get("ts", "")
            if not ts or ts == last_ts:
                continue
            last_ts = ts

            history = []
            if os.path.exists(history_file):
                try:
                    with open(history_file, encoding="utf-8") as f:
                        history = json.load(f)
                except (json.JSONDecodeError, IOError):
                    history = []

            history.append({
                "ts":          ts,
                "datagrams":   snapshot.get("datagrams", 0),
                "delta_flows": snapshot.get("delta_flows", []),
            })
            history = history[-FLOWS_HISTORY_CAP:]
            with open(history_file, "w", encoding="utf-8") as f:
                json.dump(history, f, ensure_ascii=False)
        except Exception:
            pass


def _flow_watcher():
    """
    Hilo background: evalúa detect_flow_anomalies sobre el snapshot sFlow cada
    5 s y actúa DE INMEDIATO con fast_decide + resolve_multiple sin esperar a
    que el LLM termine (evita que ataques cortos escapen durante ciclos largos).

    También alimenta _pending_flow_alerts para que el LLM reciba contexto de
    los flujos anómalos en el próximo ciclo.

    Dedup 60 s por (port, type): una alerta solo se reinyecta si el puerto ya
    no está en _reglas_activas y han pasado >60 s desde el último disparo.
    """
    from agents.monitor_agent import detect_flow_anomalies, _format_anomaly_lines, _record_flow_alert
    from agents.resolver_agent import fast_decide, resolve_multiple

    flows_file     = os.path.join(TMP_DIR, "flows.json")
    host_port_file = os.path.join(TMP_DIR, "host_port_map.json")
    last_ts: str   = ""
    seen: dict     = {}   # "port:type" → epoch del último disparo
    pending: dict  = {}   # "port:type" → snapshots consecutivos vistos (confirmación N=2)
    windows_seen   = 0    # warmup: no actuar en los primeros 8 snapshots (~40s)

    while True:
        time.sleep(5)
        try:
            if not os.path.exists(flows_file):
                continue
            with open(flows_file, encoding="utf-8") as f:
                snapshot = json.load(f)
            ts = snapshot.get("ts", "")
            if not ts or ts == last_ts:
                continue
            last_ts = ts
            windows_seen += 1
            flows = snapshot.get("flows")
            if not flows:
                continue

            host_port = {}
            if os.path.exists(host_port_file):
                try:
                    with open(host_port_file, encoding="utf-8") as f:
                        host_port = json.load(f)
                except Exception:
                    pass

            alerts = detect_flow_anomalies(flows, host_port)

            # Actualizar contador de confirmación (N=2 snapshots consecutivos
            # antes de actuar — filtra ráfagas de 5s del bulk legítimo).
            current_keys = {f"{a.get('port','?')}:{a['type']}" for a in alerts}
            for k in list(pending.keys()):
                if k not in current_keys:
                    del pending[k]
            for k in current_keys:
                pending[k] = pending.get(k, 0) + 1

            if windows_seen <= 8:
                # Warmup ~40s: cubre el arranque simultáneo del bulk iperf (35s).
                # NO grabamos las alertas — son falsos positivos legítimos del
                # tráfico que arranca a la vez y no deben contar en la métrica
                # de FP del monitor.
                continue
            now = time.time()

            # Umbral de severidad alta: una alerta así de grande es por
            # construcción un ataque, no ruido — saltamos la confirmación N=2.
            HIGH_SURGE   = config.SURGE_BYTES_THRESHOLD  * 1.5
            HIGH_FANIN_B = config.FAN_IN_BYTES_THRESHOLD * 1.5

            def _required_n(alert):
                """Confirmaciones necesarias antes de actuar para esta alerta."""
                port    = alert.get("port", "?")
                a_type  = alert.get("type")
                # Cooling: si el puerto se desescaló hace ≤2 ciclos, exigir N=3
                # para evitar oscilación POLICING→nada→POLICING.
                relaxed_at = _recently_relaxed.get(port)
                if relaxed_at is not None and (_current_ciclo - relaxed_at) <= 2:
                    return 3
                # N=1 para severidad muy alta (DoS o DDoS evidentes)
                if a_type == "dos_volumetric" and alert.get("bytes", 0) >= HIGH_SURGE:
                    return 1
                if a_type == "ddos" and alert.get("bytes", 0) >= HIGH_FANIN_B:
                    return 1
                # Resto: N=2 (confirmación 2 snapshots seguidos)
                return 2

            fresh = [
                a for a in alerts
                if pending.get(f"{a.get('port','?')}:{a['type']}", 0) >= _required_n(a)
                and now - seen.get(f"{a.get('port','?')}:{a['type']}", 0) >= 60
            ]
            for a in fresh:
                seen[f"{a.get('port','?')}:{a['type']}"] = now
                _record_flow_alert(a)   # persiste en flow_alerts.jsonl

            lines = _format_anomaly_lines(fresh)
            for line in lines:
                _pending_flow_alerts.append(line)

            if not lines:
                continue

            # Acción inmediata: fast_decide sobre las líneas recién detectadas.
            fake_telemetry = "\n".join(lines)
            fast_actions = fast_decide(fake_telemetry, _reglas_activas)
            new_fast = [
                a for a in fast_actions
                if a.get("action") not in ("NO_ACTION", None)
                and a.get("target_port") not in _reglas_activas
            ]
            if not new_fast:
                continue

            ciclo_now = _current_ciclo
            with _live_lock:
                resolve_multiple(new_fast)
            for a in new_fast:
                p = a["target_port"]
                proto = a.get("protocol")
                _reglas_activas[p] = {
                    "action": a["action"], "ciclo": ciclo_now, "protocol": proto,
                }
                _ciclos_limpios[p] = 0
                proto_tag = f" [proto={proto}]" if proto else ""
                registrar_log(
                    f"ACCIÓN RÁPIDA [FLOW]: {a['action']}{proto_tag} en {p}. "
                    f"Motivo: {a.get('reason', 'Automático')}"
                )
                _write_qos_event(p, a["action"], "apply", ciclo_now, protocol=proto)
        except Exception:
            pass


def print_header(texto):
    print("\n" + "=" * 60)
    print(f" {texto.upper()} ".center(60, "="))
    print("=" * 60 + "\n")


def run_aiops_pipeline():
    print_header("INICIANDO SUPERVISOR AIOPS (MODO NOC CONTINUO)")

    # Reset de estado en memoria (defensivo: si se re-entra al pipeline dentro
    # del mismo proceso Python, no queremos arrastrar reglas/ciclos de la
    # sesión anterior — los falsos positivos antiguos no deben "reciclarse").
    global _current_ciclo
    _reglas_activas.clear()
    _ciclos_limpios.clear()
    _recently_relaxed.clear()
    _pending_flow_alerts.clear()
    _current_ciclo = 1

    # Limpieza agresiva de tmp/ — sólo se preserva topology_cache.json (la
    # plantilla de topología). Todo lo demás (logs, métricas, alertas, reportes,
    # ficheros sueltos) se borra para empezar la simulación con cero ruido.
    for _stale in (
        # estado de la sesión NOC
        "metrics_history.json", "state.json", "topologia_interactiva.html",
        "qos_history.json", "live_metrics.json", "network_history.json",
        "flows.json", "flows_history.json",
        "anomaly_injections.jsonl", "flow_alerts.jsonl",
        "attack_report.md", "anomaly_report.md",
        "host_port_map.json", "topology.json", "port_baseline.json",
        "server_services.json",
        # failover
        "failover_state.json", "failover_requests.json", "failover_history.jsonl",
        # QoS por intent del usuario
        "qos_intent_state.json",
        # informes y artefactos de agentes
        "ultimo_informe.txt", "ultima_rafaga_realista.txt",
        # audit log: se reinicia por sesión — para histórico usa saved_runs/
        "noc_audit.log",
        "noc_audit.log.1", "noc_audit.log.2", "noc_audit.log.3",
        "noc_audit.log.4", "noc_audit.log.5",
    ):
        _p = os.path.join(TMP_DIR, _stale)
        try:
            os.remove(_p)
        except FileNotFoundError:
            pass

    # Volver dashboard a modo "live" (tmp/) por si quedó apuntando a un
    # saved_runs/<run> de una sesión anterior — sin esto el dashboard
    # seguiría mostrando datos del run guardado en vez de la sesión nueva.
    try:
        from dashboard import app as _dash_app
        _dash_app._active_run = None
    except Exception:
        pass

    setup_audit_log()
    registrar_log("=== INICIO DE SESIÓN NOC ===")

    # =======================================================
    # === FASE 1: TOPOLOGÍA (con caché opcional) ============
    # =======================================================
    cache = _load_topology_cache()
    use_cache = False

    if cache:
        desc   = _describe_intent(cache.get("intent", {}))
        req    = cache.get("user_request", "—")
        print(f"\n[CACHÉ] Topología guardada encontrada:")
        print(f"  Tipo        : {desc}")
        print(f"  Descripción : {req}")
        resp = input("¿Reutilizar topología guardada? (S/n): ").strip().lower()
        use_cache = resp != "n"

    start_dashboard(port=config.DASHBOARD_PORT)
    print(f"[DASHBOARD] Disponible en http://0.0.0.0:{config.DASHBOARD_PORT}")

    if use_cache:
        user_request = cache["user_request"]
        intent       = cache["intent"]
        # Regeneramos siempre el script desde el intent: la caché conserva sólo
        # la intención del usuario, no el código. Así los cambios en
        # deploy_agent (launchers tipados, lanzadores de servicio, etc.) se
        # aplican aunque la topología venga de un run antiguo.
        code         = build_python_script(intent)
        print(f"\n[CACHÉ] Topología cargada — se omite la generación IA. "
              f"Script regenerado con build_python_script actual.")
    else:
        user_request = input(
            "Describe la topología de red (Ej: 'una red en árbol con profundidad 2 y fanout 4'):\n> "
        )
        intent = generate_network_intent(user_request)
        if not intent:
            print("[ERROR] No se pudo interpretar la solicitud. Saliendo...")
            registrar_log("ERROR CRÍTICO: La IA no pudo generar un intent de red.")
            return
        code = build_python_script(intent)
        _save_topology_cache(user_request, intent, code)

    # Validaciones (se aplican siempre, también sobre la caché)
    if intent.get("tipo") == "custom" and not intent.get("links"):
        print("[ERROR] La topología custom no tiene enlaces definidos. Saliendo...")
        registrar_log("ERROR CRÍTICO: intent custom sin links.")
        return

    if intent.get("tipo") == "custom":
        from agents.deploy_agent import _find_isolated_nodes
        isolated = _find_isolated_nodes(intent)
        isolated_switches = {n for n in isolated if n.startswith("s")}
        if isolated_switches:
            print(f"[ERROR] Switches sin enlazar: {sorted(isolated_switches)}. Topología inviable. Saliendo...")
            registrar_log(f"ERROR CRÍTICO: switches aislados {isolated_switches}.")
            return
        if isolated:
            print(f"[AVISO] Nodos sin enlazar que se omitirán: {sorted(isolated)}. Continuando...")
            registrar_log(f"AVISO: nodos aislados omitidos {isolated}.")

    print(f"\n[IA] Intención:\n{json.dumps(intent, indent=2)}")

    registrar_log(f"Desplegando topología: tipo={intent.get('tipo')} intent={intent}")
    deploy_unified_in_vm(code)

    endpoints = get_active_endpoints()
    if not endpoints:
        print("[ERROR] No se detectan endpoints. Saliendo...")
        registrar_log("ERROR CRÍTICO: No se detectaron endpoints.")
        return
    print(f"[INFO] Endpoints detectados: {endpoints}")

    # Re-persistir mapping de servicios desplegados — la caché de topología
    # se salta build_python_script y por tanto no lo regenera. Sin esto el
    # dashboard y traffic no ven los tipos al reutilizar topología.
    try:
        srv_types = assign_server_types(intent)
        if srv_types:
            srv_ips   = {n: endpoints.get(n) for n in srv_types}
            services  = _persist_server_services(srv_types, srv_ips)
            if services:
                print(f"[INFO] Servicios desplegados: "
                      f"{ {k: v.get('type') for k, v in services.items()} }")
    except Exception as _e:
        print(f"[WARN] No se pudo persistir server_services.json: {_e}")

    try:
        links = get_topology_links()
        draw_topology(links)
    except Exception as _e:
        print(f"[WARN] No se pudo generar la topología interactiva: {_e}")
        links = []

    # ── topology.json fresco: mapping ip→host completo (multi-interfaz) ──
    # Es lo que usan /api/flows (Sankey) y monitor_agent.detect_flow_anomalies
    # para resolver IPs a nombres. Sin esto, todo aparece como IP cruda.
    try:
        host_ips = dump_host_interfaces()
        if not host_ips:
            print("[WARN] dump_host_interfaces devolvió vacío — el Sankey "
                  "mostrará IPs en vez de nombres. Revisa el prompt de Mininet.")
        persist_topology_json(host_ips, links)
        if host_ips:
            print(f"[INFO] Mapping ip→host persistido para {len(host_ips)} host(s): "
                  f"{ {k: v for k, v in list(host_ips.items())[:6]} }"
                  f"{'…' if len(host_ips) > 6 else ''}")
    except Exception as _e:
        print(f"[WARN] No se pudo persistir topology.json: {_e}")

    # Mapa host → puerto OVS: lo necesitan attack_tool y monitor_agent
    try:
        host_port = build_host_port_map()
        print(f"[INFO] Host→puerto OVS: {host_port}")
    except Exception as _e:
        print(f"[WARN] No se pudo construir host_port_map: {_e}")

    # =======================================================
    # === FASE 2: TRÁFICO + COLECTOR LIVE ===================
    # =======================================================
    registrar_log(f"Lanzando tráfico en background: {list(endpoints.keys())}")
    launch_background_traffic(endpoints)

    # ── sFlow: visibilidad de flujos extremo a extremo ──────────────────────
    try:
        from utils.ssh_client import get_ssh_connection
        _ssh = get_ssh_connection()
        bridges_ok = configure_sflow_on_bridges(_ssh)
        if bridges_ok:
            if start_sflow_daemon(_ssh):
                registrar_log(f"sFlow activo en bridges: {bridges_ok}")
                threading.Thread(
                    target=_sflow_collector, daemon=True, name="sflow-collector",
                ).start()
    except Exception as _e:
        print(f"[WARN] No se pudo activar sFlow: {_e}")

    # El colector se ejecuta de forma continua. El lock SSH solo se adquiere
    # durante las operaciones tmux (telemetría y ejecución QoS), no durante LLM.
    threading.Thread(target=_live_collector, daemon=True, name="live-collector").start()
    threading.Thread(target=_flow_watcher,   daemon=True, name="flow-watcher").start()

    # =======================================================
    # === BUCLE INFINITO DE MONITORIZACIÓN Y RESOLUCIÓN =====
    # =======================================================
    ciclo = 1
    intervalo_actual = config.INTERVALO_BASE

    # ── Failover: seleccionar par primario/secundario y arrancar hilo dedicado ──
    _fo_server_info = load_server_info()
    _fo_pair        = auto_select_pair(_fo_server_info)
    if _fo_pair:
        registrar_log(
            f"FAILOVER: par seleccionado — primario={_fo_pair[0]}, secundario={_fo_pair[1]}"
        )
        print(f"[FAILOVER] Par: {_fo_pair[0]} (primario) → {_fo_pair[1]} (secundario)")
        # El hilo de failover sondea cada FAILOVER_POLL_INTERVAL segundos
        # — independiente del ciclo NOC, así reacciona en segundos. Los
        # eventos los escribe directamente al audit log vía registrar_log.
        set_log_callback(registrar_log)
        start_failover_loop(_fo_pair, lambda: _current_ciclo)
    else:
        print("[FAILOVER] No se encontró par válido (necesita 2 servidores del mismo tipo en el mismo bridge)")

    print_header("NOC ACTIVO — TRÁFICO CORRIENDO EN BACKGROUND")
    print(">>> Pulsa Ctrl+C en cualquier momento para detener el sistema NOC <<<\n")

    # Alias locales al estado compartido con _flow_watcher.
    reglas_activas = _reglas_activas
    ciclos_limpios = _ciclos_limpios

    try:
        while True:
            _current_ciclo = ciclo
            cycle_t0 = time.monotonic()
            print_header(f"CICLO DE SUPERVISIÓN #{ciclo}")
            registrar_log(f"--- Iniciando Ciclo #{ciclo} (intervalo={intervalo_actual}s) ---")

            # ── A0. FAILOVER: el hilo dedicado sondea cada FAILOVER_POLL_INTERVAL
            # segundos. Aquí solo drenamos los veredictos asíncronos del LLM
            # para que aparezcan en la entrada del monitor.
            fo_lines = drain_llm_messages() if _fo_pair else []

            # ── A. TELEMETRÍA: bloqueo SSH breve ─────────────────────────────
            with _live_lock:
                telemetry = collect_telemetry()

            # Incorporar veredictos del LLM de failover
            if fo_lines:
                telemetry = (telemetry or "") + "\n" + "\n".join(fo_lines)

            # Incorporar alertas de flujo acumuladas por _flow_watcher
            # (ataques detectados entre ciclos, mientras el LLM bloqueaba)
            pending_lines = []
            while _pending_flow_alerts:
                pending_lines.append(_pending_flow_alerts.popleft())
            if pending_lines:
                telemetry = (telemetry or "") + "\n" + "\n".join(pending_lines)
                print(f"\n[FLOW WATCHER] {len(pending_lines)} alerta(s) acumuladas:\n"
                      + "\n".join(pending_lines))

            if telemetry and telemetry.strip():
                print(f"\n[TELEMETRÍA DELTA]\n{telemetry}")

            # ── B-fast: acciones deterministas inmediatas (sin LLM) ───────────
            # Aplica DEFAULT_POLICY a puertos con alertas en telemetría/pending
            # que aún no hayan sido tratados por _flow_watcher mid-ciclo.
            # Los puertos ya en reglas_activas (incluyendo acciones del watcher)
            # se excluyen automáticamente por la condición "not in reglas_activas".
            #
            # skip_drops: suprimir [ALERTA ROJA] en puertos recientemente desescalados
            # (sus drops son acumulados del ciclo de POLICING anterior, no ataques nuevos).
            _skip_drops = set(_recently_relaxed.keys())
            newly_fast_ports: set = set()
            fast_actions = fast_decide(telemetry, reglas_activas,
                                       skip_alerta_roja_ports=_skip_drops)
            new_fast = [
                a for a in fast_actions
                if a.get("action") not in ("NO_ACTION", None)
                and a.get("target_port") not in reglas_activas
            ]
            if new_fast:
                print(f"\n[FAST QoS] {len(new_fast)} acción(es) inmediatas antes del LLM...")
                with _live_lock:
                    resolve_multiple(new_fast)
                for a in new_fast:
                    p = a["target_port"]
                    proto = a.get("protocol")
                    reglas_activas[p] = {
                        "action": a["action"], "ciclo": ciclo, "protocol": proto,
                    }
                    ciclos_limpios[p] = 0
                    newly_fast_ports.add(p)
                    proto_tag = f" [proto={proto}]" if proto else ""
                    registrar_log(
                        f"ACCIÓN RÁPIDA: {a['action']}{proto_tag} en {p}. "
                        f"Motivo: {a.get('reason', 'Automático')}"
                    )
                    _write_qos_event(p, a["action"], "apply", ciclo, protocol=proto)

            # ── B. ANÁLISIS IA: sin lock — el colector puede muestrear ────────
            print("\n[SUPERVISOR] Analizando estado de la red...")
            informe = generate_network_report(telemetry)
            print(f"\n[INFORME IA]\n{informe}")

            print("\n[SUPERVISOR] Evaluando intervenciones (QoS)...")
            decision = analyze_and_decide(informe, telemetry, reglas_activas,
                                          skip_alerta_roja_ports=_skip_drops)

            # Escalado forzado — excluye puertos que acaban de recibir fast_decide
            # en este mismo ciclo para evitar escalar inmediatamente.
            _esc = {"SHAPING": "POLICING", "POLICING": "BLOCK", "BLOCK": "BLOCK"}
            _lvl = {"SHAPING": 1, "POLICING": 2, "BLOCK": 3}
            for a in (decision or []):
                port   = a.get("target_port")
                action = a.get("action")
                if port in newly_fast_ports:
                    a["action"] = "NO_ACTION"  # LLM no re-actúa sobre fast ports este ciclo
                    continue
                if port and action not in ("NO_ACTION", None) and port in reglas_activas:
                    previa = reglas_activas[port]["action"]
                    if _lvl.get(action, 0) < _lvl.get(previa, 0):
                        # Acción propuesta más débil que la existente → no degradar, NO_ACTION.
                        a["action"] = "NO_ACTION"
                    elif action == previa:
                        # Misma acción sin efecto → forzar escalado.
                        nueva = _esc.get(previa, "BLOCK")
                        print(f"  [ESCALADO FORZADO] {port}: {previa} → {nueva}")
                        a["action"] = nueva
                        a["reason"] = (
                            f"Forzado: {previa} ya aplicado en ciclo "
                            f"{reglas_activas[port]['ciclo']} sin efecto."
                        )

            acciones_reales = [a for a in (decision or []) if a.get("action") != "NO_ACTION"]
            if acciones_reales or new_fast:
                for a in acciones_reales:
                    proto = a.get("protocol")
                    proto_tag = f" [proto={proto}]" if proto else ""
                    registrar_log(
                        f"ALERTA RESUELTA: {a.get('action')}{proto_tag} en {a.get('target_port')}. "
                        f"Motivo: {a.get('reason', 'Automático')}"
                    )
                    _write_qos_event(
                        a.get("target_port"), a.get("action"), "apply", ciclo, protocol=proto,
                    )
            else:
                registrar_log("ESTADO: Red estable, sin intervenciones requeridas.")

            # Calcular puertos alertados (sin SSH)
            alerted_this_cycle = set(
                re.findall(
                    r"(?:\[ALERTA ROJA\]|\[TRÁFICO INTENSO\]).*?Port\s+(s\d+-eth\d+):",
                    telemetry or "",
                )
            )

            # ── C. EJECUCIÓN + DESESCALADO: bloqueo SSH breve ────────────────
            with _live_lock:
                # Solo ejecuta las decisiones LLM (los fast ya se aplicaron arriba)
                resolve_multiple(decision)

                for a in (decision or []):
                    if a.get("action") not in ("NO_ACTION", None) and a.get("target_port"):
                        reglas_activas[a["target_port"]] = {
                            "action":   a["action"],
                            "ciclo":    ciclo,
                            "protocol": a.get("protocol"),
                        }
                        ciclos_limpios[a["target_port"]] = 0

                puertos_a_desescalar = {}
                for port, info in list(reglas_activas.items()):
                    if port not in alerted_this_cycle:
                        ciclos_limpios[port] = ciclos_limpios.get(port, 0) + 1
                        if ciclos_limpios[port] >= config.CICLOS_PARA_DESESCALAR:
                            # Pasamos el dict completo para que run_desescalado
                            # conserve el scope (protocolo) al re-aplicar.
                            puertos_a_desescalar[port] = {
                                "action":   info["action"],
                                "protocol": info.get("protocol"),
                            }
                    else:
                        ciclos_limpios[port] = 0

                if puertos_a_desescalar:
                    nuevas = run_desescalado(puertos_a_desescalar)
                    resumen = []   # para log consolidado en una sola línea
                    for port, nuevo_nivel in nuevas.items():
                        proto_prev = reglas_activas.get(port, {}).get("protocol")
                        if nuevo_nivel is None:
                            del reglas_activas[port]
                            _write_qos_event(port, None, "remove", ciclo, protocol=proto_prev)
                            # Cooling: el watcher exigirá N=3 sobre este puerto
                            # durante los próximos 2 ciclos para evitar flapping.
                            _recently_relaxed[port] = ciclo
                            resumen.append(f"{port}→remove")
                        else:
                            reglas_activas[port] = {
                                "action":   nuevo_nivel,
                                "ciclo":    ciclo,
                                "protocol": proto_prev,
                            }
                            _write_qos_event(port, nuevo_nivel, "relax", ciclo, protocol=proto_prev)
                            resumen.append(f"{port}→{nuevo_nivel}")
                        ciclos_limpios.pop(port, None)
                    registrar_log(
                        f"DESESCALADO: {', '.join(resumen)} "
                        f"(tras {config.CICLOS_PARA_DESESCALAR} ciclos limpios)"
                    )

                # Limpiar entradas de cooling expiradas (>2 ciclos)
                for p in list(_recently_relaxed.keys()):
                    if ciclo - _recently_relaxed[p] > 2:
                        del _recently_relaxed[p]

            # ── D. INTERVALO ADAPTATIVO + ESTADO (sin SSH) ───────────────────
            if alerted_this_cycle:
                intervalo_actual = config.INTERVALO_MIN
                estado_red = "ALERTA"
            elif reglas_activas:
                intervalo_actual = config.INTERVALO_BASE
                estado_red = "QoS Activa"
            else:
                intervalo_actual = min(
                    config.INTERVALO_MAX,
                    intervalo_actual + config.PASO_AMPLIACION,
                )
                estado_red = "ESTABLE"

            try:
                state_path = os.path.join(TMP_DIR, "state.json")
                with open(state_path, "w", encoding="utf-8") as _f:
                    json.dump(
                        {
                            "ciclo":            ciclo,
                            "timestamp":        datetime.now().isoformat(timespec="seconds"),
                            "estado_red":       estado_red,
                            "intervalo_actual": intervalo_actual,
                            "reglas_activas":   reglas_activas,
                            "ultimo_informe":   informe,
                        },
                        _f,
                        ensure_ascii=False,
                        indent=2,
                    )
            except IOError:
                pass

            # ── E. INYECCIÓN DE ANOMALÍAS ────────────────────────────────────
            # Probabilística (config.ANOMALY_PROBABILITY). Si dispara, queda
            # registrada en tmp/anomaly_injections.jsonl para correlacionar.
            try:
                inj = maybe_inject_anomaly(endpoints)
                if inj:
                    registrar_log(
                        f"ANOMALY INJECTED id={inj['id']} type={inj['type']} "
                        f"duration={inj['duration_sec']}s"
                    )
            except Exception as _e:
                print(f"[WARN] attack_tool falló: {_e}")
                registrar_log(f"WARN attack_tool falló: {_e}")

            # Sleep adaptativo: `intervalo_actual` es el período objetivo del ciclo
            # entero (telemetría + LLM + QoS). Sólo dormimos lo que falte para
            # cumplirlo. Si el LLM se pasó, seguimos sin pausa adicional.
            elapsed   = time.monotonic() - cycle_t0
            remaining = max(0.0, intervalo_actual - elapsed)
            print(
                f"\n[NOC] Ciclo #{ciclo} completado [{estado_red}]. "
                f"Trabajo={elapsed:.1f}s · durmiendo {remaining:.1f}s "
                f"(objetivo {intervalo_actual}s)"
            )
            registrar_log(
                f"Ciclo #{ciclo} finalizado — estado={estado_red}, "
                f"work={elapsed:.1f}s, sleep={remaining:.1f}s, target={intervalo_actual}s"
            )
            if remaining > 0:
                time.sleep(remaining)
            ciclo += 1

    except KeyboardInterrupt:
        print_header("SUPERVISOR DETENIDO POR EL USUARIO")
        registrar_log("=== APAGADO DEL SISTEMA (Intervención manual) ===")
        stop_failover_loop()
        stop_background_traffic()
        try:
            from utils.ssh_client import get_ssh_connection
            _ssh = get_ssh_connection()
            remove_sflow_from_bridges(_ssh)
            stop_sflow_daemon(_ssh)
        except Exception:
            pass
        # ── Reporte de detección de anomalías ──────────────────────────────
        try:
            report_path, results = generate_anomaly_report()
            total = len(results)
            det   = sum(1 for r in results if r["detected"])
            pct   = (100.0 * det / total) if total else 0.0
            print(f"\n[REPORT] Anomalías inyectadas: {total} · detectadas: {det} ({pct:.0f}%)")
            print(f"[REPORT] Informe completo: {report_path}")
            registrar_log(f"REPORT anomalías: {det}/{total} detectadas")
        except Exception as _e:
            print(f"[WARN] No se pudo generar el reporte de anomalías: {_e}")
        close_persistent_connection()
        print("Sistema NOC detenido. ¡Hasta pronto!")


if __name__ == "__main__":
    run_aiops_pipeline()
