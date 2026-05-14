import sys
import os
import re
import time
import json
import logging
import threading
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
)
from agents.traffic_agent import (
    get_active_endpoints,
    launch_background_traffic,
    stop_background_traffic,
)
from agents.topology import get_topology_links, draw_topology
from agents.monitor_agent import collect_telemetry, generate_network_report
from agents.resolver_agent import analyze_and_decide, resolve_multiple, run_relaxation

# -------------------------------------------------------
# Auditoría con rotación automática
# -------------------------------------------------------
_audit_logger: logging.Logger | None = None

# Lock SSH: solo para secciones que envían comandos tmux.
# Se libera durante las llamadas LLM para que el colector live pueda actuar.
_live_lock = threading.Lock()


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

def _write_qos_event(port, action, event_type, ciclo):
    """Persiste un evento QoS (apply/relax/remove) en qos_history.json para el dashboard."""
    qos_path = os.path.join(TMP_DIR, "qos_history.json")
    history = []
    if os.path.exists(qos_path):
        try:
            with open(qos_path, encoding="utf-8") as f:
                history = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    history.append({
        "ts":     datetime.now().isoformat(timespec="seconds"),
        "cycle":  ciclo,
        "port":   port,
        "action": action,
        "event":  event_type,
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
    Hilo background: recolecta métricas cada 5 s.
    Solo bloquea la conexión SSH brevemente (dpctl dump-ports).
    El lock se libera en el bucle NOC durante las llamadas LLM,
    por lo que el colector obtiene muestras continuas también durante el análisis.
    """
    from agents.monitor_agent import parse_telemetry_to_dict
    from utils.ssh_client import (
        get_ssh_connection,
        send_tmux_command,
        capture_tmux_output,
        wait_for_mininet_prompt,
    )

    live_file = os.path.join(TMP_DIR, "live_metrics.json")
    live_prev: dict = {}

    while True:
        time.sleep(5)

        acquired = _live_lock.acquire(blocking=False)
        if not acquired:
            continue

        try:
            ssh = get_ssh_connection()
            send_tmux_command(ssh, "dpctl dump-ports")
            if not wait_for_mininet_prompt(ssh, timeout=8):
                continue
            raw     = capture_tmux_output(ssh)
            current = parse_telemetry_to_dict(raw)

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
            live_data = live_data[-60:]
            with open(live_file, "w", encoding="utf-8") as f:
                json.dump(live_data, f, ensure_ascii=False)

        except Exception:
            pass
        finally:
            _live_lock.release()


def print_header(texto):
    print("\n" + "=" * 60)
    print(f" {texto.upper()} ".center(60, "="))
    print("=" * 60 + "\n")


def run_aiops_pipeline():
    print_header("INICIANDO SUPERVISOR AIOPS (MODO NOC CONTINUO)")

    setup_audit_log()
    registrar_log("=== INICIO DE SESIÓN NOC ===")

    # Limpiar datos de sesiones anteriores (la caché NO se borra)
    for _stale in (
        "metrics_history.json", "state.json", "topologia_interactiva.html",
        "qos_history.json", "live_metrics.json", "network_history.json",
    ):
        _p = os.path.join(TMP_DIR, _stale)
        try:
            os.remove(_p)
        except FileNotFoundError:
            pass

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
        code         = cache["code"]
        print(f"\n[CACHÉ] Topología cargada — se omite la generación IA.")
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

    # Preguntar si redesplegar (solo cuando se usa caché)
    if use_cache:
        resp = input("¿Redesplegar la topología en la VM? (S/n): ").strip().lower()
        do_deploy = resp != "n"
    else:
        do_deploy = True

    if do_deploy:
        registrar_log(f"Desplegando topología: tipo={intent.get('tipo')} intent={intent}")
        deploy_unified_in_vm(code)
    else:
        print("[INFO] Saltando despliegue — se asume que Mininet ya está activo.")
        registrar_log("INFO: Despliegue omitido por el usuario (caché reutilizada).")

    endpoints = get_active_endpoints()
    if not endpoints:
        print("[ERROR] No se detectan endpoints. Saliendo...")
        registrar_log("ERROR CRÍTICO: No se detectaron endpoints.")
        return
    print(f"[INFO] Endpoints detectados: {endpoints}")

    try:
        links = get_topology_links()
        draw_topology(links)
    except Exception as _e:
        print(f"[WARN] No se pudo generar la topología interactiva: {_e}")

    # =======================================================
    # === FASE 2: TRÁFICO + COLECTOR LIVE ===================
    # =======================================================
    registrar_log(f"Lanzando tráfico en background: {list(endpoints.keys())}")
    launch_background_traffic(endpoints)

    # El colector se ejecuta de forma continua. El lock SSH solo se adquiere
    # durante las operaciones tmux (telemetría y ejecución QoS), no durante LLM.
    threading.Thread(target=_live_collector, daemon=True, name="live-collector").start()

    # =======================================================
    # === BUCLE INFINITO DE MONITORIZACIÓN Y RESOLUCIÓN =====
    # =======================================================
    ciclo = 1
    intervalo_actual = config.INTERVALO_BASE

    print_header("NOC ACTIVO — TRÁFICO CORRIENDO EN BACKGROUND")
    print(">>> Pulsa Ctrl+C en cualquier momento para detener el sistema NOC <<<\n")

    reglas_activas = {}
    ciclos_limpios = {}

    try:
        while True:
            print_header(f"CICLO DE SUPERVISIÓN #{ciclo}")
            registrar_log(f"--- Iniciando Ciclo #{ciclo} (intervalo={intervalo_actual}s) ---")

            # ── A. TELEMETRÍA: bloqueo SSH breve ─────────────────────────────
            with _live_lock:
                telemetry = collect_telemetry()

            if telemetry and telemetry.strip():
                print(f"\n[TELEMETRÍA DELTA]\n{telemetry}")

            # ── B. ANÁLISIS IA: sin lock — el colector puede muestrear ────────
            print("\n[SUPERVISOR] Analizando estado de la red...")
            informe = generate_network_report(telemetry)
            print(f"\n[INFORME IA]\n{informe}")

            print("\n[SUPERVISOR] Evaluando intervenciones (QoS)...")
            decision = analyze_and_decide(informe, telemetry, reglas_activas)

            # Escalado forzado (sin SSH)
            _esc = {"POLICING": "SHAPING", "SHAPING": "BLOCK", "BLOCK": "BLOCK"}
            for a in (decision or []):
                port   = a.get("target_port")
                action = a.get("action")
                if port and action not in ("NO_ACTION", None) and port in reglas_activas:
                    previa = reglas_activas[port]["action"]
                    if action == previa:
                        nueva = _esc.get(previa, "BLOCK")
                        print(f"  [ESCALADO FORZADO] {port}: {previa} → {nueva}")
                        a["action"] = nueva
                        a["reason"] = (
                            f"Forzado: {previa} ya aplicado en ciclo "
                            f"{reglas_activas[port]['ciclo']} sin efecto."
                        )

            acciones_reales = [a for a in (decision or []) if a.get("action") != "NO_ACTION"]
            if acciones_reales:
                for a in acciones_reales:
                    registrar_log(
                        f"ALERTA RESUELTA: {a.get('action')} en {a.get('target_port')}. "
                        f"Motivo: {a.get('reason', 'Automático')}"
                    )
                    _write_qos_event(a.get("target_port"), a.get("action"), "apply", ciclo)
            else:
                registrar_log("ESTADO: Red estable, sin intervenciones requeridas.")

            # Calcular puertos alertados (sin SSH)
            alerted_this_cycle = set(
                re.findall(
                    r"(?:\[ALERTA ROJA\]|\[TRÁFICO INTENSO\]).*?Port\s+(s\d+-eth\d+):",
                    telemetry or "",
                )
            )

            # ── C. EJECUCIÓN + RELAJACIÓN: bloqueo SSH breve ─────────────────
            with _live_lock:
                resolve_multiple(decision)

                for a in (decision or []):
                    if a.get("action") not in ("NO_ACTION", None) and a.get("target_port"):
                        reglas_activas[a["target_port"]] = {
                            "action": a["action"],
                            "ciclo":  ciclo,
                        }
                        ciclos_limpios[a["target_port"]] = 0

                puertos_a_relajar = {}
                for port, info in list(reglas_activas.items()):
                    if port not in alerted_this_cycle:
                        ciclos_limpios[port] = ciclos_limpios.get(port, 0) + 1
                        if ciclos_limpios[port] >= config.CICLOS_PARA_RELAJAR:
                            puertos_a_relajar[port] = info["action"]
                    else:
                        ciclos_limpios[port] = 0

                if puertos_a_relajar:
                    registrar_log(
                        f"RELAJACIÓN INICIADA: {list(puertos_a_relajar.keys())} "
                        f"tras {config.CICLOS_PARA_RELAJAR} ciclos limpios"
                    )
                    nuevas = run_relaxation(puertos_a_relajar)
                    for port, nuevo_nivel in nuevas.items():
                        if nuevo_nivel is None:
                            del reglas_activas[port]
                            registrar_log(f"RELAJACIÓN COMPLETA: {port} sin restricciones activas")
                            _write_qos_event(port, None, "remove", ciclo)
                        else:
                            reglas_activas[port] = {"action": nuevo_nivel, "ciclo": ciclo}
                            registrar_log(f"RELAJACIÓN PARCIAL: {port} reducido a {nuevo_nivel}")
                            _write_qos_event(port, nuevo_nivel, "relax", ciclo)
                        ciclos_limpios.pop(port, None)

            # ── D. INTERVALO ADAPTATIVO + ESTADO (sin SSH) ───────────────────
            if alerted_this_cycle:
                intervalo_actual = config.INTERVALO_MIN
                estado_red = "ALERTA"
            elif reglas_activas:
                intervalo_actual = config.INTERVALO_BASE
                estado_red = "MITIGACIÓN ACTIVA"
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

            print(
                f"\n[NOC] Ciclo #{ciclo} completado [{estado_red}]. "
                f"Próximo análisis en {intervalo_actual}s..."
            )
            registrar_log(f"Ciclo #{ciclo} finalizado — estado={estado_red}, next={intervalo_actual}s")
            time.sleep(intervalo_actual)
            ciclo += 1

    except KeyboardInterrupt:
        print_header("SUPERVISOR DETENIDO POR EL USUARIO")
        registrar_log("=== APAGADO DEL SISTEMA (Intervención manual) ===")
        stop_background_traffic()
        close_persistent_connection()
        print("Sistema NOC detenido. ¡Hasta pronto!")


if __name__ == "__main__":
    run_aiops_pipeline()
