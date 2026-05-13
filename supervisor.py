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

TMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp")
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
    generate_bulk_traffic,
    run_bulk_traffic_logic,
)
from agents.topology import get_topology_links, draw_topology
from agents.monitor_agent import collect_telemetry, generate_network_report
from agents.resolver_agent import analyze_and_decide, resolve_multiple, run_relaxation

# -------------------------------------------------------
# Auditoría con rotación automática
# -------------------------------------------------------
_audit_logger: logging.Logger | None = None


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


def print_header(texto):
    print("\n" + "=" * 60)
    print(f" {texto.upper()} ".center(60, "="))
    print("=" * 60 + "\n")


def run_aiops_pipeline():
    print_header("INICIANDO SUPERVISOR AIOPS (MODO NOC CONTINUO)")

    setup_audit_log()
    registrar_log("=== INICIO DE SESIÓN NOC ===")

    # Limpiar datos de sesiones anteriores para que la gráfica empiece en blanco
    for _stale in ("metrics_history.json", "state.json", "topologia_interactiva.html"):
        _p = os.path.join(TMP_DIR, _stale)
        try:
            os.remove(_p)
        except FileNotFoundError:
            pass

    # =======================================================
    # === FASE 1: SETUP DE INFRAESTRUCTURA (Solo 1 vez) =====
    # =======================================================
    user_request = input(
        "Describe la topología de red (Ej: 'una red en árbol con profundidad 2 y fanout 4'):\n> "
    )

    start_dashboard(port=config.DASHBOARD_PORT)
    print(f"[DASHBOARD] Disponible en http://0.0.0.0:{config.DASHBOARD_PORT}")

    intent = generate_network_intent(user_request)
    if not intent:
        print("[ERROR] No se pudo interpretar la solicitud. Saliendo...")
        registrar_log("ERROR CRÍTICO: La IA no pudo generar un intent de red.")
        return

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

    print(f"\n[IA] Intención extraída:\n{json.dumps(intent, indent=2)}")
    code = build_python_script(intent)

    registrar_log(f"Desplegando topología: tipo={intent.get('tipo')} intent={intent}")
    run_ping = input("¿Ejecutar pingall tras el despliegue? (s/N): ").strip().lower() == "s"
    deploy_unified_in_vm(code, run_pingall=run_ping)

    # Obtenemos los endpoints (hosts + servidores) con sus IPs reales
    endpoints = get_active_endpoints()
    if not endpoints:
        print("[ERROR] No se detectan endpoints. Saliendo...")
        registrar_log("ERROR CRÍTICO: No se detectaron endpoints.")
        return
    print(f"[INFO] Endpoints detectados: {endpoints}")

    # Generar mapa interactivo Cytoscape para el dashboard
    try:
        links = get_topology_links()
        draw_topology(links)
    except Exception as _e:
        print(f"[WARN] No se pudo generar la topología interactiva: {_e}")

    # =======================================================
    # === FASE 2: ARRANCAR TRÁFICO CONTINUO EN BACKGROUND ===
    # =======================================================
    registrar_log(f"Lanzando tráfico en background: {list(endpoints.keys())}")
    launch_background_traffic(endpoints)

    # =======================================================
    # === BUCLE INFINITO DE MONITORIZACIÓN Y RESOLUCIÓN =====
    # =======================================================
    ciclo = 1
    intervalo_actual = config.INTERVALO_BASE

    print_header("NOC ACTIVO — TRÁFICO CORRIENDO EN BACKGROUND")
    print(">>> Pulsa Ctrl+C en cualquier momento para detener el sistema NOC <<<\n")

    # Estado persistente entre ciclos: {puerto → {"action": str, "ciclo": int}}
    reglas_activas = {}
    # Contadores de ciclos limpios por puerto (sin alerta activa)
    ciclos_limpios = {}

    try:
        while True:
            print_header(f"CICLO DE SUPERVISIÓN #{ciclo}")
            registrar_log(f"--- Iniciando Ciclo #{ciclo} (intervalo={intervalo_actual}s) ---")

            # --- A. TRÁFICO REALISTA: inyectar ráfaga periódica en background ---
            if ciclo % config.CICLOS_ENTRE_RAFAGAS == 0:
                server_cmds, client_cmds = generate_bulk_traffic(endpoints)
                if server_cmds or client_cmds:
                    threading.Thread(
                        target=run_bulk_traffic_logic,
                        args=(server_cmds, client_cmds),
                        daemon=True,
                    ).start()
                    registrar_log(f"Ráfaga de tráfico realista inyectada (ciclo {ciclo})")

            # --- B. SENSOR: Recolectar telemetría (delta) ---
            telemetry = collect_telemetry()
            if telemetry and telemetry.strip():
                print(f"\n[TELEMETRÍA DELTA]\n{telemetry}")

            # --- B. DIAGNÓSTICO: Informe de la IA ---
            print("\n[SUPERVISOR] Analizando estado de la red...")
            informe = generate_network_report(telemetry)
            print(f"\n[INFORME IA]\n{informe}")

            # --- C. DECISIÓN: Evaluación de QoS ---
            print("\n[SUPERVISOR] Evaluando intervenciones (QoS)...")
            decision = analyze_and_decide(informe, telemetry, reglas_activas)

            # Escalado forzado: si el LLM repite una acción ya aplicada, Python la sube de nivel
            _esc = {"POLICING": "SHAPING", "SHAPING": "BLOCK", "BLOCK": "BLOCK"}
            for a in (decision or []):
                port = a.get("target_port")
                action = a.get("action")
                if port and action not in ("NO_ACTION", None) and port in reglas_activas:
                    previa = reglas_activas[port]["action"]
                    if action == previa:
                        nueva = _esc.get(previa, "BLOCK")
                        print(f"  [ESCALADO FORZADO] {port}: {previa} → {nueva}")
                        a["action"] = nueva
                        a["reason"] = f"Forzado: {previa} ya aplicado en ciclo {reglas_activas[port]['ciclo']} sin efecto."

            acciones_reales = [a for a in (decision or []) if a.get("action") != "NO_ACTION"]
            if acciones_reales:
                for a in acciones_reales:
                    registrar_log(
                        f"ALERTA RESUELTA: {a.get('action')} en {a.get('target_port')}. "
                        f"Motivo: {a.get('reason', 'Automático')}"
                    )
            else:
                registrar_log("ESTADO: Red estable, sin intervenciones requeridas.")

            # --- D. EJECUCIÓN: Aplicar todas las acciones de QoS ---
            resolve_multiple(decision)

            # Actualizar estado persistente con las acciones ejecutadas en este ciclo
            for a in (decision or []):
                if a.get("action") not in ("NO_ACTION", None) and a.get("target_port"):
                    reglas_activas[a["target_port"]] = {
                        "action": a["action"],
                        "ciclo": ciclo,
                    }
                    ciclos_limpios[a["target_port"]] = 0  # reset contador al escalar

            # --- E. RELAJACIÓN: revertir restricciones si el tráfico se normalizó ---
            alerted_this_cycle = set(
                re.findall(
                    r"(?:\[ALERTA ROJA\]|\[TRÁFICO INTENSO\]).*?Port\s+(s\d+-eth\d+):",
                    telemetry or "",
                )
            )

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
                    else:
                        reglas_activas[port] = {"action": nuevo_nivel, "ciclo": ciclo}
                        registrar_log(f"RELAJACIÓN PARCIAL: {port} reducido a {nuevo_nivel}")
                    ciclos_limpios.pop(port, None)

            # --- F. INTERVALO ADAPTATIVO ---
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

            # --- G. ESTADO: persistir snapshot para el dashboard ---
            try:
                state_path = os.path.join(TMP_DIR, "state.json")
                with open(state_path, "w", encoding="utf-8") as _f:
                    json.dump(
                        {
                            "ciclo": ciclo,
                            "timestamp": datetime.now().isoformat(timespec="seconds"),
                            "estado_red": estado_red,
                            "intervalo_actual": intervalo_actual,
                            "reglas_activas": reglas_activas,
                            "ultimo_informe": informe,
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
