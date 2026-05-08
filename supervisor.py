import sys
import os
import time
import json
from datetime import datetime

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
)
from agents.monitor_agent import collect_telemetry, generate_network_report
from agents.resolver_agent import analyze_and_decide, execute_resolution


def print_header(texto):
    print("\n" + "=" * 60)
    print(f" {texto.upper()} ".center(60, "="))
    print("=" * 60 + "\n")


def registrar_log(mensaje):
    """Guarda un registro con fecha y hora en el archivo de bitácora."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea_log = f"[{timestamp}] {mensaje}\n"

    with open(os.path.join(TMP_DIR, "noc_audit.log"), "a", encoding="utf-8") as f:
        f.write(linea_log)


def run_aiops_pipeline():
    print_header("INICIANDO SUPERVISOR AIOPS (MODO NOC CONTINUO)")

    # Limpiamos el log anterior al iniciar
    if os.path.exists(os.path.join(TMP_DIR, "noc_audit.log")):
        os.remove(os.path.join(TMP_DIR, "noc_audit.log"))
    registrar_log("INICIO DEL SISTEMA AIOPS")

    # =======================================================
    # === FASE 1: SETUP DE INFRAESTRUCTURA (Solo 1 vez) =====
    # =======================================================
    user_request = input(
        "Describe la topología de red (Ej: 'una red en árbol con profundidad 2 y fanout 4'):\n> "
    )

    intent = generate_network_intent(user_request)
    if not intent:
        print("[ERROR] No se pudo interpretar la solicitud. Saliendo...")
        registrar_log("ERROR CRÍTICO: La IA no pudo generar un intent de red.")
        return

    print(f"\n[IA] Intención extraída:\n{json.dumps(intent, indent=2)}")
    code = build_python_script(intent)

    registrar_log(f"Desplegando topología: tipo={intent.get('tipo')} intent={intent}")
    deploy_unified_in_vm(code)

    # Obtenemos los endpoints (hosts + servidores) con sus IPs reales
    endpoints = get_active_endpoints()
    if not endpoints:
        print("[ERROR] No se detectan endpoints. Saliendo...")
        registrar_log("ERROR CRÍTICO: No se detectaron endpoints.")
        return
    print(f"[INFO] Endpoints detectados: {endpoints}")

    # =======================================================
    # === FASE 2: ARRANCAR TRÁFICO CONTINUO EN BACKGROUND ===
    # =======================================================
    registrar_log(f"Lanzando tráfico en background: {list(endpoints.keys())}")
    launch_background_traffic(endpoints)

    # =======================================================
    # === BUCLE INFINITO DE MONITORIZACIÓN Y RESOLUCIÓN =====
    # =======================================================
    INTERVALO_CICLO = 10  # segundos entre ciclos de observación
    ciclo = 1

    print_header("NOC ACTIVO — TRÁFICO CORRIENDO EN BACKGROUND")
    print(">>> Pulsa Ctrl+C en cualquier momento para detener el sistema NOC <<<\n")

    try:
        while True:
            print_header(f"CICLO DE SUPERVISIÓN #{ciclo}")
            registrar_log(f"--- Iniciando Ciclo #{ciclo} ---")

            # --- A. SENSOR: Recolectar telemetría (delta) ---
            telemetry = collect_telemetry()
            if telemetry and telemetry.strip():
                print(f"\n[TELEMETRÍA DELTA]\n{telemetry}")

            # --- B. DIAGNÓSTICO: Informe de la IA ---
            print("\n[SUPERVISOR] Analizando estado de la red...")
            informe = generate_network_report(telemetry)
            print(f"\n[INFORME IA]\n{informe}")

            # --- C. DECISIÓN: Evaluación de QoS ---
            print("\n[SUPERVISOR] Evaluando intervenciones (QoS)...")
            decision = analyze_and_decide(informe)

            if decision and decision.get("action") != "none":
                accion = decision.get("action")
                puerto = decision.get("target_port")
                motivo = decision.get("reason", "Sin motivo")
                registrar_log(
                    f"ALERTA RESUELTA: Se aplicó {accion} en {puerto}. Motivo: {motivo}"
                )
            else:
                registrar_log("ESTADO: Red estable, sin intervenciones requeridas.")

            # --- D. EJECUCIÓN: Aplicar QoS si corresponde ---
            execute_resolution(decision)

            print(f"\n[NOC] Ciclo #{ciclo} completado. Próximo análisis en {INTERVALO_CICLO}s...")
            time.sleep(INTERVALO_CICLO)
            ciclo += 1

    except KeyboardInterrupt:
        print_header("SUPERVISOR DETENIDO POR EL USUARIO")
        registrar_log("APAGADO DEL SISTEMA (Intervención manual)")
        stop_background_traffic()
        print("Sistema NOC detenido. ¡Hasta pronto!")


if __name__ == "__main__":
    run_aiops_pipeline()
