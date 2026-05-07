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
    get_active_hosts,
    generate_bulk_traffic,
    run_bulk_traffic_logic,
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

    if input("\n¿Desplegar este script? (s/n): ").lower() != "s":
        print("Operación cancelada.")
        return

    registrar_log(f"Desplegando topología: tipo={intent.get('tipo')} intent={intent}")
    deploy_unified_in_vm(code)

    # Obtenemos los hosts activos una sola vez
    hosts = get_active_hosts()
    if not hosts:
        print("[ERROR] No se detectan hosts. Saliendo...")
        registrar_log("ERROR CRÍTICO: No se detectaron hosts.")
        return

    # =======================================================
    # === BUCLE INFINITO DE MONITORIZACIÓN Y RESOLUCIÓN =====
    # =======================================================
    ciclo = 1
    try:
        while True:
            print_header(f"INICIANDO CICLO DE SUPERVISIÓN #{ciclo}")
            registrar_log(f"--- Iniciando Ciclo #{ciclo} ---")

            # --- A. INYECCIÓN DE TRÁFICO ---
            print("[SUPERVISOR] Simulando nueva época de tráfico en la red...")
            comandos_trafico = generate_bulk_traffic(hosts)
            run_bulk_traffic_logic(comandos_trafico)

            # --- B. SENSOR Y DIAGNÓSTICO ---
            print("\n[SUPERVISOR] Analizando el estado de la red...")
            telemetry = collect_telemetry()
            informe = generate_network_report(telemetry)
            print(f"\n[INFORME IA]\n{informe}")

            # --- C. RESOLUCIÓN AUTOMÁTICA ---
            print("\n[SUPERVISOR] Evaluando intervenciones (QoS)...")
            decision = analyze_and_decide(informe)

            # Guardamos la decisión de la IA en el Log
            if decision and decision.get("action") != "none":
                accion = decision.get("action")
                puerto = decision.get("target_port")
                motivo = decision.get("reason", "Sin motivo")
                registrar_log(
                    f"ALERTA RESUELTA: Se aplicó {accion} en {puerto}. Motivo: {motivo}"
                )
            else:
                registrar_log("ESTADO: Red estable, sin intervenciones requeridas.")

            execute_resolution(decision)

            print_header(f"FIN DEL CICLO #{ciclo}")
            print("El sistema entrará en reposo 10 segundos antes del siguiente ciclo.")
            print(">>> Pulsa Ctrl+C para detener el Supervisor NOC <<<")

            time.sleep(10)
            ciclo += 1

    except KeyboardInterrupt:
        print_header("SUPERVISOR DETENIDO POR EL USUARIO")
        print("Saliendo del Modo NOC de forma segura. ¡Hasta pronto!")
        registrar_log("APAGADO DEL SISTEMA (Intervención manual)")


if __name__ == "__main__":
    run_aiops_pipeline()
