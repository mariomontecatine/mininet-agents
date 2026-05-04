import sys
import os
import time

# Nos aseguramos de que Python encuentre la carpeta agents
sys.path.append(os.path.join(os.path.dirname(__file__), "agents"))

from agents.deploy_agent import (
    clear_agent_memory,
    generate_mininet_command,
    deploy_in_vm,
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


def run_aiops_pipeline():
    print_header("INICIANDO SUPERVISOR AIOPS (MODO NOC CONTINUO)")

    # =======================================================
    # === FASE 1: SETUP DE INFRAESTRUCTURA (Solo 1 vez) =====
    # =======================================================
    clear_agent_memory()
    user_request = input(
        "Describe la topología de red (Ej: 'una red en árbol con profundidad 2 y fanout 4'):\n> "
    )
    cmd = generate_mininet_command(user_request)
    print(f"\n[IA] Comando sugerido: sudo {cmd}")

    if input("\n¿Desplegar? (s/n): ").lower() != "s":
        print("Operación cancelada.")
        return

    deploy_in_vm(cmd)

    # Obtenemos los hosts activos una sola vez
    hosts = get_active_hosts()
    if not hosts:
        print("[ERROR] No se detectan hosts. Saliendo...")
        return

    # =======================================================
    # === BUCLE INFINITO DE MONITORIZACIÓN Y RESOLUCIÓN =====
    # =======================================================
    ciclo = 1
    try:
        while True:
            print_header(f"INICIANDO CICLO DE SUPERVISIÓN #{ciclo}")

            # --- A. INYECCIÓN DE TRÁFICO (Simulación de usuarios) ---
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
            execute_resolution(decision)

            print_header(f"FIN DEL CICLO #{ciclo}")
            print("El sistema entrará en reposo 10 segundos antes del siguiente ciclo.")
            print(">>> Pulsa Ctrl+C para detener el Supervisor NOC <<<")

            time.sleep(10)
            ciclo += 1

    except KeyboardInterrupt:
        # Esto captura cuando el usuario pulsa Ctrl+C en la terminal
        print_header("SUPERVISOR DETENIDO POR EL USUARIO")
        print("Saliendo del Modo NOC de forma segura. ¡Hasta pronto!")


if __name__ == "__main__":
    run_aiops_pipeline()
