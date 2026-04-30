import sys
import os
import time

# Nos aseguramos de que Python encuentre la carpeta agents
sys.path.append(os.path.join(os.path.dirname(__file__), "agents"))

# Importamos las funciones principales de nuestros agentes
try:
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
except ImportError as e:
    print(f"Error importando módulos: {e}")
    sys.exit(1)


def print_header(texto):
    print("\n" + "=" * 50)
    print(f" {texto.upper()} ".center(50, "="))
    print("=" * 50 + "\n")


def run_aiops_pipeline():
    print_header("INICIANDO SUPERVISOR AIOPS")

    # --- FASE 1: DESPLIEGUE ---
    print_header("FASE 1: DESPLIEGUE DE INFRAESTRUCTURA")
    clear_agent_memory()
    user_request = input(
        "Describe la topología de red (Ej: 'una red en árbol con profundidad 2 y fanout 4'):\n> "
    )
    cmd = generate_mininet_command(user_request)
    print(f"\n[IA] Comando sugerido: sudo {cmd}")

    if input("\n¿Desplegar? (s/n): ").lower() != "s":
        return
    deploy_in_vm(cmd)

    # --- FASE 2: INYECCIÓN DE TRÁFICO (ATAQUE 1) ---
    print_header("FASE 2: TRÁFICO DE RED (SIN QoS)")
    hosts = get_active_hosts()
    if not hosts:
        print("[ERROR] No se detectan hosts. Saliendo...")
        return

    comandos_trafico = generate_bulk_traffic(hosts)

    # Guardamos los comandos en memoria temporal para el re-test
    with open("ultima_rafaga.txt", "w") as f:
        f.write("\n".join(comandos_trafico))

    print(f"[SUPERVISOR] Lanzando {len(comandos_trafico)} flujos en background...")
    run_bulk_traffic_logic(
        comandos_trafico
    )  # ¡OJO! Tendrás que refactorizar esto levemente (lee abajo)

    # --- FASE 3: MONITORIZACIÓN ---
    print_header("FASE 3: MONITORIZACIÓN Y ANÁLISIS")
    telemetry = collect_telemetry()
    print(telemetry)
    informe = generate_network_report(telemetry)
    print(f"\n[INFORME IA]\n{informe}")

    # --- FASE 4: RESOLUCIÓN ---
    print_header("FASE 4: MITIGACIÓN (QoS)")
    decision = analyze_and_decide(informe)
    execute_resolution(decision)

    # --- FASE 5: RE-TEST (VERIFICACIÓN DE BUCLE CERRADO) ---
    print_header("FASE 5: RE-EVALUACIÓN (CON QoS)")
    print(
        "[SUPERVISOR] Relanzando la misma ráfaga de estrés para comprobar la mitigación..."
    )
    run_bulk_traffic_logic(comandos_trafico)

    telemetry_post = collect_telemetry()
    print(telemetry_post)
    informe_post = generate_network_report(telemetry_post)
    print(f"\n[INFORME FINAL IA]\n{informe_post}")

    print_header("CICLO AIOps COMPLETADO CON ÉXITO")


if __name__ == "__main__":
    run_aiops_pipeline()
