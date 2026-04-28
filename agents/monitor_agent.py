import sys
import os
import time
import re
import ollama

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)

MODEL_NAME = "qwen2.5:3b"


def collect_telemetry():
    """Recolecta datos y añade alertas visuales para ayudar a la IA."""
    print("\n[SENSOR] Recolectando telemetría de la red...")
    try:
        ssh = get_ssh_connection()

        # Limpiamos buffer
        send_tmux_command(ssh, "")
        wait_for_mininet_prompt(ssh, timeout=5)

        print(" -> Ejecutando test de latencia (pingall)...")
        send_tmux_command(ssh, "pingall")
        wait_for_mininet_prompt(ssh, timeout=60)

        print(" -> Solicitando estado de los switches...")
        send_tmux_command(ssh, "dpctl dump-ports")
        wait_for_mininet_prompt(ssh, timeout=10)

        raw_output = capture_tmux_output(ssh)
        ssh.close()

        # --- PRE-PROCESADO ROBUSTO CON ALERTAS INYECTADAS ---
        important_lines = []
        for line in raw_output.split("\n"):
            if any(
                key in line
                for key in ["Results:", "dropped", "rx pkts", "tx pkts", "port "]
            ):
                clean_line = line.strip().replace('"', "")

                # LA MAGIA DE PYTHON: Si detectamos drops > 0 (que no sea drop=0)
                match_drop = re.search(r"drop=([1-9]\d*)", clean_line)
                if match_drop:
                    clean_line = f"🔴 [ALERTA ROJA] {clean_line} <-- ¡HAY {match_drop.group(1)} PAQUETES DESCARTADOS AQUÍ!"

                # Si detectamos un número de bytes larguísimo (más de 8 cifras, > 10MB)
                match_bytes = re.search(r"bytes=(\d{8,})", clean_line)
                if match_bytes:
                    clean_line = f"⚠️ [TRÁFICO EXTREMO] {clean_line} <-- CONGESTIÓN EN ESTE PUERTO"

                important_lines.append(clean_line)

        filtro = "\n".join(important_lines)

        if len(important_lines) < 3:
            print(
                "[WARNING SENSOR] La captura de datos parece corrupta o insuficiente."
            )

        return filtro

    except Exception as e:
        print(f"Error crítico en el sensor: {e}")
        return None


def generate_network_report(filtered_telemetry):
    print("\n[IA] Analizando métricas y detectando anomalías...")

    system_prompt = (
        "Eres un Analista Senior de Redes (NOC).\n"
        "Analiza la telemetría de Mininet que se te proporciona.\n\n"
        "REGLAS CRÍTICAS DE FORMATO (¡OBLIGATORIAS!):\n"
        "1. NO repitas mis instrucciones ni las reglas en tu respuesta.\n"
        "2. NO uses bloques de código markdown (como ```plaintext).\n"
        "3. Empieza directamente redactando el informe.\n\n"
        "REGLAS DE ANÁLISIS:\n"
        "1. PRESTA ATENCIÓN A LAS ALERTAS: Si ves [ALERTA ROJA] o [TRÁFICO EXTREMO] en el texto, DEBES reportarlo como un fallo crítico de red o congestión masiva.\n"
        "2. NUNCA digas que la red está sana si hay alertas rojas presentes.\n"
        "3. Menciona exactamente qué puertos están sufriendo congestión o pérdida de paquetes según las alertas."
    )

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"DATA FILTRADA DE RED:\n{filtered_telemetry}"},
        ],
    )

    return response["message"]["content"].strip()


def run_monitor_agent():
    print("=== AGENTE MONITOR DE RED (AIOps) ===")

    telemetry = collect_telemetry()

    if not telemetry:
        print("Error: Fallo al comunicarse con la red.")
        return

    print("\n--- TELEMETRÍA FILTRADA PARA LA IA ---")
    print(telemetry)
    print("---------------------------------------")

    report = generate_network_report(telemetry)

    print("\n================ INFORME DE LA IA ================")
    print(report)
    print("==================================================")


if __name__ == "__main__":
    run_monitor_agent()
