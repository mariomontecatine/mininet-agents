import sys
import os
import time
import re
import json
import ollama

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)

MODEL_NAME = "qwen2.5:7b"
TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)
HISTORY_FILE = os.path.join(TMP_DIR, "network_history.json")


def format_bytes(size):
    """Convierte bytes a formato legible (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def parse_telemetry_to_dict(raw_output):
    """Convierte el texto sucio de dpctl en un diccionario estructurado, ignorando puertos inútiles."""
    stats = {}
    current_port = None

    lines = raw_output.split("\n")
    for line in lines:
        line = line.strip()

        # 1. Detectar la línea de recepción (rx) y sacar el nombre exacto
        if line.startswith("port ") and "rx pkts" in line:
            p_match = re.search(r'port\s+["\']?([a-zA-Z0-9_-]+)["\']?:', line)
            if p_match:
                name = p_match.group(1)

                # LA MAGIA: Si el puerto es LOCAL, lo ignoramos por completo
                if "LOCAL" in name:
                    current_port = None
                    continue

                current_port = name

                if current_port not in stats:
                    stats[current_port] = {"rx_bytes": 0, "tx_bytes": 0, "drop": 0}

                rx_b = re.search(r"bytes=(\d+)", line)
                drop_rx = re.search(r"drop=(\d+)", line)

                if rx_b:
                    stats[current_port]["rx_bytes"] = int(rx_b.group(1))
                if drop_rx:
                    stats[current_port]["drop"] += int(drop_rx.group(1))

        # 2. Detectar la línea de transmisión (tx)
        elif line.startswith("tx pkts") and current_port:
            tx_b = re.search(r"bytes=(\d+)", line)
            drop_tx = re.search(r"drop=(\d+)", line)

            if tx_b:
                stats[current_port]["tx_bytes"] = int(tx_b.group(1))
            if drop_tx:
                stats[current_port]["drop"] += int(drop_tx.group(1))

    return stats


def calculate_delta(current_stats):
    """Calcula la diferencia entre los datos actuales y los guardados."""
    delta_stats = {}

    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            old_stats = json.load(f)
    else:
        old_stats = {}

    for port, data in current_stats.items():
        if port in old_stats:
            # Calculamos la diferencia (Delta)
            d_rx = max(0, data["rx_bytes"] - old_stats[port]["rx_bytes"])
            d_tx = max(0, data["tx_bytes"] - old_stats[port]["tx_bytes"])
            d_dr = max(0, data["drop"] - old_stats[port]["drop"])

            delta_stats[port] = {"rx": d_rx, "tx": d_tx, "drop": d_dr}
        else:
            # FIX: Si es la primera vez, el delta es el valor actual absoluto (porque partimos de 0)
            delta_stats[port] = {
                "rx": data["rx_bytes"],
                "tx": data["tx_bytes"],
                "drop": data["drop"],
            }

    # Guardamos los actuales como referencia para la próxima vez
    with open(HISTORY_FILE, "w") as f:
        json.dump(current_stats, f)

    return delta_stats


def collect_telemetry():
    print("\n[SENSOR] Recolectando telemetría en tiempo real (Modo Delta)...")
    try:
        ssh = get_ssh_connection()
        send_tmux_command(ssh, "dpctl dump-ports")
        wait_for_mininet_prompt(ssh, timeout=15)
        raw_output = capture_tmux_output(ssh)
        ssh.close()

        # 1. Convertir a datos numéricos
        current_data = parse_telemetry_to_dict(raw_output)

        # 2. Calcular cuánto ha cambiado
        deltas = calculate_delta(current_data)

        # 3. Formatear para la IA
        important_lines = []
        if "Results:" in raw_output:
            res = re.search(r"Results:.*", raw_output)
            if res:
                important_lines.append(f">>> CONECTIVIDAD: {res.group(0)}")

        for port, val in deltas.items():
            if val["rx"] == 0 and val["tx"] == 0 and val["drop"] == 0:
                continue

            # USAMOS LA NUEVA FUNCIÓN PARA HUMANIZAR LOS NÚMEROS
            rx_str = format_bytes(val["rx"])
            tx_str = format_bytes(val["tx"])

            line = f"Port {port}: rx_delta={rx_str}, tx_delta={tx_str}, drop_delta={val['drop']}"

            if val["drop"] > 0:
                line = f"🔴 [ALERTA ROJA] {line} <-- ¡PÉRDIDA ACTIVA!"
            if val["rx"] > 10485760 or val["tx"] > 10485760:  # 10MB en bytes
                line = f"⚠️ [TRÁFICO INTENSO] {line} <-- FLUJO ALTO DETECTADO"

            important_lines.append(line)

        return "\n".join(important_lines)

    except Exception as e:
        print(f"Error crítico en el sensor: {e}")
        return None


def generate_network_report(filtered_telemetry):
    print("\n[IA] Analizando deltas de tráfico...")

    if not filtered_telemetry or not filtered_telemetry.strip():
        return "Red estable. No se detectó tráfico significativo ni pérdidas de paquetes en este ciclo."

    system_prompt = (
        "Eres un Analista Senior de Redes (NOC). Responde SOLO con el diagnóstico, "
        "sin repetir instrucciones ni usar markdown.\n"
        "Se te dan estadísticas DELTA de los últimos segundos.\n"
        "REGLAS:\n"
        "1. Identifica los puertos con [ALERTA ROJA] (pérdidas) o [TRÁFICO INTENSO] (>10 MB).\n"
        "2. Nombra cada puerto exactamente como aparece en los datos (ej: s1-eth2).\n"
        "3. Si todo está dentro de lo normal, escribe exactamente: 'Red estable.'\n"
        "4. Máximo 5 líneas."
    )

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"ESTADÍSTICAS DELTA:\n{filtered_telemetry}"},
        ],
        options={"temperature": 0},
    )
    return response["message"]["content"].strip()


def run_monitor_agent():
    print("=== AGENTE MONITOR PRO (Con Memoria de Estado) ===")
    telemetry = collect_telemetry()

    if not telemetry:
        print("Error: No se pudo obtener telemetría.")
        return

    print("\n--- TELEMETRÍA DELTA PARA LA IA ---")
    print(telemetry)

    report = generate_network_report(telemetry)

    with open(os.path.join(TMP_DIR, "ultimo_informe.txt"), "w", encoding="utf-8") as f:
        f.write(report)

    print("\n================ INFORME DE LA IA ================")
    print(report)
    print("==================================================")


if __name__ == "__main__":
    run_monitor_agent()
