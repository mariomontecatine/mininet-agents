import sys
import os
import re
import time
import random
import ollama
import subprocess

# Parche para rutas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import get_ssh_connection, send_tmux_command, capture_tmux_output

MODEL_NAME = "qwen2.5:3b"


def get_active_hosts():
    """Escanea la red y devuelve lista de hosts."""
    try:
        ssh = get_ssh_connection()
        send_tmux_command(ssh, "nodes")
        time.sleep(1)
        output = capture_tmux_output(ssh)
        ssh.close()
        hosts = sorted(list(set(re.findall(r"\bh\d+\b", output))))
        return hosts
    except Exception as e:
        print(f"Error al escanear: {e}")
        return []


def generate_bulk_traffic(hosts):
    print(f"\n[IA] Planificando ráfaga de tráfico masivo para {len(hosts)} hosts...")

    hosts_list = ", ".join(hosts)

    # Preparamos una lista de sugerencias aleatorias para ayudar a la IA
    suggestions = []
    for h in hosts:
        target = random.choice([target for target in hosts if target != h])
        suggestions.append(f"{h} -> {target}")
    suggestions_str = " | ".join(suggestions)

    system_prompt = (
        f"Eres un orquestador de tráfico masivo en Mininet. La red tiene estos hosts: {hosts_list}.\n"
        "TU OBJETIVO: Generar UN comando de iperf para CADA host de la lista para que TODOS envíen tráfico simultáneamente.\n\n"
        "REGLAS CRÍTICAS:\n"
        "1. Debes devolver una lista de comandos, uno por línea.\n"
        "2. Cada comando DEBE terminar con el símbolo '&' para que se ejecuten en paralelo.\n"
        "3. Formato: <origen> iperf -c 10.0.0.<num_destino> -t <segundos> &\n"
        "4. Varía los tiempos (entre 10 y 40s) y decide si usas UDP (-u -b 10M) o TCP (por defecto).\n"
        f"5. Sugerencias de parejas: {suggestions_str}.\n"
        "6. Devuelve SOLO los comandos, sin explicaciones ni markdown."
    )

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "Genera el plan de tráfico masivo para todos los hosts.",
            },
        ],
    )

    raw_output = response["message"]["content"].strip()
    # Limpiamos bloques de código si la IA los pone
    clean_commands = (
        raw_output.replace("```bash", "").replace("```", "").strip().split("\n")
    )

    return [cmd.strip() for cmd in clean_commands if cmd.strip()]


def run_bulk_traffic():
    print("=== AGENTE GENERADOR DE TRÁFICO MASIVO ===")

    repetir = input(
        "\n¿Quieres REPETIR la última ráfaga de tráfico para verificar la QoS? (s/n): "
    )

    if repetir.lower() == "s" and os.path.exists("ultima_rafaga.txt"):
        print("[SISTEMA] Cargando comandos de la ráfaga anterior...")
        with open("ultima_rafaga.txt", "r") as f:
            commands = [line.strip() for line in f.readlines() if line.strip()]
    else:
        # Modo normal (Nuevo ráfaga)
        hosts = get_active_hosts()
        if not hosts:
            print("Error: No se detectan hosts. ¿Está la red levantada?")
            return
        commands = generate_bulk_traffic(hosts)

        # Guardamos el nuevo ráfaga para el futuro
        with open("ultima_rafaga.txt", "w") as f:
            f.write("\n".join(commands))

    print(f"\n[PLAN DE EJECUCIÓN] Se lanzarán {len(commands)} flujos:")
    for c in commands:
        print(f"  > {c}")

    try:
        ssh = get_ssh_connection()

        # 1. Lanzamos todos los flujos
        for cmd in commands:
            # Quitamos el '&' si lo tiene, le añadimos la redirección al agujero negro y volvemos a poner '&'
            cmd_silenciado = cmd.replace("&", "").strip() + " > /dev/null 2>&1 &"
            send_tmux_command(ssh, cmd_silenciado)
            time.sleep(0.1)

        # 2. Calculamos el tiempo de espera
        times = re.findall(r"-t\s+(\d+)", " ".join(commands))
        max_wait = max([int(t) for t in times]) if times else 20

        print(
            f"\n[TRÁFICO] Flujos inyectados. La red estará bajo carga durante {max_wait} segundos."
        )

        # 3. DISPARAMOS EL AGENTE MONITOR AUTOMÁTICAMENTE
        print(
            "\n[ORQUESTACIÓN] Despertando al Agente Monitor para que analice esta ráfaga..."
        )
        ruta_monitor = os.path.join(os.path.dirname(__file__), "monitor_agent.py")

        # Popen lanza el script en paralelo. GUARDAMOS LA REFERENCIA en 'proceso_monitor'
        proceso_monitor = subprocess.Popen([sys.executable, ruta_monitor])

        # 4. Esperamos a que el tráfico termine (nuestra cuenta atrás de iperf)
        time.sleep(max_wait)
        print("\n[TRÁFICO] El ráfaga de tráfico físico ha finalizado en la red.")

        # 5. SINCRONIZACIÓN (La magia para que no se corte)
        # Comprobamos si el Monitor sigue trabajando. Si es así, le esperamos.
        if proceso_monitor.poll() is None:
            print(
                "[ORQUESTACIÓN] Esperando a que la IA del Monitor termine de redactar el informe..."
            )
            proceso_monitor.wait()  # Esto pausa el script hasta que el Monitor acabe 100%

        print("[ORQUESTACIÓN] Ciclo conjunto completado con éxito.")
        ssh.close()

    except Exception as e:
        print(f"Error en ejecución: {e}")


def run_bulk_traffic_logic(commands):
    """Ejecuta una lista de comandos iperf silenciosamente."""
    try:
        ssh = get_ssh_connection()
        for cmd in commands:
            cmd_silenciado = cmd.replace("&", "").strip() + " > /dev/null 2>&1 &"
            send_tmux_command(ssh, cmd_silenciado)
            time.sleep(0.1)

        # Encontramos el tiempo máximo (el -t más grande)
        max_wait = 10
        for cmd in commands:
            match = re.search(r"-t\s+(\d+)", cmd)
            if match:
                max_wait = max(max_wait, int(match.group(1)))

        print(f" -> Esperando {max_wait} segundos a que la ráfaga termine...")
        time.sleep(max_wait)
        ssh.close()
    except Exception as e:
        print(f"Error inyectando tráfico: {e}")


if __name__ == "__main__":
    run_bulk_traffic()
