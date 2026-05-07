import sys
import os
import re
import time
import random

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)

TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)


def get_active_endpoints():
    """Consulta a Mininet los nombres e IPs reales de todos los hosts (incluidos servidores)."""
    try:
        ssh = get_ssh_connection()
        send_tmux_command(ssh, "py [(h.name, h.IP()) for h in net.hosts]")
        wait_for_mininet_prompt(ssh, timeout=10)
        raw_output = capture_tmux_output(ssh)
        ssh.close()

        # Parsea líneas como: [('h1', '10.0.0.1'), ('srv1', '192.168.1.2'), ...]
        matches = re.findall(r"\('([^']+)',\s*'([^']*)'\)", raw_output)
        endpoints = {name: ip for name, ip in matches if ip.strip()}
        return endpoints
    except Exception as e:
        print(f"[ERROR] No se pudieron obtener los endpoints: {e}")
        return {}


def generate_bulk_traffic(endpoints, duration=35):
    """Genera comandos iperf usando los nombres e IPs reales de la red activa."""
    if len(endpoints) < 2:
        return [], []

    nombres = list(endpoints.keys())
    random.shuffle(nombres)
    mitad = len(nombres) // 2
    clientes = nombres[:mitad]
    servidores = nombres[mitad:]

    perfiles = [
        ("Netflix_4K",     f"-t {duration} -b 25M"),
        ("Descarga_P2P",   f"-t {duration} -b 80M -P 2"),
        ("Navegacion_Web", "-t 10 -b 5M"),
        ("IoT_Sensor",     f"-t {duration} -b 500K"),
    ]

    server_cmds = [f"{srv} iperf -s &" for srv in servidores]
    client_cmds = []
    reporte_perfiles = []

    for i, cliente in enumerate(clientes):
        servidor = servidores[i % len(servidores)]
        ip_servidor = endpoints[servidor]
        perfil_nombre, perfil_args = random.choice(perfiles)
        client_cmds.append(f"{cliente} iperf -c {ip_servidor} {perfil_args} &")
        reporte_perfiles.append(
            f" -> {cliente} → {servidor} ({ip_servidor}) | Perfil: {perfil_nombre}"
        )

    with open(os.path.join(TMP_DIR, "ultima_rafaga_realista.txt"), "w") as f:
        f.write("\n".join(reporte_perfiles))

    return server_cmds, client_cmds


def run_bulk_traffic_logic(server_cmds, client_cmds):
    """Arranca servidores iperf, luego lanza clientes con perfil realista."""
    print("\n[SIMULADOR] Inyectando comportamientos de red realistas...")

    if os.path.exists(os.path.join(TMP_DIR, "ultima_rafaga_realista.txt")):
        with open(os.path.join(TMP_DIR, "ultima_rafaga_realista.txt"), "r") as f:
            print(f.read())

    try:
        ssh = get_ssh_connection()

        # Matar iperfs residuales de ciclos anteriores
        send_tmux_command(ssh, "sh pkill -f iperf; true")
        time.sleep(0.5)

        # Arrancar servidores y esperar a que estén escuchando
        for cmd in server_cmds:
            send_tmux_command(ssh, cmd)
            time.sleep(0.1)
        time.sleep(1)

        # Arrancar clientes
        for cmd in client_cmds:
            send_tmux_command(ssh, cmd)
            time.sleep(0.1)

        ssh.close()

        tiempo_espera = 25
        print(
            f"\n[SIMULADOR] Esperando {tiempo_espera} segundos a que los usuarios terminen sus tareas..."
        )
        time.sleep(tiempo_espera)

    except Exception as e:
        print(f"[ERROR] Fallo al ejecutar el tráfico: {e}")


if __name__ == "__main__":
    endpoints = get_active_endpoints()
    print(f"[INFO] Endpoints detectados: {endpoints}")
    server_cmds, client_cmds = generate_bulk_traffic(endpoints)
    run_bulk_traffic_logic(server_cmds, client_cmds)
