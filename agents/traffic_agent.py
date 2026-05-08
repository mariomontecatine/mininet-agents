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


def launch_background_traffic(endpoints):
    """
    Lanza tráfico continuo en background en Mininet.
    Clasifica endpoints por prefijo: srv* → servidores HTTP, h* → clientes.
    Devuelve control inmediatamente tras enviar los comandos a tmux.
    """
    servers = {n: ip for n, ip in endpoints.items() if n.startswith("srv")}
    hosts = {n: ip for n, ip in endpoints.items() if n.startswith("h")}

    if not hosts and not servers:
        print("[TRAFFIC] No se detectaron hosts (h* o srv*). No se lanza tráfico.")
        return

    print("\n[TRAFFIC] Iniciando tráfico continuo en background...")
    print(f"  Servidores web (srv*): {list(servers.keys()) or 'ninguno'}")
    print(f"  Clientes/hosts  (h*):  {list(hosts.keys()) or 'ninguno'}")

    try:
        ssh = get_ssh_connection()

        # Limpiar residuos de sesiones anteriores.
        # Tres send_tmux_command separados para evitar conflictos de quoting en el wrapper.
        send_tmux_command(ssh, "sh pkill -f iperf; true")
        time.sleep(0.2)
        send_tmux_command(ssh, "sh pkill -f wget; true")
        time.sleep(0.2)
        send_tmux_command(ssh, "sh pkill -f http.server; true")
        time.sleep(0.5)

        # --- Tráfico Base: bucle wget de h* hacia srv* ---
        if servers and hosts:
            srv_ips = list(servers.values())

            for srv_name in servers:
                # Servidor HTTP ligero en cada nodo srv*
                send_tmux_command(ssh, f"{srv_name} python3 -m http.server 8080 >/dev/null 2>&1 &")
                time.sleep(0.1)
            time.sleep(0.5)

            host_names = list(hosts.keys())
            for i, host_name in enumerate(host_names):
                target_ip = srv_ips[i % len(srv_ips)]
                # Dobles comillas internas: safe con el wrapper de single quotes de send_tmux_command
                cmd = (
                    f'{host_name} bash -c '
                    f'"while true; do wget -q -O /dev/null http://{target_ip}:8080/ 2>/dev/null; sleep 2; done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.05)

            print(f"[TRAFFIC] Base: {len(hosts)} cliente(s) en bucle wget → {len(servers)} servidor(es) HTTP")

        # --- Tráfico Anómalo: iperf UDP pesado entre h* para provocar cuello de botella ---
        host_list = list(hosts.keys())
        if len(host_list) >= 2:
            victim_name = host_list[-1]
            victim_ip = hosts[victim_name]
            attackers = host_list[:min(2, len(host_list) - 1)]

            send_tmux_command(ssh, f"{victim_name} iperf -s -u >/dev/null 2>&1 &")
            time.sleep(0.3)

            for attacker in attackers:
                cmd = f"{attacker} iperf -c {victim_ip} -u -b 100M -t 3600 >/dev/null 2>&1 &"
                send_tmux_command(ssh, cmd)
                time.sleep(0.05)

            print(f"[TRAFFIC] Anómalo: {len(attackers)} atacante(s) UDP → {victim_name} ({victim_ip}) @ 100Mbps")

        ssh.close()
        print("[TRAFFIC] Control devuelto al supervisor. El tráfico corre en background.")

    except Exception as e:
        print(f"[ERROR] Fallo al lanzar tráfico en background: {e}")


def stop_background_traffic():
    """Mata todos los procesos de tráfico lanzados por launch_background_traffic."""
    print("\n[TRAFFIC] Deteniendo procesos de tráfico en background...")
    try:
        ssh = get_ssh_connection()
        send_tmux_command(ssh, "sh pkill -f iperf; true")
        time.sleep(0.2)
        send_tmux_command(ssh, "sh pkill -f wget; true")
        time.sleep(0.2)
        send_tmux_command(ssh, "sh pkill -f http.server; true")
        time.sleep(0.3)
        ssh.close()
        print("[TRAFFIC] Procesos de background terminados.")
    except Exception as e:
        print(f"[ERROR] Fallo al detener el tráfico: {e}")


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
