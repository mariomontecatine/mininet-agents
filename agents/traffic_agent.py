import sys
import os
import re
import time
import random

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.ssh_client import get_ssh_connection, send_tmux_command, capture_tmux_output

TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)


def get_active_hosts():
    try:
        ssh = get_ssh_connection()
        output = capture_tmux_output(ssh)
        ssh.close()

        # Buscar todo lo que empiece por h y un número (ej: h1, h14)
        active_hosts = re.findall(r"\bh\d+\b", output)
        hosts_unicos = sorted(list(set(active_hosts)))
        return hosts_unicos
    except Exception as e:
        print(f"[ERROR] No se pudieron obtener los hosts: {e}")
        return []


def generate_bulk_traffic(hosts, duration=35):
    """Genera comandos iperf simulando perfiles de usuarios reales."""
    comandos = []
    if len(hosts) < 2:
        return comandos

    # Barajamos los hosts y los dividimos en clientes y servidores
    random.shuffle(hosts)
    mitad = len(hosts) // 2
    clientes = hosts[:mitad]
    servidores = hosts[mitad:]

    # PERFILES DE TRÁFICO REALISTA
    perfiles = [
        ("Netflix_4K", f"-t {duration} -b 25M"),  # Streaming constante a 25 Mbps
        (
            "Descarga_P2P",
            f"-t {duration} -b 80M -P 2",
        ),  # Descarga agresiva a 80 Mbps con 2 hilos
        ("Navegacion_Web", "-t 10 -b 5M"),  # Ráfaga corta de 5 Mbps
        ("IoT_Sensor", f"-t {duration} -b 500K"),  # Ruido de fondo muy bajo (0.5 Mbps)
    ]

    reporte_perfiles = []

    for i, cliente in enumerate(clientes):
        # Asignamos un servidor
        servidor = servidores[i % len(servidores)]

        # En Mininet (topo=tree), la IP por defecto de hX es 10.0.0.X
        num_servidor = servidor.replace("h", "")
        ip_servidor = f"10.0.0.{num_servidor}"

        # Elegimos un comportamiento al azar para este usuario
        perfil_nombre, perfil_args = random.choice(perfiles)

        # Montamos el comando (ej: h1 iperf -c 10.0.0.2 -t 35 -b 25M &)
        cmd_string = f"{cliente} iperf -c {ip_servidor} {perfil_args} &"
        comandos.append(cmd_string)

        reporte_perfiles.append(
            f" -> {cliente} se conecta a {servidor} | Perfil: {perfil_nombre}"
        )

    # Guardamos el mapeo en un txt para que el supervisor lo pueda imprimir bonito
    with open(os.path.join(TMP_DIR, "ultima_rafaga_realista.txt"), "w") as f:
        f.write("\n".join(reporte_perfiles))

    return comandos


def run_bulk_traffic_logic(comandos):
    """Ejecuta los comandos en la VM de forma silenciosa."""
    print("\n[SIMULADOR] Inyectando comportamientos de red realistas...")

    # Imprimimos quién está haciendo qué
    if os.path.exists(os.path.join(TMP_DIR, "ultima_rafaga_realista.txt")):
        with open(os.path.join(TMP_DIR, "ultima_rafaga_realista.txt"), "r") as f:
            print(f.read())

    try:
        ssh = get_ssh_connection()
        for cmd in comandos:
            send_tmux_command(ssh, cmd)
            time.sleep(0.1)  # Pequeña pausa para no saturar Tmux

        ssh.close()

        # Esperamos a que los flujos terminen (margen sobre el perfil más largo: 25 s)
        tiempo_espera = 25
        print(
            f"\n[SIMULADOR] Esperando {tiempo_espera} segundos a que los usuarios terminen sus tareas..."
        )
        time.sleep(tiempo_espera)

    except Exception as e:
        print(f"[ERROR] Fallo al ejecutar el tráfico: {e}")


if __name__ == "__main__":
    hosts = get_active_hosts()
    cmds = generate_bulk_traffic(hosts)
    run_bulk_traffic_logic(cmds)
