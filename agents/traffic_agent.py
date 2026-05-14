import sys
import os
import re
import time
import random
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import config
from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)

TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)

# Puerto reservado para tráfico intra-subnet (evita conflicto con bulk en 5001)
_INTRA_PORT = 5555


def _group_by_subnet(endpoints):
    """Agrupa endpoints por prefijo /24 de su IP."""
    groups = defaultdict(list)
    for name, ip in endpoints.items():
        if ip:
            subnet = ".".join(ip.split(".")[:3])
            groups[subnet].append((name, ip))
    return dict(groups)


def launch_background_traffic(endpoints):
    """
    Lanza tráfico continuo en background con tres componentes:
      1. Wget ON-OFF inter-subnet con asignación de servidor por subred.
      2. Iperf intra-subnet periódico (no cruza el router).
    Cada cliente arranca con un delay aleatorio para evitar sincronización.
    """
    servers = {n: ip for n, ip in endpoints.items() if n.startswith("srv")}
    hosts   = {n: ip for n, ip in endpoints.items() if n.startswith("h")}

    if not hosts:
        print("[TRAFFIC] No se detectaron hosts. No se lanza tráfico.")
        return

    print("\n[TRAFFIC] Iniciando tráfico continuo en background...")
    print(f"  Servidores web (srv*): {list(servers.keys()) or 'ninguno'}")
    print(f"  Clientes/hosts  (h*):  {list(hosts.keys()) or 'ninguno'}")

    # Agrupar por subred para asignación inteligente de servidores
    subnet_groups = _group_by_subnet({**hosts, **servers})
    subnet_to_srvs = defaultdict(list)
    for subnet, members in subnet_groups.items():
        for name, ip in members:
            if name.startswith("srv"):
                subnet_to_srvs[subnet].append(ip)
    all_srv_ips = list(servers.values())

    try:
        ssh = get_ssh_connection()

        # Limpiar residuos de sesiones anteriores
        send_tmux_command(ssh, "sh pkill -f iperf; true")
        time.sleep(0.2)
        send_tmux_command(ssh, "sh pkill -f wget; true")
        time.sleep(0.2)
        send_tmux_command(ssh, "sh pkill -f http.server; true")
        time.sleep(0.5)

        # ── 1. Servidores HTTP en cada srv* ────────────────────────────────────
        if servers:
            for srv_name in servers:
                send_tmux_command(ssh, f"{srv_name} python3 -m http.server 8080 >/dev/null 2>&1 &")
                time.sleep(0.1)
            time.sleep(0.5)

        # ── 2. Bucles wget ON-OFF por host ─────────────────────────────────────
        if servers:
            intra_count = 0
            for i, (host_name, host_ip) in enumerate(hosts.items()):
                host_subnet = ".".join(host_ip.split(".")[:3])
                # Preferir servidor de la misma subred (tráfico local)
                local_srvs = subnet_to_srvs.get(host_subnet, [])
                target_pool = local_srvs if local_srvs else all_srv_ips
                target_ip = random.choice(target_pool)
                if target_ip in local_srvs:
                    intra_count += 1

                # Arranque escalonado + sleep variable (modelo ON-OFF realista)
                initial_delay = random.randint(0, 10)
                cmd = (
                    f'{host_name} bash -c '
                    f'"sleep {initial_delay}; '
                    f'while true; do '
                    f'wget -q -O /dev/null http://{target_ip}:8080/ 2>/dev/null; '
                    f'sleep $((RANDOM % 18 + 3)); '
                    f'done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.05)

            print(f"[TRAFFIC] Base: {len(hosts)} cliente(s) ON-OFF → {len(servers)} servidor(es) HTTP")
            print(f"[TRAFFIC] De ellos, {intra_count} usan servidor en su misma subred (tráfico local)")

        # ── 3. Servidores iperf persistentes en srv* (puerto 5002) ────────────
        #    Bucle de auto-reinicio: cuando un cliente desconecta, el servidor
        #    vuelve a escuchar de inmediato → cola natural de conexiones.
        session_srvs = {}   # srv_name → ip
        for srv_name, srv_ip in servers.items():
            cmd = (
                f'{srv_name} bash -c '
                f'"while true; do iperf -s -p 5002 >/dev/null 2>&1; '
                f'sleep 0.1; done" &'
            )
            send_tmux_command(ssh, cmd)
            time.sleep(0.08)
            session_srvs[srv_name] = srv_ip

        # ── 4. Session workers en h* (flujos asíncronos, Poisson-like) ────────
        #    Cada host decide de forma independiente cuándo iniciar una
        #    transferencia y con qué perfil → sin picos sincronizados.
        session_perfiles = [
            ("HeavyDL",  f"-b $((RANDOM % 40 + 10))M -t $((RANDOM % 25 + 10))"),  # 10-50 Mbps
            ("MediumFT", f"-b $((RANDOM % 15 +  3))M -t $((RANDOM % 20 +  8))"),  # 3-18 Mbps
            ("LightWeb",  "-b $((RANDOM %  5 +  1))M -t $((RANDOM % 10 +  4))"),  #  1-6 Mbps
            ("VoIP",      "-b $((RANDOM %  1 +  1))M -t $((RANDOM % 30 + 15))"),  # ~1 Mbps
        ]
        srv_ips_list = list(servers.values())
        if not srv_ips_list:
            srv_ips_list = all_srv_ips

        session_count = 0
        for i, (host_name, host_ip) in enumerate(hosts.items()):
            # Peso del perfil: hosts con índice bajo tienden a ser "heavy users"
            if i < len(hosts) // 3:
                perfil_args = session_perfiles[0][1]   # HeavyDL
                inter_sleep = "$((RANDOM % 40 + 20))"  # 20-60 s entre sesiones
            elif i < 2 * len(hosts) // 3:
                perfil_args = session_perfiles[1][1]   # MediumFT
                inter_sleep = "$((RANDOM % 60 + 30))"  # 30-90 s
            else:
                perfil_args = random.choice(session_perfiles[2:])[1]  # Light / VoIP
                inter_sleep = "$((RANDOM % 80 + 40))"  # 40-120 s

            # Selección aleatoria del servidor destino
            target_ip = random.choice(srv_ips_list)
            # Delay inicial escalonado: evita que todos empiecen a la vez
            initial_delay = random.randint(i * 2, i * 2 + 15)

            cmd = (
                f'{host_name} bash -c '
                f'"sleep {initial_delay}; '
                f'while true; do '
                f'iperf -c {target_ip} -p 5002 {perfil_args} >/dev/null 2>&1; '
                f'sleep {inter_sleep}; '
                f'done" &'
            )
            send_tmux_command(ssh, cmd)
            time.sleep(0.05)
            session_count += 1

        # ── 5. Iperf intra-subnet (host↔host en el mismo switch) ──────────────
        intra_pairs = 0
        for subnet, members in subnet_groups.items():
            same_sw_hosts = [(n, ip) for n, ip in members if n.startswith("h")]
            if len(same_sw_hosts) < 2:
                continue
            for j in range(min(2, len(same_sw_hosts) - 1)):
                src_name = same_sw_hosts[j][0]
                dst_ip   = same_sw_hosts[j + 1][1]
                delay    = random.randint(8, 25)
                cmd = (
                    f'{src_name} bash -c '
                    f'"sleep {delay}; '
                    f'while true; do '
                    f'iperf -s -p {_INTRA_PORT} >/dev/null 2>&1 & SPID=$!; '
                    f'sleep 1; '
                    f'iperf -c {dst_ip} -p {_INTRA_PORT} -t 5 '
                    f'-b $((RANDOM % 15 + 1))M >/dev/null 2>&1; '
                    f'kill $SPID 2>/dev/null; '
                    f'sleep $((RANDOM % 30 + 15)); '
                    f'done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.05)
                intra_pairs += 1

        if session_count:
            print(f"[TRAFFIC] Session workers: {session_count} host(s) con flujos iperf asíncronos (p. 5002)")
        if intra_pairs:
            print(f"[TRAFFIC] Intra-subnet: {intra_pairs} par(es) iperf local (no cruzan router)")

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

        matches = re.findall(r"\('([^']+)',\s*'([^']*)'\)", raw_output.replace('\n', ''))
        endpoints = {name.strip(): ip.strip() for name, ip in matches if ip.strip()}
        return endpoints
    except Exception as e:
        print(f"[ERROR] No se pudieron obtener los endpoints: {e}")
        return {}


def generate_bulk_traffic(endpoints, duration=config.DURACION_BULK):
    """
    Genera comandos iperf con arranques escalonados y mezcla realista de perfiles:
      - Elephant flows (grandes): Netflix 4K, P2P, backup
      - Medium flows: compartir ficheros, actualización, vídeo HD
      - Mouse flows:  navegación, IoT, VoIP
    Solo usa endpoints h* y srv* (excluye routers r*).
    """
    # Excluir routers y nodos sin IP
    valid = {n: ip for n, ip in endpoints.items()
             if (n.startswith("h") or n.startswith("srv")) and ip}

    if len(valid) < 2:
        return [], []

    nombres = list(valid.keys())
    random.shuffle(nombres)
    mitad    = max(1, len(nombres) // 2)
    clientes = nombres[:mitad]
    servidores = nombres[mitad:]

    # 3 niveles: elephant (alta BW, larga duración) / medium / mouse
    perfiles = [
        # Elephant
        ("Netflix_4K",      f"-t {duration} -b 25M"),
        ("Descarga_P2P",    f"-t {duration} -b 80M -P 2"),
        ("Backup_Servidor", f"-t {duration} -b 50M"),
        # Medium
        ("Compartir_Fich",  "-t 20 -b 15M"),
        ("Actualizacion",   "-t 15 -b 12M"),
        ("Video_720p",      f"-t {duration} -b 8M"),
        # Mouse
        ("Navegacion_Web",  "-t 8 -b 3M"),
        ("IoT_Sensor",      f"-t {duration} -b 500K"),
        ("VoIP",            f"-t {duration} -b 200K"),
    ]

    server_cmds = [f"{srv} iperf -s &" for srv in servidores]
    client_cmds = []
    reporte_perfiles = []

    for i, cliente in enumerate(clientes):
        servidor = servidores[i % len(servidores)]
        ip_servidor = valid[servidor]
        perfil_nombre, perfil_args = random.choice(perfiles)

        # Arranque escalonado: cada cliente espera un tiempo aleatorio distinto
        delay = random.randint(0, 15)
        client_cmds.append(
            f"{cliente} bash -c 'sleep {delay}; iperf -c {ip_servidor} {perfil_args}' &"
        )
        reporte_perfiles.append(
            f" -> {cliente} → {servidor} ({ip_servidor}) | {perfil_nombre} | +{delay}s"
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

        for cmd in server_cmds:
            send_tmux_command(ssh, cmd)
            time.sleep(0.1)
        time.sleep(1)

        for cmd in client_cmds:
            send_tmux_command(ssh, cmd)
            time.sleep(0.1)

        ssh.close()

        tiempo_espera = config.ESPERA_POST_BULK
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
