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
SERVER_SERVICES_FILE = os.path.join(TMP_DIR, "server_services.json")


def _group_by_subnet(endpoints):
    """Agrupa endpoints por prefijo /24 de su IP."""
    groups = defaultdict(list)
    for name, ip in endpoints.items():
        if ip:
            subnet = ".".join(ip.split(".")[:3])
            groups[subnet].append((name, ip))
    return dict(groups)


def _load_server_services():
    """Lee tmp/server_services.json (mapping srv→tipo) si existe.

    Sin este fichero (despliegues legacy / topologías estándar sin srv*) se
    asume que cualquier srv* es HTTP — mantiene el comportamiento previo.
    """
    import json as _json
    if not os.path.exists(SERVER_SERVICES_FILE):
        return {}
    try:
        with open(SERVER_SERVICES_FILE, encoding="utf-8") as f:
            return _json.load(f)
    except (_json.JSONDecodeError, IOError):
        return {}


def _partition_servers_by_type(servers, service_map):
    """Devuelve {tipo: {srv_name: ip}}. Sin mapping, todos van a 'http'."""
    out = {"http": {}, "dns": {}, "ssh": {}, "sip": {}}
    for name, ip in servers.items():
        info  = service_map.get(name)
        stype = (info or {}).get("type", "http")
        if stype not in out:
            stype = "http"
        out[stype][name] = ip
    return out


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

    # Partición de servidores por tipo (http/dns/ssh/sip).
    service_map = _load_server_services()
    by_type     = _partition_servers_by_type(servers, service_map)
    http_srvs   = by_type["http"]
    dns_srvs    = by_type["dns"]
    ssh_srvs    = by_type["ssh"]
    sip_srvs    = by_type["sip"]

    print("\n[TRAFFIC] Iniciando tráfico continuo en background...")
    print(f"  Servidores (srv*): {list(servers.keys()) or 'ninguno'}")
    if service_map:
        print(f"  HTTP : {list(http_srvs)} · DNS : {list(dns_srvs)} · "
              f"SSH : {list(ssh_srvs)} · SIP : {list(sip_srvs)}")
    else:
        print("  (sin server_services.json — todos tratados como HTTP)")
    print(f"  Clientes/hosts  (h*): {list(hosts.keys()) or 'ninguno'}")

    # Agrupar por subred para asignación inteligente de servidores HTTP
    subnet_groups = _group_by_subnet({**hosts, **servers})
    subnet_to_http_srvs = defaultdict(list)
    for subnet, members in subnet_groups.items():
        for name, ip in members:
            if name in http_srvs:
                subnet_to_http_srvs[subnet].append(ip)
    all_http_ips = list(http_srvs.values())

    try:
        ssh = get_ssh_connection()

        # Limpiar residuos de sesiones anteriores. Cubrimos:
        #  - herramientas históricas (iperf/wget/http.server)
        #  - probes de aplicación (ping -c, dig @)
        #  - marcadores : <nombre>_loop de los bucles bash actuales
        #  - hping3 (fondo + ataques)
        for pat in (
            "iperf", "wget", "http.server", "hping3",
            "'ping -c'", "'dig @'",
            "sshprobe_loop", "sipprobe_loop", "icmpprobe_loop",
            "bg_http_loop", "bg_dns_loop", "bg_ssh_loop", "bg_sip_loop",
        ):
            send_tmux_command(ssh, f"sh pkill -f {pat}; true")
            time.sleep(0.15)
        time.sleep(0.5)

        # ── 1. Bucles wget ON-OFF por host hacia los HTTP REALES (puerto 80) ──
        # Sin auxiliar en 8080 ya: el `serve_http` del launcher (deploy_agent)
        # crea /tmp/web/page.bin y sirve en :80. Así el tráfico HTTP se
        # clasifica como "http" puro en el panel, no como http_alt artificial.
        if http_srvs:
            intra_count = 0
            for i, (host_name, host_ip) in enumerate(hosts.items()):
                host_subnet = ".".join(host_ip.split(".")[:3])
                local_srvs = subnet_to_http_srvs.get(host_subnet, [])
                target_pool = local_srvs if local_srvs else all_http_ips
                target_ip = random.choice(target_pool)
                if target_ip in local_srvs:
                    intra_count += 1

                initial_delay = random.randint(0, 10)
                cmd = (
                    f'{host_name} bash -c '
                    f'"sleep {initial_delay}; '
                    f'while true; do '
                    f'wget -q -O /dev/null http://{target_ip}:80/page.bin 2>/dev/null; '
                    f'sleep $((RANDOM % 10 + 6)); '
                    f'done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.3)

            print(f"[TRAFFIC] HTTP: {len(hosts)} cliente(s) ON-OFF → {len(http_srvs)} servidor(es) (puerto 80)")
            print(f"[TRAFFIC] De ellos, {intra_count} usan servidor en su misma subred (tráfico local)")
        else:
            print("[TRAFFIC] HTTP: no hay servidores HTTP — se omiten los wget loops")

        # NOTA: el bulk iperf TCP/5002 + iperf intra-subnet se ELIMINÓ a partir
        # de esta versión. Generaba un "ruido" alto e indistinguible de un DoS
        # volumétrico (10-50 Mbps por host), que disparaba constantemente las
        # heurísticas SURGE/FAN_IN. Ahora el fondo es:
        #   - Probes de aplicación (wget, dig, /dev/tcp, /dev/udp) — bytes reales
        #     pero volumen muy bajo, sin choque con los umbrales de ataque.
        #   - Streams hping3 a baja tasa hacia los puertos reales de cada
        #     servicio — aportan "trickle" visible por protocolo en el panel.
        #   - ICMP host↔host con ráfagas más largas y frecuencia mayor.

        # ── 3. ICMP host↔host — ráfagas moderadas ─────────────────────────────
        # ping con -s 256 → 256B + 28B cabecera ≈ 284B por paquete. 10 paquetes
        # a 0.2 s = 2 s de ráfaga → ~1.5 KB/s por host activo.
        #
        # ANTES usábamos `peers=(...); target=${peers[$((RANDOM % ${#peers[@]}))]}`
        # pero el outer-bash de Mininet expandía esas variables ANTES de pasar al
        # inner-bash (donde peers se define), causando división por cero y abortando
        # el comando completo. Ahora Python elige UN target fijo por host. Pérdida
        # menor: cada host pingará siempre al mismo peer (no rota) pero el loop SÍ
        # sobrevive y genera tráfico ICMP visible.
        icmp_count = 0
        host_items = list(hosts.items())
        if len(host_items) >= 2:
            for i, (host_name, _) in enumerate(host_items):
                peers = [ip for n, ip in host_items if n != host_name]
                if not peers:
                    continue
                target_ip = random.choice(peers)
                delay  = random.randint(2, 18)
                cmd = (
                    f'{host_name} bash -c '
                    f'": icmpprobe_loop; sleep {delay}; '
                    f'while true; do '
                    f'ping -c 10 -i 0.2 -s 256 -W 1 -q {target_ip} >/dev/null 2>&1; '
                    f'sleep $((RANDOM % 12 + 8)); '
                    f'done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.3)
                icmp_count += 1

        # ── 7. Tráfico DNS sintético — queries UDP/53 hacia servidores DNS ────
        #    Prefiere servidores tipados como 'dns'. Si no hay → fallback a
        #    cualquier srv (compat con despliegues legacy sin server_services).
        dns_count = 0
        dns_port  = config.SERVICE_PORTS.get("dns", 53)
        dns_targets = list(dns_srvs.values()) or list(servers.values())
        if dns_targets:
            queryers = list(hosts.keys())[:max(1, len(hosts) // 2)]
            for host_name in queryers:
                target_ip = random.choice(dns_targets)
                delay = random.randint(10, 40)
                cmd = (
                    f'{host_name} bash -c '
                    f'"sleep {delay}; '
                    f'while true; do '
                    f'dig @{target_ip} -p {dns_port} example.com +tries=1 +timeout=1 +short '
                    f'>/dev/null 2>&1; '
                    f'sleep $((RANDOM % 45 + 15)); '
                    f'done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.3)
                dns_count += 1

        # ── 8. Tráfico SSH sintético — banner-grab TCP/22 vía /dev/tcp ────────
        #    Cada probe abre conexión TCP, lee 64B de banner y cierra. Bajo
        #    volumen, pero introduce TCP/22 en las muestras sFlow.
        ssh_count = 0
        ssh_port  = config.SERVICE_PORTS.get("ssh", 22)
        if ssh_srvs and hosts:
            ssh_targets = list(ssh_srvs.values())
            probers = list(hosts.keys())[:max(1, len(hosts) // 2)]
            for host_name in probers:
                target_ip = random.choice(ssh_targets)
                delay = random.randint(8, 35)
                cmd = (
                    f'{host_name} bash -c '
                    f'": sshprobe_loop; sleep {delay}; '
                    f'while true; do '
                    f'timeout 2 bash -c '
                    f'\\"exec 3<>/dev/tcp/{target_ip}/{ssh_port}; '
                    f'head -c 64 <&3 >/dev/null 2>&1; exec 3<&-\\" >/dev/null 2>&1; '
                    f'sleep $((RANDOM % 50 + 20)); '
                    f'done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.3)
                ssh_count += 1

        # ── 9. Tráfico SIP sintético — OPTIONS UDP/5060 vía /dev/udp ──────────
        # send_tmux_command envuelve el comando en COMILLAS SIMPLES para tmux,
        # así que dentro del bash -c (con comillas dobles) sólo podemos usar
        # comillas dobles ESCAPADAS (\"...\") para argumentos internos. Las
        # secuencias \r\n las interpreta `echo -e` en el destino.
        sip_count = 0
        sip_port  = config.SERVICE_PORTS.get("sip", 5060)
        if sip_srvs and hosts:
            sip_targets = list(sip_srvs.values())
            probers = list(hosts.keys())[:max(1, len(hosts) // 2)]
            for host_name in probers:
                target_ip = random.choice(sip_targets)
                delay = random.randint(10, 40)
                # \\\\r\\\\n en la f-string → literal \\r\\n en bash → echo -e
                # los convierte en CR LF al ejecutarse.
                sip_payload = (
                    f"OPTIONS sip:probe SIP/2.0\\r\\n"
                    f"Via: SIP/2.0/UDP probe\\r\\n"
                    f"From: <sip:probe@local>\\r\\n"
                    f"To: <sip:probe@{target_ip}>\\r\\n"
                    f"Call-ID: probe@local\\r\\n"
                    f"CSeq: 1 OPTIONS\\r\\n"
                    f"Content-Length: 0\\r\\n\\r\\n"
                )
                cmd = (
                    f'{host_name} bash -c '
                    f'": sipprobe_loop; sleep {delay}; '
                    f'while true; do '
                    f'echo -ne \\"{sip_payload}\\" '
                    f'> /dev/udp/{target_ip}/{sip_port} 2>/dev/null; '
                    f'sleep $((RANDOM % 50 + 25)); '
                    f'done" &'
                )
                send_tmux_command(ssh, cmd)
                time.sleep(0.3)
                sip_count += 1

        # ── 10. hping3 low-rate por protocolo — trickle visible en el panel ───
        # Comprobamos primero si hping3 está disponible; si no, omitimos el
        # bloque sin error (la aplicación-layer ya funciona sola).
        try:
            _, stdout_chk, _ = ssh.exec_command("which hping3", timeout=5)
            hping3_ok = bool(stdout_chk.read().decode("utf-8", errors="replace").strip())
        except Exception:
            hping3_ok = False

        bg_counts = {"http": 0, "dns": 0, "ssh": 0, "sip": 0}
        if hping3_ok:
            # (label, target_dict, transport_flag, dport, transport)
            bg_targets = [
                ("http", http_srvs, "-S",    config.SERVICE_PORTS.get("http", 80),  "tcp"),
                ("dns",  dns_srvs,  "--udp", config.SERVICE_PORTS.get("dns", 53),   "udp"),
                ("ssh",  ssh_srvs,  "-S",    config.SERVICE_PORTS.get("ssh", 22),   "tcp"),
                ("sip",  sip_srvs,  "--udp", config.SERVICE_PORTS.get("sip", 5060), "udp"),
            ]
            host_list = list(hosts.keys())
            for label, dst_pool, flag, dport, transport in bg_targets:
                if not dst_pool or not host_list:
                    continue
                # 3 hosts hacen trickle hacia cada servicio. Ráfagas de 10 s
                # y pausa de 15-30 s → ciclo de actividad para que el panel
                # vea picos legítimos sin tasa plana.
                generators = host_list[:3]
                dst_ips = list(dst_pool.values())
                for h in generators:
                    target = random.choice(dst_ips)
                    delay  = random.randint(2, 15)
                    # -i u10000 = 100 pps · 600B = 60 KB/s ≈ 480 Kbps por host.
                    # -c 1000 → ráfaga de 10 s. -k -s = sport fijo → en sFlow
                    # aparece como UN solo flujo (sin esto, miles de flujos).
                    # Un ataque va a 80 Mbps → ratio 160×, sigue siendo señal clara.
                    cmd = (
                        f'{h} bash -c '
                        f'": bg_{label}_loop; sleep {delay}; '
                        f'while true; do '
                        f'hping3 {flag} -p {dport} -k -s 23456 '
                        f'-i u10000 -d 600 -c 1000 '
                        f'{target} >/dev/null 2>&1; '
                        f'sleep $((RANDOM % 16 + 15)); '
                        f'done" &'
                    )
                    send_tmux_command(ssh, cmd)
                    time.sleep(0.3)
                    bg_counts[label] += 1
        else:
            print("[TRAFFIC][WARN] hping3 no instalado → se omiten los streams de "
                  "fondo por protocolo. Para más realismo: sudo apt install hping3")

        if icmp_count:
            print(f"[TRAFFIC] ICMP: {icmp_count} host(s) con ráfagas largas host↔host")
        if dns_count:
            print(f"[TRAFFIC] DNS: {dns_count} host(s) con queries sintéticas UDP/{dns_port}")
        if ssh_count:
            print(f"[TRAFFIC] SSH: {ssh_count} host(s) con banner-grab TCP/{ssh_port}")
        if sip_count:
            print(f"[TRAFFIC] SIP: {sip_count} host(s) con OPTIONS UDP/{sip_port}")
        if any(bg_counts.values()):
            print(f"[TRAFFIC] hping3 background: {bg_counts}")

        ssh.close()
        print("[TRAFFIC] Control devuelto al supervisor. El tráfico corre en background.")

    except Exception as e:
        print(f"[ERROR] Fallo al lanzar tráfico en background: {e}")


def stop_background_traffic():
    """Mata todos los procesos de tráfico lanzados por launch_background_traffic."""
    print("\n[TRAFFIC] Deteniendo procesos de tráfico en background...")
    try:
        ssh = get_ssh_connection()
        for pat in (
            "iperf", "wget", "http.server", "hping3",
            "'ping -c'", "'dig @'",
            "sshprobe_loop", "sipprobe_loop", "icmpprobe_loop",
            "bg_http_loop", "bg_dns_loop", "bg_ssh_loop", "bg_sip_loop",
        ):
            send_tmux_command(ssh, f"sh pkill -f {pat}; true")
            time.sleep(0.15)
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
