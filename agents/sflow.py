"""
Agente sFlow: visibilidad de flujos extremo a extremo en el NOC.

Levanta un colector sFlow v5 (Python puro, sin sflowtool) como demonio en la VM,
configura sFlow en todos los bridges OVS y expone los flujos top-N por par
(src_ip, dst_ip) a través de /tmp/sflow_flows.json en la VM.

El supervisor lee ese fichero periódicamente vía SSH y lo replica en
tmp/flows.json local para que Flask lo sirva en /api/flows.
"""

import json
import time

# ── Daemon sFlow embebido (se sube a la VM via SFTP) ─────────────────────────
# Mantiene una ventana deslizante de WINDOW_SEC segundos y vuelca los top-N
# pares (src,dst) ordenados por bytes a /tmp/sflow_flows.json cada FLUSH_SEC.
_SFLOW_DAEMON = '''\
#!/usr/bin/env python3
"""sFlow v5 UDP collector daemon — sin dependencias externas.

Escribe top-N flujos por (src_ip, dst_ip) en /tmp/sflow_flows.json
de forma atómica cada FLUSH_SEC segundos, sobre una ventana
deslizante de WINDOW_SEC segundos.
"""
import socket, struct, json, time, os, signal, sys
from collections import deque, defaultdict

WINDOW_SEC = 20
FLUSH_SEC  = 5
TOP_N      = 300   # margen para topologías grandes (14 hosts × 4 servicios +
                   # responses + ICMP + ataques). Con menos, los flujos
                   # pequeños del port_scan caen fuera del top-N.
OUTPUT     = "/tmp/sflow_flows.json"

def parse_sflow_v5(data):
    """Devuelve [(src_ip, dst_ip, ip_proto, svc_port, bytes_scaled), ...].

    `svc_port` es el "puerto de servicio" del flujo: el menor de (sport, dport)
    cuando ambos son no-cero. Esto agrega bidireccionalmente request+response
    (h1:43210→srv:80 y srv:80→h1:43210 quedan ambos con svc_port=80) y evita
    que hping3, que randomiza el sport por paquete, fragmente un ataque en
    miles de flujos distintos en sFlow.

    ip_proto sigue los números IANA (1=ICMP, 6=TCP, 17=UDP). Cuando el
    protocolo no es TCP/UDP, svc_port=0.
    """
    results = []
    if len(data) < 28:
        return results
    try:
        pos = 0
        def read4():
            nonlocal pos
            v = struct.unpack_from(">I", data, pos)[0]
            pos += 4
            return v

        if read4() != 5:
            return results
        addr_type = read4()
        if addr_type == 1:
            pos += 4
        elif addr_type == 2:
            pos += 16
        else:
            return results
        read4(); read4(); read4()
        num_samples = read4()

        for _ in range(num_samples):
            if pos + 8 > len(data):
                break
            sample_type = read4()
            sample_len  = read4()
            sample_end  = pos + sample_len

            if sample_type == 1 and pos + 32 <= sample_end:
                read4(); read4()
                sampling_rate = max(1, read4())
                read4(); read4()
                read4(); read4()
                num_records = read4()

                for _ in range(num_records):
                    if pos + 8 > sample_end:
                        break
                    rec_type = read4()
                    rec_len  = read4()
                    rec_end  = pos + rec_len

                    if rec_type == 1 and rec_len >= 16:
                        hdr_proto  = read4()
                        frame_len  = read4()
                        read4()
                        hdr_len    = read4()
                        hdr = data[pos:pos + hdr_len]

                        if hdr_proto == 1 and len(hdr) >= 34:
                            eth_type = struct.unpack_from(">H", hdr, 12)[0]
                            ip_off = 14
                            if eth_type == 0x8100 and len(hdr) >= 38:
                                eth_type = struct.unpack_from(">H", hdr, 16)[0]
                                ip_off = 18
                            if eth_type == 0x0800 and len(hdr) >= ip_off + 20:
                                src = ".".join(str(b) for b in hdr[ip_off+12:ip_off+16])
                                dst = ".".join(str(b) for b in hdr[ip_off+16:ip_off+20])
                                ip_proto = hdr[ip_off + 9]
                                ihl = (hdr[ip_off] & 0x0F) * 4
                                svc_port = 0
                                if ip_proto in (6, 17) and len(hdr) >= ip_off + ihl + 4:
                                    sport, dport = struct.unpack_from(
                                        ">HH", hdr, ip_off + ihl
                                    )
                                    if sport and dport:
                                        svc_port = sport if sport < dport else dport
                                    else:
                                        svc_port = sport or dport
                                results.append(
                                    (src, dst, ip_proto, svc_port,
                                     frame_len * sampling_rate)
                                )
                    pos = rec_end
            pos = sample_end
    except Exception:
        pass
    return results


def _atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


_running = True
def _stop(*_):
    global _running
    _running = False
signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT,  _stop)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 6343))
sock.settimeout(0.5)

# Eventos: deque de (timestamp, src, dst, bytes)
events = deque()
datagrams_total = 0
last_flush_ts   = time.time()   # frontera del delta (no solapado)
next_flush      = last_flush_ts + FLUSH_SEC

while _running:
    try:
        data, _ = sock.recvfrom(65535)
        datagrams_total += 1
        now = time.time()
        for src, dst, proto, svc_port, nbytes in parse_sflow_v5(data):
            events.append((now, src, dst, proto, svc_port, nbytes))
    except socket.timeout:
        pass
    except Exception:
        pass

    now = time.time()
    if now >= next_flush:
        # Ventana deslizante: live top-N (overlap entre flushes)
        cutoff = now - WINDOW_SEC
        while events and events[0][0] < cutoff:
            events.popleft()

        # Agregamos por (src, dst, proto, svc_port). svc_port = puerto del
        # servicio (well-known). Junta request+response y evita la fragmentación
        # del flood hping3 (cuyo sport varía por paquete).
        live_bytes = defaultdict(int)
        live_pkts  = defaultdict(int)
        delta_bytes = defaultdict(int)
        delta_pkts  = defaultdict(int)
        for ts, src, dst, proto, svc_port, b in events:
            key = (src, dst, proto, svc_port)
            live_bytes[key] += b
            live_pkts[key]  += 1
            if ts >= last_flush_ts:
                delta_bytes[key] += b
                delta_pkts[key]  += 1

        live_ranked  = sorted(live_bytes.items(),  key=lambda x: x[1], reverse=True)[:TOP_N]
        delta_ranked = sorted(delta_bytes.items(), key=lambda x: x[1], reverse=True)[:TOP_N]

        # Emitimos el svc_port como "dport" — formato compatible con el resto
        # del sistema (monitor_agent._proto_to_service usa (proto, dport)).
        snapshot = {
            "ts":          time.strftime("%Y-%m-%dT%H:%M:%S"),
            "window_sec":  WINDOW_SEC,
            "delta_sec":   FLUSH_SEC,
            "datagrams":   datagrams_total,
            "flows": [
                {"src": k[0], "dst": k[1], "proto": k[2], "dport": k[3],
                 "bytes": v, "pkts": live_pkts[k]}
                for k, v in live_ranked
            ],
            "delta_flows": [
                {"src": k[0], "dst": k[1], "proto": k[2], "dport": k[3],
                 "bytes": v, "pkts": delta_pkts[k]}
                for k, v in delta_ranked
            ],
        }
        try:
            _atomic_write(OUTPUT, snapshot)
        except Exception:
            pass
        last_flush_ts = now
        next_flush    = now + FLUSH_SEC

sock.close()
sys.exit(0)
'''


# ── Helpers internos ─────────────────────────────────────────────────────────

def _run(ssh, cmd, timeout=10):
    _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    return (
        stdout.read().decode("utf-8", errors="replace"),
        stderr.read().decode("utf-8", errors="replace"),
    )


def _list_bridges(ssh):
    out, _ = _run(ssh, "sudo ovs-vsctl list-br 2>/dev/null")
    return [b.strip() for b in out.splitlines() if b.strip()]


# ── API pública ──────────────────────────────────────────────────────────────

def configure_sflow_on_bridges(ssh, collector_ip="127.0.0.1", port=6343,
                               sampling=16, polling=5):
    """Aplica sFlow a todos los bridges OVS activos.

    sampling=16 → 1 de cada 16 paquetes. Más fino que 1/64 para que la
    heurística de port scan vea suficientes destinos distintos en
    escaneos cortos (12 destinos ≈ 75 % de probabilidad de captura).
    En Mininet el coste extra de CPU/IO es despreciable.
    polling=5   → contadores cada 5 s.
    """
    bridges = _list_bridges(ssh)
    if not bridges:
        print("[sFlow] No hay bridges OVS activos — sFlow no aplicado.")
        return []

    print(f"[sFlow] Configurando en {bridges} → {collector_ip}:{port} "
          f"(sampling=1/{sampling}, polling={polling}s)")
    ok = []
    for br in bridges:
        cmd = (
            f'sudo ovs-vsctl -- --id=@sf create sflow '
            f'agent=lo '
            f'target=\'"{collector_ip}:{port}"\' '
            f'sampling={sampling} '
            f'polling={polling} '
            f'-- set bridge {br} sflow=@sf 2>&1'
        )
        out, err = _run(ssh, cmd, timeout=15)
        if err.strip() or "error" in out.lower() or "unexpected" in out.lower():
            print(f"  [sFlow] WARN {br}: {(err or out).strip()}")
        else:
            ok.append(br)
    return ok


def remove_sflow_from_bridges(ssh):
    """Quita sFlow de todos los bridges y destruye los registros sFlow huérfanos."""
    bridges = _list_bridges(ssh)
    for br in bridges:
        _run(ssh, f"sudo ovs-vsctl clear bridge {br} sflow 2>/dev/null", timeout=10)
    _run(ssh, "sudo ovs-vsctl -- --all destroy sflow 2>/dev/null", timeout=10)


def start_sflow_daemon(ssh):
    """Sube el daemon a /tmp/sflow_daemon.py y lo arranca en background.

    Idempotente: mata cualquier instancia previa antes de relanzar.
    """
    print("[sFlow] Subiendo daemon a la VM...")
    sftp = ssh.open_sftp()
    with sftp.open("/tmp/sflow_daemon.py", "w") as f:
        f.write(_SFLOW_DAEMON)
    sftp.close()

    _run(ssh, "pkill -f sflow_daemon.py 2>/dev/null; true", timeout=5)
    _run(ssh, "rm -f /tmp/sflow_flows.json /tmp/sflow_daemon.log", timeout=5)

    _run(
        ssh,
        "nohup python3 /tmp/sflow_daemon.py "
        "> /tmp/sflow_daemon.log 2>&1 &",
        timeout=5,
    )
    time.sleep(1)
    out, _ = _run(ssh, "pgrep -f sflow_daemon.py")
    if out.strip():
        print(f"[sFlow] Daemon arrancado (pid={out.strip().splitlines()[0]})")
        return True
    print("[sFlow] ERROR: el daemon no quedó vivo. Ver /tmp/sflow_daemon.log en la VM.")
    return False


def stop_sflow_daemon(ssh):
    """Mata el daemon y limpia ficheros temporales en la VM."""
    _run(ssh, "pkill -f sflow_daemon.py 2>/dev/null; true", timeout=5)
    _run(ssh, "rm -f /tmp/sflow_daemon.py /tmp/sflow_daemon.log /tmp/sflow_flows.json",
         timeout=5)


def fetch_flows(ssh):
    """Lee /tmp/sflow_flows.json desde la VM. Devuelve dict (vacío si no existe)."""
    out, _ = _run(ssh, "cat /tmp/sflow_flows.json 2>/dev/null", timeout=10)
    if not out.strip():
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}
