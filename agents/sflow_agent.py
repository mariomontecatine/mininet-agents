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
TOP_N      = 20
OUTPUT     = "/tmp/sflow_flows.json"

def parse_sflow_v5(data):
    """Devuelve [(src_ip, dst_ip, bytes_scaled), ...]."""
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
                                results.append((src, dst, frame_len * sampling_rate))
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
        for src, dst, nbytes in parse_sflow_v5(data):
            events.append((now, src, dst, nbytes))
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

        live_bytes = defaultdict(int)
        live_pkts  = defaultdict(int)
        # Delta: solo eventos desde last_flush_ts (no solapados)
        delta_bytes = defaultdict(int)
        delta_pkts  = defaultdict(int)
        for ts, src, dst, b in events:
            live_bytes[(src, dst)] += b
            live_pkts[(src, dst)]  += 1
            if ts >= last_flush_ts:
                delta_bytes[(src, dst)] += b
                delta_pkts[(src, dst)]  += 1

        live_ranked = sorted(live_bytes.items(), key=lambda x: x[1], reverse=True)[:TOP_N]
        delta_ranked = sorted(delta_bytes.items(), key=lambda x: x[1], reverse=True)[:TOP_N]

        snapshot = {
            "ts":          time.strftime("%Y-%m-%dT%H:%M:%S"),
            "window_sec":  WINDOW_SEC,
            "delta_sec":   FLUSH_SEC,
            "datagrams":   datagrams_total,
            "flows": [
                {"src": k[0], "dst": k[1], "bytes": v, "pkts": live_pkts[k]}
                for k, v in live_ranked
            ],
            "delta_flows": [
                {"src": k[0], "dst": k[1], "bytes": v, "pkts": delta_pkts[k]}
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
                               sampling=64, polling=5):
    """Aplica sFlow a todos los bridges OVS activos.

    sampling=64 → 1 de cada 64 paquetes (compromiso CPU/precisión).
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
