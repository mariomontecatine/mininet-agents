#!/usr/bin/env python3
"""
Prueba aislada de sFlow sobre OVS — visibilidad de flujos origen→destino.

REQUISITO: el supervisor NOC debe estar CORRIENDO (necesita una topología activa).
Ejecutar desde la raíz del proyecto:
    python3 tests/probe_sflow.py [--duration 30]

El script:
  1. Configura sFlow en todos los bridges OVS activos (sampling=1 para la prueba).
  2. Lanza un colector sFlow v5 Python puro en la VM (sin dependencias externas).
  3. Captura los flujos N segundos y los agrega por par (src_ip, dst_ip).
  4. Muestra qué host está hablando con qué servidor y cuánto volumen.
  5. Elimina la configuración sFlow al terminar — no deja rastro.
"""

import sys
import os
import json
import time
import argparse
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.ssh_client import _new_client

# ── Colector sFlow v5 embebido (se sube a la VM via SFTP) ────────────────────
_SFLOW_COLLECTOR = '''\
#!/usr/bin/env python3
"""sFlow v5 UDP collector — sin dependencias externas."""
import socket, struct, json, time, sys
from collections import defaultdict

def parse_sflow_v5(data):
    """Parsea un datagrama sFlow v5 y devuelve lista de (src_ip, dst_ip, bytes)."""
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

        if read4() != 5:   # version
            return results
        addr_type = read4()
        if addr_type == 1:
            pos += 4      # agent IPv4
        elif addr_type == 2:
            pos += 16     # agent IPv6
        else:
            return results

        read4(); read4(); read4()  # sub_agent_id, seq_num, uptime
        num_samples = read4()

        for _ in range(num_samples):
            if pos + 8 > len(data):
                break
            sample_type = read4()
            sample_len  = read4()
            sample_end  = pos + sample_len

            if sample_type == 1 and pos + 32 <= sample_end:  # flow sample
                read4(); read4()          # seq, source_id
                sampling_rate = max(1, read4())
                read4(); read4()          # sample_pool, drops
                read4(); read4()          # input_if, output_if
                num_records = read4()

                for _ in range(num_records):
                    if pos + 8 > sample_end:
                        break
                    rec_type = read4()
                    rec_len  = read4()
                    rec_end  = pos + rec_len

                    if rec_type == 1 and rec_len >= 16:  # sampled header
                        hdr_proto  = read4()   # 1 = Ethernet
                        frame_len  = read4()
                        read4()                # stripped
                        hdr_len    = read4()
                        hdr = data[pos:pos + hdr_len]

                        if hdr_proto == 1 and len(hdr) >= 34:
                            eth_type = struct.unpack_from(">H", hdr, 12)[0]
                            ip_off = 14
                            if eth_type == 0x8100 and len(hdr) >= 38:
                                # VLAN-tagged: skip 4 extra bytes
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


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 6343))
sock.settimeout(1.0)

duration = int(sys.argv[1]) if len(sys.argv) > 1 else 30
end_time = time.time() + duration

flow_bytes = defaultdict(int)
flow_pkts  = defaultdict(int)
datagrams  = 0

while time.time() < end_time:
    try:
        data, _ = sock.recvfrom(65535)
        datagrams += 1
        for src, dst, nbytes in parse_sflow_v5(data):
            flow_bytes[(src, dst)] += nbytes
            flow_pkts[(src, dst)]  += 1
    except socket.timeout:
        continue

sock.close()
result = {
    "datagrams": datagrams,
    "flows": [
        {"src": k[0], "dst": k[1], "bytes": v, "pkts": flow_pkts[k]}
        for k, v in sorted(flow_bytes.items(), key=lambda x: x[1], reverse=True)
    ]
}
print(json.dumps(result))
'''


# ── Helpers ───────────────────────────────────────────────────────────────────

def fmt_bytes(b):
    b = float(b)
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.2f} TB"


def _run(ssh, cmd, timeout=10):
    _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    return stdout.read().decode(), stderr.read().decode()


def _get_bridges(ssh):
    out, _ = _run(ssh, "sudo ovs-vsctl list-br 2>/dev/null")
    return [b.strip() for b in out.splitlines() if b.strip()]


def _configure_sflow(ssh, bridges, collector_ip="127.0.0.1", port=6343):
    """Añade sFlow a cada bridge OVS. Sampling=1 (cada paquete) para la prueba."""
    print(f"[sFlow] Configurando en {bridges} → {collector_ip}:{port}")
    # OVS espera que el valor target incluya las comillas como parte del string
    for br in bridges:
        cmd = (
            f'sudo ovs-vsctl -- --id=@sf create sflow '
            f'agent=lo '
            f'target=\'"{collector_ip}:{port}"\' '
            f'sampling=1 '
            f'polling=5 '
            f'-- set bridge {br} sflow=@sf 2>&1'
        )
        out, err = _run(ssh, cmd, timeout=15)
        if err.strip():
            print(f"  [WARN] {br}: {err.strip()}")
        elif "error" in out.lower() or "unexpected" in out.lower():
            print(f"  [WARN] {br}: {out.strip()}")
        else:
            uuid = out.strip()
            print(f"  {br}: OK  (uuid={uuid[:8]}...)")


def _remove_sflow(ssh, bridges):
    for br in bridges:
        _run(ssh, f"sudo ovs-vsctl clear bridge {br} sflow 2>/dev/null", timeout=10)
    _run(ssh, "sudo ovs-vsctl -- --all destroy sflow 2>/dev/null", timeout=10)
    print("[sFlow] Configuración eliminada.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Prueba sFlow sobre OVS")
    parser.add_argument("--duration", type=int, default=30,
                        help="Segundos de captura (default: 30)")
    parser.add_argument("--top", type=int, default=10,
                        help="Top N pares a mostrar (default: 10)")
    args = parser.parse_args()

    print("=" * 60)
    print(" PROBE sFlow — visibilidad de flujos origen→destino ".center(60, "="))
    print("=" * 60)

    print("\n[PROBE] Conectando a la VM...")
    ssh = _new_client()

    # ── Bridges OVS activos ───────────────────────────────────────────────────
    bridges = _get_bridges(ssh)
    if not bridges:
        print("[ERROR] No hay bridges OVS activos. ¿Está corriendo el supervisor NOC?")
        ssh.close()
        return
    print(f"[PROBE] Bridges OVS encontrados: {bridges}")

    # ── Subir colector Python a la VM ─────────────────────────────────────────
    print("[PROBE] Subiendo colector sFlow Python...")
    sftp = ssh.open_sftp()
    with sftp.open("/tmp/sflow_collector.py", "w") as f:
        f.write(_SFLOW_COLLECTOR)
    sftp.close()

    # ── Lanzar colector en background (antes de activar sFlow en OVS) ─────────
    _run(ssh, "pkill -f sflow_collector.py 2>/dev/null; true", timeout=5)
    _run(ssh, "rm -f /tmp/sflow_output.json")
    _run(ssh,
         f"nohup python3 /tmp/sflow_collector.py {args.duration} "
         f"> /tmp/sflow_output.json 2>/dev/null &",
         timeout=5)
    time.sleep(1)  # dar tiempo al colector para que haga bind en el puerto

    # ── Configurar sFlow en bridges ───────────────────────────────────────────
    _configure_sflow(ssh, bridges)

    # ── Esperar captura ───────────────────────────────────────────────────────
    print(f"[sFlow] Capturando flujos durante {args.duration}s...")
    time.sleep(args.duration + 3)

    # ── Limpiar sFlow de los bridges ──────────────────────────────────────────
    _remove_sflow(ssh, bridges)

    # ── Leer resultados ───────────────────────────────────────────────────────
    out, _ = _run(ssh, "cat /tmp/sflow_output.json 2>/dev/null", timeout=15)
    _run(ssh, "rm -f /tmp/sflow_collector.py /tmp/sflow_output.json")
    ssh.close()

    # ── Parsear JSON ──────────────────────────────────────────────────────────
    try:
        data = json.loads(out.strip() or "{}")
    except json.JSONDecodeError:
        print(f"[ERROR] Salida inesperada del colector:\n{out[:300]}")
        return

    flows     = data.get("flows", [])
    datagrams = data.get("datagrams", 0)
    print(f"\n[sFlow] Datagramas sFlow recibidos: {datagrams}")
    print(f"[sFlow] Pares origen→destino únicos: {len(flows)}")

    if not flows:
        print("[sFlow] Sin flujos IP detectados.")
        print("        ¿Hay tráfico activo? Verifica que el supervisor")
        print("        haya lanzado launch_background_traffic().")
        return

    # ── Top pares ─────────────────────────────────────────────────────────────
    ranked = flows[: args.top]
    print(f"\n{'─'*60}")
    print(f"  Top-{args.top} pares por volumen  (ventana: {args.duration}s)")
    print(f"{'─'*60}")
    print(f"  {'Origen':<18} {'Destino':<18} {'Volumen':>10}  {'Muestras':>8}")
    print(f"{'─'*60}")
    for fl in ranked:
        print(f"  {fl['src']:<18} {fl['dst']:<18} "
              f"{fmt_bytes(fl['bytes']):>10}  {fl['pkts']:>8}")
    print(f"{'─'*60}")

    # ── Resumen por host origen ───────────────────────────────────────────────
    by_src = defaultdict(int)
    for fl in flows:
        by_src[fl["src"]] += fl["bytes"]
    print("\n  Tráfico total generado por host:")
    for src, b in sorted(by_src.items(), key=lambda kv: kv[1], reverse=True):
        print(f"    {src:<18} → {fmt_bytes(b)}")

    print("\n[PROBE] Si estos datos son útiles, el siguiente paso es:")
    print("  1. Mantener el colector como demonio en la VM.")
    print("  2. Escribir los flujos en /tmp/flows.json periódicamente.")
    print("  3. Añadir /api/flows al dashboard Flask.")
    print("  4. Renderizar un diagrama de Sankey con los top-10 pares.")


if __name__ == "__main__":
    main()
