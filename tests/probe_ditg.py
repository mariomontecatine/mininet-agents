#!/usr/bin/env python3
"""
Prueba aislada de D-ITG vs iperf en una topología Mininet mínima.

REQUISITO: el supervisor NOC debe estar DETENIDO (usa la misma VM).
Ejecutar desde la raíz del proyecto:
    python3 tests/probe_ditg.py

El script:
  1. Verifica / instala D-ITG en la VM.
  2. Despliega una topología de 2 hosts en una sesión tmux separada.
  3. Corre primero iperf (referencia) y después D-ITG con distribución
     de Pareto para IDT y tamaño de paquete.
  4. Compara los deltas de contadores OVS de ambas pruebas.
  5. Limpia todo al terminar.
"""

import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.ssh_client import _new_client

# ── Sesión tmux dedicada (distinta a sesion_mininet) ─────────────────────────
TMUX_SESSION = "probe_ditg"

# ── Script Python que correrá en la VM (via SFTP) ────────────────────────────
_PROBE_SCRIPT = '''\
#!/usr/bin/env python3
"""Mininet probe: iperf baseline vs D-ITG Pareto."""
import sys
sys.stdout.reconfigure(encoding="utf-8")  # fuerza UTF-8 independiente del terminal
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel
import time, re, shutil

setLogLevel("warning")

def fmt_bytes(b):
    b = float(b)
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.2f} TB"

def extract_rx_bytes(dump):
    """Extrae bytes RX por puerto de ovs-ofctl dump-ports.
    Formato: '  port N: rx pkts=X, bytes=Y, ...'
    """
    return [int(m) for m in re.findall(r"rx pkts=\\d+, bytes=(\\d+)", dump)]

def rx_delta(before, after):
    """Devuelve diferencias de bytes RX entre dos dumps OVS."""
    b = extract_rx_bytes(before)
    a = extract_rx_bytes(after)
    return [max(0, av - bv) for av, bv in zip(a, b)]

net = Mininet(topo=SingleSwitchTopo(2))
net.start()
h1, h2, s1 = net.get("h1"), net.get("h2"), net.get("s1")
print(f"Topología: h1={h1.IP()}  h2={h2.IP()}  s1={s1.name}")
print("="*60)

# ── 1. REFERENCIA: iperf ──────────────────────────────────────────────────────
print("\\n[1/3] IPERF — tráfico constante 30s")
ovs_before_iperf = s1.cmd("ovs-ofctl dump-ports s1")
h2.cmd("iperf -s -p 5001 &")
time.sleep(0.5)
out = h1.cmd(f"iperf -c {h2.IP()} -p 5001 -t 30 -f m 2>&1")
print(out.strip())
h2.cmd("pkill iperf")
time.sleep(0.5)

ovs_after_iperf = s1.cmd("ovs-ofctl dump-ports s1")
iperf_delta = rx_delta(ovs_before_iperf, ovs_after_iperf)
print("\\nDelta RX OVS (iperf):")
for i, b in enumerate(iperf_delta, 1):
    print(f"  puerto {i}: {fmt_bytes(b)}")

# ── 2. D-ITG ─────────────────────────────────────────────────────────────────
ditg_ok = bool(shutil.which("ITGSend"))
ditg_delta = []

if not ditg_ok:
    print("\\n[2/3] D-ITG no instalado — omitiendo prueba D-ITG")
    print("      Instalar con: sudo apt-get install d-itg")
else:
    print("\\n[2/3] D-ITG — distribución Pareto 30s")
    print("      IDT:    Pareto(alpha=1.5, min=500 µs) → ráfagas de alta varianza")
    print("      Tamaño: Pareto(alpha=1.2, min=512 B)  → paquetes de cola pesada")

    ovs_before_ditg = s1.cmd("ovs-ofctl dump-ports s1")

    h2.cmd("ITGRecv &")
    time.sleep(0.5)

    # alpha < 2 → varianza infinita (auto-similitud)
    cmd = (
        f"ITGSend -a {h2.IP()} -T UDP "
        "-dP 1.5 500 "     # IDT Pareto: shape=1.5, min=500 µs
        "-bP 1.2 512 "     # Tamaño Pareto: shape=1.2, min=512 B
        "-t 30000 "        # 30 segundos
        "-l /tmp/itg_sender.log 2>&1"
    )
    out_ditg = h1.cmd(cmd)
    if "error" in out_ditg.lower() or "invalid" in out_ditg.lower():
        print("  [WARN] Sintaxis Pareto no soportada — usando exponencial (-dE)")
        cmd = (
            f"ITGSend -a {h2.IP()} -T UDP "
            "-dE 1000 "    # IDT exponencial, media 1000 µs
            "-t 30000 "
            "-l /tmp/itg_sender.log 2>&1"
        )
        out_ditg = h1.cmd(cmd)

    print(out_ditg.strip() or "(sin salida — ver log)")

    dec = h1.cmd("ITGDec /tmp/itg_sender.log 2>&1")
    # Filtrar spinner de ITGDec: las lineas del spinner son muy largas (>200 chars)
    dec_clean = "\\n".join(
        l for l in dec.splitlines() if l.strip() and len(l.strip()) < 200
    )
    print("\\nEstadísticas D-ITG (ITGDec):")
    print(dec_clean)

    h2.cmd("pkill ITGRecv")

    ovs_after_ditg = s1.cmd("ovs-ofctl dump-ports s1")
    ditg_delta = rx_delta(ovs_before_ditg, ovs_after_ditg)
    print("\\nDelta RX OVS (D-ITG):")
    for i, b in enumerate(ditg_delta, 1):
        print(f"  puerto {i}: {fmt_bytes(b)}")

# ── 3. COMPARATIVA ───────────────────────────────────────────────────────────
print("\\n[3/3] Comparativa (delta RX en los 30s de cada prueba):")
print(f"  iperf  → {[fmt_bytes(b) for b in iperf_delta]}")
if ditg_ok and ditg_delta:
    print(f"  D-ITG  → {[fmt_bytes(b) for b in ditg_delta]}")
    total_iperf = sum(iperf_delta)
    total_ditg  = sum(ditg_delta)
    if total_iperf > 0:
        ratio = total_ditg / total_iperf
        print(f"  Ratio D-ITG/iperf: {ratio:.2f}")
        if ratio < 0.5:
            print("  → D-ITG transfiere significativamente menos — distribución Pareto visible")
        else:
            print("  → Volúmenes similares — la granularidad de dump-ports limita la observación")

print("\\n[PROBE] Limpiando...")
net.stop()
print("[PROBE] Hecho.")
'''


def _run(ssh, cmd, timeout=5):
    """exec_command síncrono con timeout."""
    _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode()
    err = stderr.read().decode()
    return out, err


def _check_no_mininet(ssh):
    """Advierte si ya hay bridges OVS activos (señal de que Mininet está corriendo)."""
    out, _ = _run(ssh, "sudo ovs-vsctl list-br 2>/dev/null")
    bridges = [b.strip() for b in out.splitlines() if b.strip()]
    count = len(bridges)
    if count > 0:
        print(f"[WARN] Hay bridges OVS activos en la VM: {bridges}")
        print("       Esto indica que Mininet ya está corriendo — puede haber conflicto de nombres.")
        print("       Detén el supervisor NOC y ejecuta 'sudo mn --clean' antes de esta prueba.")
        print("       Continuar de todos modos en 5s... (Ctrl+C para cancelar)")
        time.sleep(5)


def main():
    print("=" * 60)
    print(" PROBE D-ITG — prueba aislada ".center(60, "="))
    print("=" * 60)

    print("\n[PROBE] Conectando a la VM...")
    ssh = _new_client()

    _check_no_mininet(ssh)

    # ── Verificar / instalar D-ITG ────────────────────────────────────────────
    out, _ = _run(ssh, "which ITGSend 2>/dev/null || echo NOTFOUND")
    if "NOTFOUND" in out:
        print("[PROBE] D-ITG no encontrado. Intentando instalar via apt...")
        out, err = _run(ssh, "sudo apt-get install -y d-itg 2>&1 | tail -6", timeout=120)
        print(out)
        out, _ = _run(ssh, "which ITGSend 2>/dev/null || echo NOTFOUND")
        if "NOTFOUND" in out:
            print("[PROBE] D-ITG no disponible en los repos del sistema.")
            print("        La prueba continuará sin D-ITG (solo iperf de referencia).")
            print("        Para instalarlo manualmente en la VM:")
            print("          sudo apt-get install d-itg")
        else:
            print(f"[PROBE] D-ITG instalado: {out.strip()}")
    else:
        print(f"[PROBE] D-ITG encontrado: {out.strip()}")

    # ── Subir el script Python a la VM via SFTP ───────────────────────────────
    print("[PROBE] Subiendo script a la VM...")
    sftp = ssh.open_sftp()
    with sftp.open("/tmp/probe_ditg_mn.py", "w") as f:
        f.write(_PROBE_SCRIPT)
    sftp.close()

    # ── Limpiar posibles runs anteriores ─────────────────────────────────────
    _run(ssh, f"tmux kill-session -t {TMUX_SESSION} 2>/dev/null; true")
    _run(ssh, "rm -f /tmp/probe_ditg_output.txt")

    # ── Ejecutar en tmux dedicado ─────────────────────────────────────────────
    _run(ssh, f"tmux new-session -d -s {TMUX_SESSION} -x 220 -y 50")
    time.sleep(0.5)
    _run(ssh,
         f"tmux send-keys -t {TMUX_SESSION} "
         f"'sudo python3 /tmp/probe_ditg_mn.py 2>&1 | tee /tmp/probe_ditg_output.txt' C-m")

    print("[PROBE] Prueba en ejecución (~75s con D-ITG, ~45s solo iperf)...")
    print("        Monitorizando progreso:\n")

    deadline   = time.time() + 180
    last_shown = 0
    while time.time() < deadline:
        time.sleep(3)
        _, out, _ = ssh.exec_command(
            "cat /tmp/probe_ditg_output.txt 2>/dev/null")
        content = out.read().decode("utf-8", errors="replace")
        lines = content.splitlines()
        for line in lines[last_shown:]:
            print("  " + line)
        last_shown = len(lines)
        if "[PROBE] Hecho." in content:
            break
    else:
        print("\n[PROBE] Timeout — la prueba tardó demasiado.")

    # ── Limpiar ───────────────────────────────────────────────────────────────
    _run(ssh, f"tmux kill-session -t {TMUX_SESSION} 2>/dev/null; true")
    _run(ssh, "rm -f /tmp/probe_ditg_mn.py /tmp/probe_ditg_output.txt /tmp/itg_sender.log")
    ssh.close()
    print("\n[PROBE] Sesión cerrada.")


if __name__ == "__main__":
    main()
