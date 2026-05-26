"""Prueba de llamada VoIP (RTP) con antes/después de QoS sobre el troncal central.

Demuestra, con números, que priorizar el VoIP en el router central protege la
llamada cuando el troncal está saturado.

Diseño del experimento (la ÚNICA variable es la priorización):
  - El enlace troncal se limita a `link_mbps` (p.ej. 10) vía el HTB del puerto de
    shaping (central_link.shaping_port). El límite existe en AMBAS fases.
  - ANTES : HTB con UNA sola clase → RTP y tráfico pesado compiten en igualdad →
            la llamada se degrada (pérdida/jitter altos, MOS bajo).
  - DESPUÉS: HTB multi-tier con el RTP en la clase interactiva (prio 0) → la
            llamada queda protegida (pérdida≈0, jitter bajo, MOS alto).
  - En ambas fases corre la MISMA llamada RTP (srv→host, cruza el troncal) y el
    MISMO tráfico de saturación (iperf UDP srv→host, cruza el troncal).

El resultado se escribe en tmp/voip_test_result.json con un campo `status`
("running" | "done" | "error") para que el dashboard lo sondee.
"""

import json
import os
import re
import threading
import time

from utils import config
from utils.ssh_client import get_ssh_connection, send_tmux_command
from agents import qos_intent
from agents.central_link import load_central_link

_ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP_DIR     = os.path.join(_ROOT, "tmp")
TOPO_FILE   = os.path.join(TMP_DIR, "topology.json")
RESULT_FILE = os.path.join(TMP_DIR, "voip_test_result.json")
RTP_LOCAL   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rtp_tool.py")
RTP_REMOTE  = "/tmp/rtp_tool.py"
AUDIO_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mario-talk.wav")
AUDIO_REMOTE = "/tmp/voip_audio.wav"

RTP_PORT    = config.SERVICE_PORTS.get("rtp", 16384)
IPERF_PORT  = 5001          # UDP iperf (no catalogado → cae en best-effort)
_IP_RE      = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

_lock = threading.Lock()
_running = False


# ── Topología: lados del troncal y selección de extremos ─────────────────────

def _load_topo():
    with open(TOPO_FILE, encoding="utf-8") as f:
        return json.load(f)


def _build_node_graph(topo):
    """Adyacencia nodo→[nodos] solo con enlaces físicos (ambos extremos nombre)."""
    adj = {}
    for l in topo.get("links", []):
        a, b = l.get("from"), l.get("to")
        if not a or not b or _IP_RE.match(str(a)) or _IP_RE.match(str(b)):
            continue
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
    return {k: sorted(v) for k, v in adj.items()}


def _nearest_router(adj, routers):
    from collections import deque
    nearest, q = {}, deque()
    for r in routers:
        nearest[r] = r
        q.append(r)
    while q:
        cur = q.popleft()
        for nb in adj.get(cur, []):
            if nb not in nearest:
                nearest[nb] = nearest[cur]
                q.append(nb)
    return nearest


def _is_router(n): return n.startswith("r") and not n.startswith("srv")


def pick_endpoints(central, topo):
    """Elige (emisor servidor, receptor host) en lados OPUESTOS del troncal, más
    un par extra para el tráfico de saturación. Devuelve dict con nombres+IPs."""
    adj = _build_node_graph(topo)
    endpoints = topo.get("endpoints", {})
    routers = [n for n in adj if _is_router(n)]
    nearest = _nearest_router(adj, routers)

    shaping_port = central["shaping_port"]
    hosts_router = central.get("neighbors", {}).get(shaping_port)   # router lado hosts
    # router del lado servidores = el del puerto reverso (o cualquier otro)
    rev_port = central.get("shaping_port_reverse")
    servers_router = central.get("neighbors", {}).get(rev_port)
    if not servers_router:
        others = [r for r in routers if r != hosts_router]
        servers_router = others[0] if others else hosts_router

    def _side(prefix, router):
        return [n for n in endpoints
                if n.startswith(prefix) and nearest.get(n) == router]

    hosts = _side("h", hosts_router) or [n for n in endpoints if n.startswith("h")]
    servers = _side("srv", servers_router) or [n for n in endpoints if n.startswith("srv")]
    if not hosts or not servers:
        raise ValueError("No hay hosts/servidores en lados opuestos del troncal.")

    receiver = hosts[0]
    sender = servers[0]
    # Par de saturación: distinto host destino si hay; servidor extra si hay.
    bulk_host = hosts[1] if len(hosts) > 1 else hosts[0]
    bulk_srv = servers[1] if len(servers) > 1 else servers[0]

    return {
        "sender": sender, "sender_ip": endpoints[sender],
        "receiver": receiver, "receiver_ip": endpoints[receiver],
        "bulk_srv": bulk_srv, "bulk_srv_ip": endpoints[bulk_srv],
        "bulk_host": bulk_host, "bulk_host_ip": endpoints[bulk_host],
        "hosts_router": hosts_router, "servers_router": servers_router,
    }


# ── tc en el troncal: cap plano (antes) y QoS priorizada (después) ────────────

def _apply_plain_cap(ssh, port, link_mbps):
    """HTB con una única clase: limita el troncal pero NO prioriza (baseline)."""
    cmds = [
        f"sh tc qdisc del dev {port} root 2>/dev/null; true",
        f"sh tc qdisc add dev {port} root handle 1: htb default 10",
        (f"sh tc class add dev {port} parent 1: classid 1:10 htb "
         f"rate {link_mbps:.2f}mbit ceil {link_mbps:.2f}mbit"),
    ]
    for i, c in enumerate(cmds):
        send_tmux_command(ssh, c)
        time.sleep(0.3 if i == 0 else 0.1)


def _apply_voip_qos(ssh, port, link_mbps):
    """HTB priorizada con el RTP en la clase interactiva. Reusa qos_intent."""
    plan = qos_intent.build_qos_plan(None, [{"app": "voip"}], total_mbps=link_mbps,
                                     scope="network")
    cmds = qos_intent.build_tc_commands(plan)
    for i, entry in enumerate(cmds):
        send_tmux_command(ssh, entry["cmd"])
        time.sleep(0.3 if i == 0 else 0.08)
    return plan


def _clear_cap(ssh, port):
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
    time.sleep(0.2)


# ── Tráfico (vía tmux: '<host> <cmd>') ───────────────────────────────────────

def _push_rtp_tool(ssh):
    """Copia rtp_tool.py y el audio a la VM (sftp). Mismo fs para todos los hosts."""
    sftp = ssh.open_sftp()
    try:
        sftp.put(RTP_LOCAL, RTP_REMOTE)
        if os.path.exists(AUDIO_LOCAL):
            sftp.put(AUDIO_LOCAL, AUDIO_REMOTE)
    finally:
        sftp.close()


def _fetch(ssh, remote, local):
    """Trae un fichero de la VM al host local (para servirlo desde el dashboard)."""
    try:
        sftp = ssh.open_sftp()
        try:
            sftp.get(remote, local)
            return True
        finally:
            sftp.close()
    except Exception:
        return False


def _tshark_rtp(ssh, pcap_remote):
    """Análisis RTP INDEPENDIENTE con tshark (Wireshark) sobre el pcap capturado.

    Fuerza el dissector RTP en el puerto y pide el resumen de streams. Devuelve
    {loss_pct, jitter_ms, raw} — el `raw` es la tabla literal de Wireshark, que
    es la prueba de que las métricas no las inventa nuestro script.
    """
    cmd = (f"tshark -r {pcap_remote} -d udp.port=={RTP_PORT},rtp "
           f"-q -z rtp,streams 2>/dev/null")
    try:
        _i, o, _e = ssh.exec_command(cmd, timeout=30)
        raw = o.read().decode("utf-8", errors="replace").strip()
    except Exception as e:
        return {"raw": f"(tshark no disponible: {e})"}
    out = {"raw": raw}
    # Pérdida: Wireshark muestra algo como "471 (79.7%)".
    m = re.search(r"\(\s*([\d.]+)\s*%\)", raw)
    if m:
        out["loss_pct"] = float(m.group(1))
    # Jitter medio: última columna float de la fila de datos (ms).
    for line in raw.splitlines():
        floats = re.findall(r"\d+\.\d+", line)
        if len(floats) >= 2 and ("." in line):
            # heurística: la fila de datos del stream trae varios floats; el
            # jitter medio suele ser el penúltimo/último. Guardamos el último.
            out["jitter_ms"] = float(floats[-1])
    return out


def _start_bulk(ssh, ep, secs):
    """iperf UDP servidor(host)→cliente(servidor) que cruza el troncal y satura."""
    # Servidor iperf en el host receptor del bulk.
    send_tmux_command(ssh, f"{ep['bulk_host']} iperf -s -u -p {IPERF_PORT} >/dev/null 2>&1 &")
    time.sleep(0.5)
    # Cliente desde el servidor (lado opuesto): 60 Mbps >> cap del troncal.
    send_tmux_command(
        ssh,
        f"{ep['bulk_srv']} iperf -c {ep['bulk_host_ip']} -u -p {IPERF_PORT} "
        f"-b 60m -t {int(secs) + 4} >/dev/null 2>&1 &")
    time.sleep(0.3)


def _stop_bulk(ssh):
    send_tmux_command(ssh, "sh pkill -f 'iperf' 2>/dev/null; true")
    time.sleep(0.5)


def _run_call(ssh, ep, secs, tag):
    """Lanza la llamada RTP de una fase y devuelve métricas + verificación.

    En el host receptor: (1) tcpdump captura el RTP real → pcap; (2) el receptor
    reconstruye el audio recibido → WAV. El emisor manda el audio real. Al acabar
    se contrasta con tshark y se traen pcap+wav al dashboard.
    """
    out_remote   = f"/tmp/rtp_result_{tag}.json"
    audio_remote = f"/tmp/rtp_audio_{tag}.wav"
    pcap_remote  = f"/tmp/rtp_{tag}.pcap"
    send_tmux_command(ssh, f"sh rm -f {out_remote} {audio_remote} {pcap_remote} 2>/dev/null; true")
    time.sleep(0.2)

    # 1) tcpdump en el receptor (captura independiente del RTP que LLEGA).
    send_tmux_command(
        ssh,
        f"{ep['receiver']} tcpdump -n -i any udp port {RTP_PORT} -w {pcap_remote} "
        f">/tmp/tcpdump_{tag}.log 2>&1 &")
    time.sleep(0.8)
    # 2) Receptor (mide + reconstruye audio).
    send_tmux_command(
        ssh,
        f"{ep['receiver']} python3 {RTP_REMOTE} recv {RTP_PORT} {secs} {out_remote} "
        f"{audio_remote} >/tmp/rtp_recv_{tag}.log 2>&1 &")
    time.sleep(0.8)
    # 3) Emisor con el audio real.
    send_tmux_command(
        ssh,
        f"{ep['sender']} python3 {RTP_REMOTE} send {ep['receiver_ip']} {RTP_PORT} "
        f"{secs} 50 160 40000 {AUDIO_REMOTE} >/tmp/rtp_send_{tag}.log 2>&1 &")

    # Espera a que termine la llamada + el flush del receptor.
    time.sleep(int(secs) + 6)
    send_tmux_command(ssh, "sh pkill -f tcpdump 2>/dev/null; true")
    time.sleep(0.8)

    # Métricas de nuestro receptor.
    _i, o, _e = ssh.exec_command(f"cat {out_remote} 2>/dev/null", timeout=10)
    raw = o.read().decode("utf-8", errors="replace").strip()
    try:
        metrics = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        metrics = {"error": "sin resultado", "raw": raw[:200]}

    # Verificación independiente con tshark (Wireshark) sobre el pcap.
    metrics["tshark"] = _tshark_rtp(ssh, pcap_remote)

    # Traer artefactos al dashboard (tmp/), para servir audio y pcap.
    wav_local  = os.path.join(TMP_DIR, f"voip_audio_{tag}.wav")
    pcap_local = os.path.join(TMP_DIR, f"voip_capture_{tag}.pcap")
    if _fetch(ssh, audio_remote, wav_local):
        metrics["audio_file"] = f"voip_audio_{tag}.wav"
    if _fetch(ssh, pcap_remote, pcap_local):
        metrics["pcap_file"] = f"voip_capture_{tag}.pcap"
    return metrics


# ── Orquestación ─────────────────────────────────────────────────────────────

def _write_status(payload):
    try:
        with open(RESULT_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except IOError:
        pass


def _audio_secs(default=12):
    """Duración (s, redondeada al alza) del clip de audio: la llamada dura eso."""
    import math
    import wave
    try:
        w = wave.open(AUDIO_LOCAL, "rb")
        d = w.getnframes() / float(w.getframerate())
        w.close()
        return max(4, int(math.ceil(d)))
    except Exception:
        return default


def run_test(secs=None, link_mbps=10.0):
    """Ejecuta el experimento completo (bloqueante). Escribe RESULT_FILE.

    secs=None → la llamada dura lo que dure el audio (mario-talk.wav).
    """
    global _running
    if secs is None:
        secs = _audio_secs()
    with _lock:
        if _running:
            return {"status": "busy"}
        _running = True

    state = {"status": "running", "phase": "init", "started_at": time.time(),
             "config": {"secs": secs, "link_mbps": link_mbps}}
    _write_status(state)

    try:
        central = load_central_link()
        if not central:
            raise ValueError("No hay enlace central. Despliega la red primero.")
        topo = _load_topo()
        ep = pick_endpoints(central, topo)
        port = central["shaping_port"]
        state.update({"central": central, "endpoints": ep})

        ssh = get_ssh_connection()
        _push_rtp_tool(ssh)

        # ── FASE ANTES: cap plano, sin prioridad ──
        state["phase"] = "antes"; _write_status(state)
        _apply_plain_cap(ssh, port, link_mbps)
        _start_bulk(ssh, ep, secs)
        before = _run_call(ssh, ep, secs, "before")
        _stop_bulk(ssh)
        state["before"] = before; _write_status(state)

        time.sleep(2)

        # ── FASE DESPUÉS: QoS priorizada ──
        state["phase"] = "despues"; _write_status(state)
        plan = _apply_voip_qos(ssh, port, link_mbps)
        state["qos_plan"] = {"target_port": plan["target_port"],
                             "tc_commands": plan.get("tc_commands") or qos_intent.build_tc_commands(plan)}
        _start_bulk(ssh, ep, secs)
        after = _run_call(ssh, ep, secs, "after")
        _stop_bulk(ssh)
        state["after"] = after

        # Limpieza del cap del troncal (dejamos la red como estaba).
        _clear_cap(ssh, port)
        ssh.close()

        state["phase"] = "done"
        state["status"] = "done"
        state["finished_at"] = time.time()
        _write_status(state)
        return state
    except Exception as e:
        state["status"] = "error"
        state["error"] = f"{type(e).__name__}: {e}"
        _write_status(state)
        return state
    finally:
        with _lock:
            _running = False


def run_test_async(secs=None, link_mbps=10.0):
    """Lanza run_test en un hilo (para no bloquear el endpoint HTTP)."""
    t = threading.Thread(target=run_test, kwargs={"secs": secs, "link_mbps": link_mbps},
                         daemon=True)
    t.start()
    return {"status": "started", "secs": secs or _audio_secs(), "link_mbps": link_mbps}


def load_result():
    if not os.path.exists(RESULT_FILE):
        return None
    try:
        with open(RESULT_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None
