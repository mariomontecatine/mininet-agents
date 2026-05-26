#!/usr/bin/env python3
"""Generador/medidor de una llamada VoIP RTP real para Mininet.

Es un script AUTÓNOMO (solo stdlib) que se copia a la VM y se ejecuta dentro de
los hosts Mininet con `<host> python3 /tmp/rtp_tool.py ...`. No importa nada del
proyecto: corre con el python3 plano de la VM.

Modela una llamada G.711 (PCMU): 50 paquetes/s, ~160 B de payload (20 ms de
audio), cabecera RTP de 12 B → ~64-69 kbps. El puerto se fija (por defecto
16384, el rango RTP "pinneado" que clasificamos en SERVICE_DEFS) y el sport del
emisor también, para que sFlow vea UN solo flujo.

  Emisor:   python3 rtp_tool.py send <dst_ip> <dst_port> <secs> [pps] [payload] [sport] [audio_wav]
  Receptor: python3 rtp_tool.py recv <bind_port> <secs> <out_json> [audio_out_wav]

El receptor calcula, al estilo de un analizador VoIP real (RFC 3550 + E-model):
  - loss_pct   : % de paquetes RTP perdidos (huecos en el nº de secuencia)
  - jitter_ms  : jitter de interarrival suavizado (RFC 3550)
  - throughput_kbps
  - mos        : MOS estimado (E-model simplificado para G.711)
y lo escribe como JSON en <out_json>.
"""

import audioop
import json
import os
import socket
import struct
import sys
import time
import wave

RTP_VERSION = 2
PT_PCMU     = 0          # G.711 µ-law
CLOCK_HZ    = 8000       # reloj RTP de G.711
SAMPLES_20MS = 160       # muestras por paquete a 20 ms (= 160 bytes µ-law)
ULAW_SILENCE = b"\xff" * SAMPLES_20MS   # silencio digital en µ-law


# ── Audio: WAV ⇄ tramas µ-law de 20 ms (stdlib, sin sox/ffmpeg) ──────────────

def _load_ulaw_frames(wav_path):
    """Lee un WAV, lo pasa a 8 kHz mono y lo trocea en tramas µ-law de 160 B."""
    w = wave.open(wav_path, "rb")
    n_ch = w.getnchannels()
    width = w.getsampwidth()
    rate = w.getframerate()
    pcm = w.readframes(w.getnframes())
    w.close()
    if width != 2:                      # normalizamos a 16-bit
        pcm = audioop.lin2lin(pcm, width, 2)
        width = 2
    if n_ch == 2:                       # estéreo → mono
        pcm = audioop.tomono(pcm, 2, 0.5, 0.5)
    if rate != CLOCK_HZ:                # resample a 8 kHz
        pcm, _ = audioop.ratecv(pcm, 2, 1, rate, CLOCK_HZ, None)
    ulaw = audioop.lin2ulaw(pcm, 2)     # 16-bit PCM → µ-law (1 byte/muestra)
    frames = [ulaw[i:i + SAMPLES_20MS] for i in range(0, len(ulaw), SAMPLES_20MS)]
    if frames and len(frames[-1]) < SAMPLES_20MS:
        frames[-1] = frames[-1] + ULAW_SILENCE[len(frames[-1]):]
    return frames or [ULAW_SILENCE]


def _write_wav_from_ulaw(ulaw_bytes, out_path):
    """Decodifica µ-law → PCM 16-bit y escribe un WAV mono 8 kHz."""
    pcm = audioop.ulaw2lin(ulaw_bytes, 2)
    w = wave.open(out_path, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(CLOCK_HZ)
    w.writeframes(pcm)
    w.close()


# ── Emisor ───────────────────────────────────────────────────────────────────

def send(dst_ip, dst_port, secs, pps=50, payload=160, sport=40000, audio=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", int(sport)))
    except OSError:
        pass  # si el sport está ocupado, dejamos que el SO elija (sFlow lo verá distinto)

    # Si hay audio, mandamos sus tramas µ-law (en bucle si la llamada es más
    # larga que el clip). Si no, silencio (relleno sintético).
    frames = None
    if audio and os.path.exists(audio):
        try:
            frames = _load_ulaw_frames(audio)
        except Exception as e:
            print(f"[RTP-SEND] WARN no pude leer {audio} ({e}); uso silencio.")
    silence = b"\xff" * int(payload)

    ssrc = int(time.time()) & 0xFFFFFFFF
    seq = 0
    ts = 0
    interval = 1.0 / float(pps)
    n = int(secs) * int(pps)
    start = time.time()
    for i in range(n):
        media = frames[i % len(frames)] if frames else silence
        header = struct.pack(
            "!BBHII",
            (RTP_VERSION << 6),         # V=2, P=0, X=0, CC=0
            PT_PCMU,                    # M=0, PT=0
            seq & 0xFFFF,
            ts & 0xFFFFFFFF,
            ssrc,
        )
        try:
            sock.sendto(header + media, (dst_ip, int(dst_port)))
        except OSError:
            pass
        seq += 1
        ts += SAMPLES_20MS
        # Cadencia constante: dormir hasta el siguiente tick teórico.
        nxt = start + (i + 1) * interval
        delay = nxt - time.time()
        if delay > 0:
            time.sleep(delay)
    sock.close()
    src = "audio" if frames else "silencio"
    print(f"[RTP-SEND] {seq} paquetes a {dst_ip}:{dst_port} (~{pps} pps, {src})")


# ── Receptor + métricas ──────────────────────────────────────────────────────

def _mos_from(loss_pct, jitter_ms):
    """MOS estimado vía E-model simplificado (G.711).

    No medimos retardo de un solo sentido (no hay reloj sincronizado), así que
    aproximamos el retardo de reproducción como un buffer base + 2× jitter —
    suficiente para que el antes/después sea claro. Documentado como aprox.
    """
    # Impairment por retardo (Id): d = base playout + 2*jitter
    d = 50.0 + 2.0 * jitter_ms
    Id = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    # Impairment por pérdida (Ie_eff) para G.711 sin PLC: Bpl≈4.3
    Bpl = 4.3
    Ie_eff = (95.0) * (loss_pct / (loss_pct + Bpl)) if loss_pct > 0 else 0.0
    R = 93.2 - Id - Ie_eff
    R = max(0.0, min(100.0, R))
    if R <= 0:
        mos = 1.0
    else:
        mos = 1.0 + 0.035 * R + 7e-6 * R * (R - 60.0) * (100.0 - R)
    return round(max(1.0, min(4.5, mos)), 2)


def recv(bind_port, secs, out_json, audio_out=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", int(bind_port)))
    # Timeout = duración + margen para recibir la cola de paquetes.
    deadline = time.time() + float(secs) + 3.0
    sock.settimeout(1.0)

    seqs = []           # nº de secuencia recibidos
    payloads = {}       # seq → payload µ-law (para reconstruir el audio recibido)
    total_bytes = 0
    transit_prev = None
    jitter = 0.0        # RFC 3550, en unidades de reloj RTP
    first_arrival = None
    last_arrival = None

    while time.time() < deadline:
        try:
            data, _addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        if len(data) < 12:
            continue
        now = time.time()
        b0, _b1, seq, ts, _ssrc = struct.unpack("!BBHII", data[:12])
        if (b0 >> 6) != RTP_VERSION:
            continue
        if first_arrival is None:
            first_arrival = now
        last_arrival = now
        total_bytes += len(data)
        seqs.append(seq)
        payloads[seq] = data[12:]

        # Jitter RFC 3550: transit = arrival_clock - rtp_ts. Comparamos transit
        # consecutivos. arrival en unidades de reloj RTP (8 kHz).
        arrival_rtp = now * CLOCK_HZ
        transit = arrival_rtp - ts
        if transit_prev is not None:
            d = abs(transit - transit_prev)
            jitter += (d - jitter) / 16.0
        transit_prev = transit

    sock.close()

    received = len(seqs)
    result = {
        "received": received,
        "loss_pct": 0.0,
        "jitter_ms": 0.0,
        "throughput_kbps": 0.0,
        "mos": 1.0,
        "expected": 0,
        "lost": 0,
    }
    if received >= 2:
        lo, hi = min(seqs), max(seqs)
        # Manejo simple sin wrap (20 s a 50 pps = 1000 < 65535, no hay wrap).
        expected = hi - lo + 1
        lost = max(0, expected - received)
        loss_pct = round(100.0 * lost / expected, 2) if expected > 0 else 0.0
        jitter_ms = round(1000.0 * jitter / CLOCK_HZ, 2)
        span = (last_arrival - first_arrival) or 1.0
        throughput_kbps = round(total_bytes * 8 / span / 1000.0, 1)
        result.update({
            "expected": expected,
            "lost": lost,
            "loss_pct": loss_pct,
            "jitter_ms": jitter_ms,
            "throughput_kbps": throughput_kbps,
            "mos": _mos_from(loss_pct, jitter_ms),
        })

        # Reconstruye el audio TAL CUAL se recibió: cada hueco de secuencia
        # (paquete perdido) se rellena con silencio → la versión sin QoS suena
        # entrecortada de verdad, porque le faltan esas tramas.
        if audio_out:
            try:
                chunks = []
                for s in range(lo, hi + 1):
                    p = payloads.get(s, ULAW_SILENCE)
                    if len(p) != SAMPLES_20MS:
                        p = (p + ULAW_SILENCE)[:SAMPLES_20MS]
                    chunks.append(p)
                _write_wav_from_ulaw(b"".join(chunks), audio_out)
                result["audio_wav"] = audio_out
            except Exception as e:
                result["audio_error"] = str(e)

    try:
        with open(out_json, "w") as f:
            json.dump(result, f)
    except IOError:
        pass
    print(f"[RTP-RECV] {json.dumps(result)}")
    return result


# ── CLI ──────────────────────────────────────────────────────────────────────

def _main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    mode = argv[1]
    if mode == "send":
        dst_ip   = argv[2]
        dst_port = argv[3]
        secs     = argv[4]
        pps      = argv[5] if len(argv) > 5 else 50
        payload  = argv[6] if len(argv) > 6 else 160
        sport    = argv[7] if len(argv) > 7 else 40000
        audio    = argv[8] if len(argv) > 8 else None
        send(dst_ip, dst_port, int(secs), int(pps), int(payload), int(sport), audio)
        return 0
    if mode == "recv":
        bind_port = argv[2]
        secs      = argv[3]
        out_json  = argv[4] if len(argv) > 4 else "/tmp/rtp_result.json"
        audio_out = argv[5] if len(argv) > 5 else None
        recv(int(bind_port), int(secs), out_json, audio_out)
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
