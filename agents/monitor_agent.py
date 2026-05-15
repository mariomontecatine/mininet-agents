import sys
import os
import time
import re
import json
import ollama
from datetime import datetime

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config
from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)

MODEL_NAME = config.MODEL_MONITOR
TMP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp"
)
os.makedirs(TMP_DIR, exist_ok=True)
HISTORY_FILE     = os.path.join(TMP_DIR, "network_history.json")
METRICS_FILE     = os.path.join(TMP_DIR, "metrics_history.json")
FLOWS_FILE       = os.path.join(TMP_DIR, "flows.json")
FLOW_ALERTS_FILE = os.path.join(TMP_DIR, "flow_alerts.jsonl")
HOST_PORT_FILE   = os.path.join(TMP_DIR, "host_port_map.json")


def _append_metrics(delta_stats):
    """Añade un snapshot de deltas a la serie temporal con clasificación de severidad."""
    severity = {}
    for port, vals in delta_stats.items():
        if vals.get("drop", 0) > 0:
            severity[port] = "critical"
        elif (vals.get("rx", 0) > config.UMBRAL_TRAFICO_BYTES
              or vals.get("tx", 0) > config.UMBRAL_TRAFICO_BYTES):
            severity[port] = "warn"
        elif vals.get("rx", 0) > 0 or vals.get("tx", 0) > 0:
            severity[port] = "normal"
        else:
            severity[port] = "idle"

    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "ports": delta_stats,
        "severity": severity,
    }
    history = []
    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE) as f:
                history = json.load(f)
        except (json.JSONDecodeError, IOError):
            history = []

    history.append(entry)
    if len(history) > config.METRICS_MAX_ENTRIES:
        history = history[-config.METRICS_MAX_ENTRIES:]

    with open(METRICS_FILE, "w") as f:
        json.dump(history, f)


def _load_flows():
    if not os.path.exists(FLOWS_FILE):
        return None
    try:
        with open(FLOWS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def _load_host_port_map():
    if not os.path.exists(HOST_PORT_FILE):
        return {}
    try:
        with open(HOST_PORT_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _record_flow_alert(rec):
    """Persiste cada anomalía detectada (fila JSONL) para el reporte posterior."""
    try:
        with open(FLOW_ALERTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except IOError:
        pass


def detect_flow_anomalies(flows, host_port):
    """
    Heurísticas sobre el snapshot live de flujos sFlow.
    Devuelve lista de dicts con tipo, host involucrado y puerto OVS.

    Tipos:
      - port_scan      : fan_out ≥ FAN_OUT_THRESHOLD
      - ddos_fanin     : fan_in  ≥ FAN_IN_THRESHOLD AND bytes ≥ FAN_IN_BYTES_THRESHOLD
      - dos_volumetric : un flujo individual ≥ SURGE_BYTES_THRESHOLD
    """
    if not flows:
        return []

    # IP → host name (inverso del host_port_map). Para mapping legible.
    ip_to_name = {}
    # Reconstruimos IP→name a partir de tmp/topology.json (más fiable que host_port_map).
    topo_path = os.path.join(TMP_DIR, "topology.json")
    if os.path.exists(topo_path):
        try:
            with open(topo_path, encoding="utf-8") as f:
                topo = json.load(f)
            for link in topo.get("links", []):
                a, b = str(link.get("from", "")), str(link.get("to", ""))
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", b) and not re.match(r"^\d+\.\d+\.\d+\.\d+$", a):
                    ip_to_name[b] = a
                elif re.match(r"^\d+\.\d+\.\d+\.\d+$", a) and not re.match(r"^\d+\.\d+\.\d+\.\d+$", b):
                    ip_to_name[a] = b
        except (json.JSONDecodeError, IOError):
            pass

    fan_out_dsts  = {}   # src_ip → set(dst_ip)
    fan_in_srcs   = {}   # dst_ip → set(src_ip)
    fan_in_bytes  = {}   # dst_ip → total bytes
    surge_flows   = []   # [(src, dst, bytes, pkts), ...]

    for f in flows:
        src = f.get("src", "")
        dst = f.get("dst", "")
        b   = f.get("bytes", 0)
        pkts= f.get("pkts", 0)
        fan_out_dsts.setdefault(src, set()).add(dst)
        fan_in_srcs.setdefault(dst, set()).add(src)
        fan_in_bytes[dst] = fan_in_bytes.get(dst, 0) + b
        if b >= config.SURGE_BYTES_THRESHOLD:
            surge_flows.append((src, dst, b, pkts))

    alerts = []
    ts = datetime.now().isoformat(timespec="seconds")

    for src_ip, dsts in fan_out_dsts.items():
        if len(dsts) >= config.FAN_OUT_THRESHOLD:
            host = ip_to_name.get(src_ip, src_ip)
            alerts.append({
                "type":    "port_scan",
                "host":    host,
                "host_ip": src_ip,
                "port":    host_port.get(host),
                "dsts":    len(dsts),
                "ts":      ts,
            })

    for dst_ip, srcs in fan_in_srcs.items():
        if (len(srcs) >= config.FAN_IN_THRESHOLD
                and fan_in_bytes.get(dst_ip, 0) >= config.FAN_IN_BYTES_THRESHOLD):
            host = ip_to_name.get(dst_ip, dst_ip)
            alerts.append({
                "type":    "ddos_fanin",
                "host":    host,
                "host_ip": dst_ip,
                "port":    host_port.get(host),
                "srcs":    len(srcs),
                "bytes":   fan_in_bytes[dst_ip],
                "ts":      ts,
            })

    for src_ip, dst_ip, b, pkts in surge_flows:
        src_host = ip_to_name.get(src_ip, src_ip)
        dst_host = ip_to_name.get(dst_ip, dst_ip)
        alerts.append({
            "type":     "dos_volumetric",
            "host":     src_host,
            "host_ip":  src_ip,
            "port":     host_port.get(src_host),
            "victim":   dst_host,
            "victim_ip":dst_ip,
            "bytes":    b,
            "pkts":     pkts,
            "ts":       ts,
        })

    return alerts


def _format_anomaly_lines(alerts):
    """Convierte alertas a líneas con formato 'Port sX-ethY: ...' para que el resolver las capture."""
    lines = []
    for a in alerts:
        port = a.get("port") or "s?-eth?"
        if a["type"] == "port_scan":
            line = (f"🟠 [ESCANEO] Port {port}: origen={a['host']} ({a['host_ip']}), "
                    f"{a['dsts']} destinos en ventana [posible port scan]")
        elif a["type"] == "ddos_fanin":
            line = (f"🟠 [FAN-IN] Port {port}: víctima={a['host']} ({a['host_ip']}) ← "
                    f"{a['srcs']} orígenes, {format_bytes(a['bytes'])} combinados [posible DDoS]")
        elif a["type"] == "dos_volumetric":
            line = (f"🟠 [DoS] Port {port}: {a['host']}→{a['victim']} "
                    f"({format_bytes(a['bytes'])}) [flujo volumétrico anómalo]")
        else:
            continue
        lines.append(line)
    return lines


def format_bytes(size):
    """Convierte bytes a formato legible (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def parse_telemetry_to_dict(raw_output):
    """Convierte el texto sucio de dpctl en un diccionario estructurado, ignorando puertos inútiles."""
    stats = {}
    current_port = None

    lines = raw_output.split("\n")
    for line in lines:
        line = line.strip()

        # 1. Detectar la línea de recepción (rx) y sacar el nombre exacto
        if line.startswith("port ") and "rx pkts" in line:
            p_match = re.search(r'port\s+["\']?([a-zA-Z0-9_-]+)["\']?:', line)
            if p_match:
                name = p_match.group(1)

                # LA MAGIA: Si el puerto es LOCAL, lo ignoramos por completo
                if "LOCAL" in name:
                    current_port = None
                    continue

                current_port = name

                if current_port not in stats:
                    stats[current_port] = {"rx_bytes": 0, "tx_bytes": 0, "drop": 0}

                rx_b = re.search(r"bytes=(\d+)", line)
                drop_rx = re.search(r"drop=(\d+)", line)

                if rx_b:
                    stats[current_port]["rx_bytes"] = int(rx_b.group(1))
                if drop_rx:
                    stats[current_port]["drop"] += int(drop_rx.group(1))

        # 2. Detectar la línea de transmisión (tx)
        elif line.startswith("tx pkts") and current_port:
            tx_b = re.search(r"bytes=(\d+)", line)
            drop_tx = re.search(r"drop=(\d+)", line)

            if tx_b:
                stats[current_port]["tx_bytes"] = int(tx_b.group(1))
            if drop_tx:
                stats[current_port]["drop"] += int(drop_tx.group(1))

    return stats


def calculate_delta(current_stats):
    """Calcula la diferencia entre los datos actuales y los guardados."""
    delta_stats = {}

    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            old_stats = json.load(f)
    else:
        old_stats = {}

    for port, data in current_stats.items():
        if port in old_stats:
            # Calculamos la diferencia (Delta)
            d_rx = max(0, data["rx_bytes"] - old_stats[port]["rx_bytes"])
            d_tx = max(0, data["tx_bytes"] - old_stats[port]["tx_bytes"])
            d_dr = max(0, data["drop"] - old_stats[port]["drop"])

            delta_stats[port] = {"rx": d_rx, "tx": d_tx, "drop": d_dr}
        else:
            # FIX: Si es la primera vez, el delta es el valor actual absoluto (porque partimos de 0)
            delta_stats[port] = {
                "rx": data["rx_bytes"],
                "tx": data["tx_bytes"],
                "drop": data["drop"],
            }

    # Guardamos los actuales como referencia para la próxima vez
    with open(HISTORY_FILE, "w") as f:
        json.dump(current_stats, f)

    return delta_stats


def collect_telemetry():
    print("\n[SENSOR] Recolectando telemetría en tiempo real (Modo Delta)...")
    try:
        ssh = get_ssh_connection()
        send_tmux_command(ssh, "dpctl dump-ports")
        wait_for_mininet_prompt(ssh, timeout=15)
        raw_output = capture_tmux_output(ssh)
        ssh.close()

        # 1. Convertir a datos numéricos
        current_data = parse_telemetry_to_dict(raw_output)

        # 2. Calcular cuánto ha cambiado
        deltas = calculate_delta(current_data)

        # 2b. Persistir serie temporal (solo puertos con actividad)
        active = {p: v for p, v in deltas.items() if v["rx"] or v["tx"] or v["drop"]}
        if active:
            _append_metrics(active)

        # 3. Formatear para la IA
        important_lines = []
        if "Results:" in raw_output:
            res = re.search(r"Results:.*", raw_output)
            if res:
                important_lines.append(f">>> CONECTIVIDAD: {res.group(0)}")

        for port, val in deltas.items():
            if val["rx"] == 0 and val["tx"] == 0 and val["drop"] == 0:
                continue

            # USAMOS LA NUEVA FUNCIÓN PARA HUMANIZAR LOS NÚMEROS
            rx_str = format_bytes(val["rx"])
            tx_str = format_bytes(val["tx"])

            line = f"Port {port}: rx_delta={rx_str}, tx_delta={tx_str}, drop_delta={val['drop']}"

            if val["drop"] > 0:
                line = f"🔴 [ALERTA ROJA] {line} <-- ¡PÉRDIDA ACTIVA!"
            if val["rx"] > config.UMBRAL_TRAFICO_BYTES or val["tx"] > config.UMBRAL_TRAFICO_BYTES:
                line = f"⚠️ [TRÁFICO INTENSO] {line} <-- FLUJO ALTO DETECTADO"

            important_lines.append(line)

        # ── Capa de flujos sFlow: heurísticas de anomalía ────────────────────
        snapshot = _load_flows()
        if snapshot and snapshot.get("flows"):
            host_port = _load_host_port_map()
            anomaly_alerts = detect_flow_anomalies(snapshot["flows"], host_port)
            for a in anomaly_alerts:
                _record_flow_alert(a)
            extra = _format_anomaly_lines(anomaly_alerts)
            if extra:
                important_lines.extend(extra)

        return "\n".join(important_lines)

    except Exception as e:
        print(f"Error crítico en el sensor: {e}")
        return None


def generate_network_report(filtered_telemetry):
    print("\n[IA] Analizando deltas de tráfico...")

    if not filtered_telemetry or not filtered_telemetry.strip():
        return "Red estable. No se detectó tráfico significativo ni pérdidas de paquetes en este ciclo."

    system_prompt = (
        "Eres un Analista Senior de Redes (NOC). Responde SOLO con el diagnóstico, "
        "sin repetir instrucciones ni usar markdown.\n"
        "Se te dan estadísticas DELTA de los últimos segundos.\n"
        "REGLAS:\n"
        "1. Identifica los puertos con [ALERTA ROJA] (pérdidas), [TRÁFICO INTENSO] (>10 MB), "
        "[ESCANEO] (port scan: 1 origen→muchos destinos), [FAN-IN] (DDoS coordinado) "
        "o [DoS] (flujo volumétrico anómalo).\n"
        "2. Nombra cada puerto exactamente como aparece en los datos (ej: s1-eth2).\n"
        "3. Para [ESCANEO]/[FAN-IN]/[DoS] menciona también el host origen o víctima por su nombre.\n"
        "4. Si todo está dentro de lo normal, escribe exactamente: 'Red estable.'\n"
        "5. Máximo 5 líneas."
    )

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"ESTADÍSTICAS DELTA:\n{filtered_telemetry}"},
        ],
        options={"temperature": 0},
    )
    result = response["message"]["content"].strip()

    # Fallback: si el LLM ignora el prompt y devuelve texto genérico (markdown, listas, etc.),
    # construimos el informe directamente desde la telemetría ya clasificada.
    alerted = re.findall(
        r"(?:ALERTA ROJA|TRÁFICO INTENSO|ESCANEO|FAN-IN|DoS).*?(s\d+-eth\d+)",
        filtered_telemetry,
    )
    if alerted and not any(p in result for p in alerted):
        ports_str = ", ".join(dict.fromkeys(alerted))
        result = f"ANOMALÍA detectada en: {ports_str}"

    return result


def run_monitor_agent():
    print("=== AGENTE MONITOR PRO (Con Memoria de Estado) ===")
    telemetry = collect_telemetry()

    if not telemetry:
        print("Error: No se pudo obtener telemetría.")
        return

    print("\n--- TELEMETRÍA DELTA PARA LA IA ---")
    print(telemetry)

    report = generate_network_report(telemetry)

    with open(os.path.join(TMP_DIR, "ultimo_informe.txt"), "w", encoding="utf-8") as f:
        f.write(report)

    print("\n================ INFORME DE LA IA ================")
    print(report)
    print("==================================================")


if __name__ == "__main__":
    run_monitor_agent()
