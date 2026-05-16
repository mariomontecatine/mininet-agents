import os
import re
import json
import time
import logging
import threading
from collections import defaultdict
from datetime import datetime

from flask import Flask, jsonify, render_template, request

_IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP_DIR = os.path.join(_PROJECT_ROOT, "tmp")

app = Flask(__name__)


# ── helpers ──────────────────────────────────────────────────────────────────

def _load_json(filename, default):
    path = os.path.join(_TMP_DIR, filename)
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return default


def _pad_series(series, target_len):
    """Rellena con ceros por la izquierda si la serie es más corta que target_len."""
    pad = target_len - len(series)
    return [0] * pad + series if pad > 0 else series


# ── páginas ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/topology")
def topology_page():
    topo_path = os.path.join(_TMP_DIR, "topologia_interactiva.html")
    if not os.path.exists(topo_path):
        return (
            "<body style='background:#0d1117;color:#8b949e;font-family:monospace;"
            "display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
            "Topología no disponible aún — arranca el supervisor primero.</body>"
        )
    with open(topo_path, encoding="utf-8") as f:
        return f.read()


# ── APIs ─────────────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    state = _load_json("state.json", {})
    log_lines = []
    log_path = os.path.join(_TMP_DIR, "noc_audit.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, encoding="utf-8") as f:
                log_lines = [l.rstrip() for l in f.readlines()[-60:]]
        except IOError:
            pass
    return jsonify({**state, "log_lines": log_lines})


@app.route("/api/topology-ready")
def api_topology_ready():
    ready = os.path.exists(os.path.join(_TMP_DIR, "topologia_interactiva.html"))
    return jsonify({"ready": ready})


@app.route("/api/metrics")
def api_metrics():
    """Serie temporal por puerto individual (para drill-down)."""
    history = _load_json("metrics_history.json", [])
    if not history:
        return jsonify({"labels": [], "ports": {}})

    labels = [e["ts"].split("T")[-1] for e in history]
    ports: dict = {}
    n = len(labels)

    for entry in history:
        for port, vals in entry.get("ports", {}).items():
            if port not in ports:
                ports[port] = {"rx": [], "tx": [], "drop": []}
            ports[port]["rx"].append(vals.get("rx", 0))
            ports[port]["tx"].append(vals.get("tx", 0))
            ports[port]["drop"].append(vals.get("drop", 0))

    for port_data in ports.values():
        for key in ("rx", "tx", "drop"):
            ports_series = port_data[key]
            pad = n - len(ports_series)
            if pad > 0:
                port_data[key] = [0] * pad + ports_series

    return jsonify({"labels": labels, "ports": ports})


@app.route("/api/metrics/switch")
def api_metrics_switch():
    """Serie temporal agregada por switch (s1, s2, s3…)."""
    history = _load_json("metrics_history.json", [])
    if not history:
        return jsonify({"labels": [], "switches": {}})

    labels = [e["ts"].split("T")[-1] for e in history]
    switches: dict = {}

    for entry in history:
        sw_agg = defaultdict(lambda: {"rx": 0, "tx": 0, "drop": 0})
        for port, vals in entry.get("ports", {}).items():
            sw = port.split("-")[0]
            sw_agg[sw]["rx"]   += vals.get("rx", 0)
            sw_agg[sw]["tx"]   += vals.get("tx", 0)
            sw_agg[sw]["drop"] += vals.get("drop", 0)
        for sw, agg in sw_agg.items():
            if sw not in switches:
                switches[sw] = {"rx": [], "tx": [], "drop": []}
            switches[sw]["rx"].append(agg["rx"])
            switches[sw]["tx"].append(agg["tx"])
            switches[sw]["drop"].append(agg["drop"])

    n = len(labels)
    for sw_data in switches.values():
        for key in ("rx", "tx", "drop"):
            sw_data[key] = _pad_series(sw_data[key], n)

    return jsonify({"labels": labels, "switches": switches})


@app.route("/api/top-talkers")
def api_top_talkers():
    """Top-5 puertos por tráfico total (rx+tx) en el último ciclo."""
    history = _load_json("metrics_history.json", [])
    if not history:
        return jsonify([])

    last = history[-1]
    severity_map = last.get("severity", {})
    ports = last.get("ports", {})

    ranked = sorted(
        ports.items(),
        key=lambda kv: kv[1].get("rx", 0) + kv[1].get("tx", 0),
        reverse=True,
    )[:5]

    result = [
        {
            "port":     port,
            "rx":       vals.get("rx", 0),
            "tx":       vals.get("tx", 0),
            "drop":     vals.get("drop", 0),
            "severity": severity_map.get(port, "normal"),
        }
        for port, vals in ranked
    ]
    return jsonify(result)


@app.route("/api/alerts")
def api_alerts():
    """
    Matriz de severidad para el heatmap.
    Devuelve las últimas 40 entradas como:
      {labels: [ts, ...], ports: [port, ...], matrix: [[sev, ...], ...]}
    matrix[i][j] = severidad del puerto i en el ciclo j
    """
    history = _load_json("metrics_history.json", [])
    if not history:
        return jsonify({"labels": [], "ports": [], "matrix": []})

    window = history[-40:]
    labels = [e["ts"].split("T")[-1] for e in window]

    # Collect all known ports (order by most activity)
    port_activity: dict[str, int] = defaultdict(int)
    for entry in window:
        for port, vals in entry.get("ports", {}).items():
            port_activity[port] += vals.get("rx", 0) + vals.get("tx", 0)

    sorted_ports = sorted(port_activity, key=lambda p: port_activity[p], reverse=True)

    sev_to_int = {"critical": 3, "warn": 2, "normal": 1, "idle": 0}

    matrix = []
    for port in sorted_ports:
        row = []
        for entry in window:
            sev = entry.get("severity", {}).get(port, "idle")
            row.append(sev_to_int.get(sev, 0))
        matrix.append(row)

    return jsonify({"labels": labels, "ports": sorted_ports, "matrix": matrix})


def _build_host_map():
    """Devuelve dict {ip: nombre_host} a partir de tmp/topology.json.

    topology.json se genera tras cada despliegue (agents/topology.py) y
    contiene links {from, to} donde una de las puntas es un nombre de host
    y la otra una IP. Aquí filtramos esos pares y construimos el reverso.
    """
    topo = _load_json("topology.json", {})
    mapping = {}
    for link in topo.get("links", []):
        a = str(link.get("from", ""))
        b = str(link.get("to", ""))
        if _IP_RE.match(b) and not _IP_RE.match(a):
            mapping[b] = a
        elif _IP_RE.match(a) and not _IP_RE.match(b):
            mapping[a] = b
    return mapping


def _enrich(flows, host_map):
    if not host_map:
        return flows
    for f in flows:
        f["src_name"] = host_map.get(f.get("src", ""), f.get("src", ""))
        f["dst_name"] = host_map.get(f.get("dst", ""), f.get("dst", ""))
    return flows


@app.route("/api/flows/history")
def api_flows_history():
    """
    Agrega los delta_flows persistidos por el supervisor sobre los últimos
    `window` segundos. Sin doble conteo: los deltas son no solapados.

    Query params:
      window: tamaño de la ventana en segundos (default 300, máx 3600).

    Respuesta (shape compatible con /api/flows):
      {ts, window_sec, datagrams, samples, flows: [{src, dst, src_name,
       dst_name, bytes, pkts}, ...]}
    """
    try:
        window = int(request.args.get("window", 300))
    except (TypeError, ValueError):
        window = 300
    window = max(30, min(window, 3600))

    history = _load_json("flows_history.json", [])
    if not history:
        return jsonify({"ts": None, "window_sec": window, "datagrams": 0,
                        "samples": 0, "flows": []})

    # Las entradas tienen ts ISO; trabajamos por índice porque los samples
    # son cada 5 s aprox. Tomamos los últimos ceil(window/5) entries.
    estimated = max(1, window // 5)
    window_entries = history[-estimated:]
    if not window_entries:
        return jsonify({"ts": None, "window_sec": window, "datagrams": 0,
                        "samples": 0, "flows": []})

    agg_bytes = defaultdict(int)
    agg_pkts  = defaultdict(int)
    datagrams_first = window_entries[0].get("datagrams", 0)
    datagrams_last  = window_entries[-1].get("datagrams", 0)
    for entry in window_entries:
        for f in entry.get("delta_flows", []):
            key = (f.get("src", ""), f.get("dst", ""))
            agg_bytes[key] += f.get("bytes", 0)
            agg_pkts[key]  += f.get("pkts", 0)

    ranked = sorted(agg_bytes.items(), key=lambda x: x[1], reverse=True)[:20]
    flows = [
        {"src": k[0], "dst": k[1], "bytes": v, "pkts": agg_pkts[k]}
        for k, v in ranked
    ]
    _enrich(flows, _build_host_map())

    return jsonify({
        "ts":         window_entries[-1].get("ts"),
        "window_sec": window,
        "datagrams":  max(0, datagrams_last - datagrams_first),
        "samples":    len(window_entries),
        "flows":      flows,
    })


@app.route("/api/flows")
def api_flows():
    """
    Flujos extremo a extremo agregados por (src_ip, dst_ip) sobre la ventana
    deslizante del daemon sFlow. Top N ya ordenado por bytes desc.

    Enriquece cada flujo con src_name/dst_name si la topología los conoce
    (cae al string IP si no hay mapping).

    Estructura: {ts, window_sec, datagrams, flows: [{src, dst, src_name,
    dst_name, bytes, pkts}, ...]}
    """
    snapshot = _load_json("flows.json", {})
    if not snapshot:
        return jsonify({"ts": None, "window_sec": 0, "datagrams": 0, "flows": []})

    _enrich(snapshot.get("flows", []), _build_host_map())
    return jsonify(snapshot)


def _describe_actor(inj):
    t = inj.get("type")
    if t in ("port_scan", "dos_volumetric"):
        return inj.get("attacker", "?")
    if t == "ddos_fanin":
        return ",".join(inj.get("attackers", []) or []) or "?"
    return "?"


def _describe_target(inj):
    t = inj.get("type")
    if t == "port_scan":
        n = len(inj.get("victims", []) or [])
        return f"{n} destinos"
    return inj.get("victim", "?")


def _alert_matches_injection(alert, injections, ar):
    """
    Una heurística cuenta como TP si dispara dentro de la ventana de alguna
    inyección Y el host involucrado pertenece a ella (atacante o víctima).
    """
    ts = ar._parse_iso(alert.get("ts"))
    if ts is None:
        return False
    alert_host = alert.get("host") or alert.get("host_ip")
    for inj in injections:
        if not ar._within(inj, ts):
            continue
        hosts = set(ar._attacker_hosts(inj))
        if alert_host and alert_host in hosts:
            return True
    return False


def _qos_apply_matches_injection(ev, injections, ar):
    """
    Una acción QoS 'apply' cuenta como TP si actúa sobre un puerto del
    atacante/víctima de alguna inyección activa.
    """
    if ev.get("event") != "apply":
        return None  # eventos relax/remove no entran en la matriz
    ts = ar._parse_iso(ev.get("ts"))
    port = ev.get("port")
    if ts is None or not port:
        return False
    for inj in injections:
        if not ar._within(inj, ts):
            continue
        if port in set(ar._attacker_ports(inj)):
            return True
    return False


def _f1(precision, recall):
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


@app.route("/api/security")
def api_security():
    """
    Vista live del subsistema de detección de anomalías.

    Devuelve:
      scorecard: agregados (total, detected, mitigated, rates, by_type)
      active:    ataques cuyo intervalo [ts_start, ts_end_planned] cubre ahora
      recent:    últimos 20 ataques con su estado actual
      alerts:    últimas 10 heurísticas disparadas (deduplicadas por type+host)
    """
    # Lazy import — evita que la importación del módulo Flask requiera
    # agents/anomaly_report al instante.
    from agents import anomaly_report as ar

    injections  = ar._load_jsonl(ar.INJECTION_LOG)
    qos_events  = ar._load_json(ar.QOS_HISTORY, [])
    flow_alerts = ar._load_jsonl(ar.FLOW_ALERTS)
    audit_lines = ar._read_audit_lines()

    now = time.time()

    enriched = []
    for inj in injections:
        start = inj.get("ts_start_epoch") or ar._parse_iso(inj.get("ts_start"))
        if start is None:
            continue
        end_planned = ar._parse_iso(inj.get("ts_end_planned")) or (
            start + inj.get("duration_sec", 60))

        cls = ar.classify_injection(inj, qos_events, flow_alerts, audit_lines)

        if start <= now <= end_planned:
            status = "in_progress"
        elif cls["signals"].get("resolver"):
            status = "mitigated"
        elif cls["detected"]:
            status = "detected_only"
        else:
            # Sin detección y dentro del grace: aún podría llegar
            if now <= end_planned + ar.GRACE_SEC:
                status = "in_progress"
            else:
                status = "missed"

        detected_by = [k for k, v in cls["signals"].items() if v]

        enriched.append({
            "id":          inj.get("id"),
            "type":        inj.get("type"),
            "ts_start":    inj.get("ts_start"),
            "ts_epoch":    start,
            "duration":    inj.get("duration_sec"),
            "elapsed":     max(0, min(now, end_planned) - start),
            "actor":       _describe_actor(inj),
            "target":      _describe_target(inj),
            "status":      status,
            "detected_by": detected_by,
            "lag":         cls["first_detection_lag_sec"],
            "resolver":    cls["signals"].get("resolver"),
        })

    # Orden cronológico inverso (más reciente primero)
    enriched.sort(key=lambda e: e["ts_epoch"], reverse=True)

    # Scorecard
    total       = len(enriched)
    mitigated   = sum(1 for e in enriched if e["status"] == "mitigated")
    detected    = sum(1 for e in enriched if e["status"] in ("mitigated", "detected_only"))
    in_progress = sum(1 for e in enriched if e["status"] == "in_progress")
    missed      = sum(1 for e in enriched if e["status"] == "missed")

    by_type = {}
    for t in ("port_scan", "dos_volumetric", "ddos_fanin"):
        items = [e for e in enriched if e["type"] == t]
        by_type[t] = {
            "total":     len(items),
            "detected":  sum(1 for e in items if e["status"] in ("mitigated","detected_only")),
            "mitigated": sum(1 for e in items if e["status"] == "mitigated"),
        }

    # ── Matriz de confusión a nivel de evento ──────────────────────────────
    # Cada heurística disparada es UN evento; cada acción QoS 'apply' también.
    # Si solapa con alguna inyección y entidades coinciden → TP, si no → FP.
    # FN se hereda del scorecard a nivel de inyección (missed).

    heur_tp = sum(1 for a in flow_alerts if _alert_matches_injection(a, injections, ar))
    heur_fp = max(0, len(flow_alerts) - heur_tp)

    apply_events = [e for e in qos_events if e.get("event") == "apply"]
    res_tp = sum(1 for e in apply_events if _qos_apply_matches_injection(e, injections, ar))
    res_fp = max(0, len(apply_events) - res_tp)

    heur_precision = heur_tp / (heur_tp + heur_fp) if (heur_tp + heur_fp) else 0.0
    res_precision  = res_tp  / (res_tp  + res_fp)  if (res_tp  + res_fp ) else 0.0
    # Recall a nivel inyección (cuántos ataques fueron detectados/mitigados)
    recall_detection  = (detected  / total) if total else 0.0
    recall_mitigation = (mitigated / total) if total else 0.0

    metrics = {
        "heuristic": {
            "tp":        heur_tp,
            "fp":        heur_fp,
            "total":     len(flow_alerts),
            "precision": round(heur_precision, 3),
            "recall":    round(recall_detection, 3),
            "f1":        round(_f1(heur_precision, recall_detection), 3),
        },
        "resolver": {
            "tp":        res_tp,
            "fp":        res_fp,
            "total":     len(apply_events),
            "precision": round(res_precision, 3),
            "recall":    round(recall_mitigation, 3),
            "f1":        round(_f1(res_precision, recall_mitigation), 3),
        },
        "confusion": {
            "tp_injections":  detected,
            "fn_injections":  missed,
            "fp_heuristic":   heur_fp,
            "fp_resolver":    res_fp,
        },
    }

    # Últimas heurísticas (deduplicadas) con flag tp/fp para el dashboard
    seen = set()
    recent_alerts = []
    for a in reversed(flow_alerts):
        key = (a.get("type"), a.get("host"))
        if key in seen:
            continue
        seen.add(key)
        recent_alerts.append({
            "ts":     a.get("ts"),
            "type":   a.get("type"),
            "host":   a.get("host"),
            "port":   a.get("port"),
            "is_tp":  _alert_matches_injection(a, injections, ar),
        })
        if len(recent_alerts) >= 10:
            break

    return jsonify({
        "scorecard": {
            "total":           total,
            "detected":        detected,
            "mitigated":       mitigated,
            "in_progress":     in_progress,
            "missed":          missed,
            "detection_rate":  (detected / total) if total else 0,
            "mitigation_rate": (mitigated / total) if total else 0,
            "by_type":         by_type,
        },
        "metrics": metrics,
        "active":  [e for e in enriched if e["status"] == "in_progress"],
        "recent":  enriched[:20],
        "alerts":  recent_alerts,
    })


@app.route("/api/qos/history")
def api_qos_history():
    """Historial de eventos QoS para el timeline (últimos 200 eventos)."""
    history = _load_json("qos_history.json", [])
    return jsonify(history[-200:])


@app.route("/api/live-metrics")
def api_live_metrics():
    """Serie temporal por puerto desde live_metrics.json (muestras cada ~5s).

    Query param `limit` (default 60, máx 2000): nº de muestras devueltas.
    """
    try:
        limit = int(request.args.get("limit", 60))
    except (TypeError, ValueError):
        limit = 60
    limit = max(10, min(limit, 2000))
    history = _load_json("live_metrics.json", [])[-limit:]
    if not history:
        return jsonify({"labels": [], "ports": {}})

    labels = [e["ts"].split("T")[-1] for e in history]
    ports: dict = {}
    n = len(labels)

    for entry in history:
        for port, vals in entry.get("ports", {}).items():
            if port not in ports:
                ports[port] = {"rx": [], "tx": [], "drop": []}
            ports[port]["rx"].append(vals.get("rx", 0))
            ports[port]["tx"].append(vals.get("tx", 0))
            ports[port]["drop"].append(vals.get("drop", 0))

    for port_data in ports.values():
        for key in ("rx", "tx", "drop"):
            pad = n - len(port_data[key])
            if pad > 0:
                port_data[key] = [0] * pad + port_data[key]

    return jsonify({"labels": labels, "ports": ports})


@app.route("/api/live-metrics/switch")
def api_live_metrics_switch():
    """Serie temporal agregada por switch desde live_metrics.json (muestras cada ~5s).

    Query param `limit` (default 60, máx 2000): nº de muestras devueltas.
    """
    try:
        limit = int(request.args.get("limit", 60))
    except (TypeError, ValueError):
        limit = 60
    limit = max(10, min(limit, 2000))
    history = _load_json("live_metrics.json", [])[-limit:]
    if not history:
        return jsonify({"labels": [], "switches": {}})

    labels = [e["ts"].split("T")[-1] for e in history]
    switches: dict = {}

    for entry in history:
        sw_agg = defaultdict(lambda: {"rx": 0, "tx": 0, "drop": 0})
        for port, vals in entry.get("ports", {}).items():
            sw = port.split("-")[0]
            sw_agg[sw]["rx"]   += vals.get("rx", 0)
            sw_agg[sw]["tx"]   += vals.get("tx", 0)
            sw_agg[sw]["drop"] += vals.get("drop", 0)
        for sw, agg in sw_agg.items():
            if sw not in switches:
                switches[sw] = {"rx": [], "tx": [], "drop": []}
            switches[sw]["rx"].append(agg["rx"])
            switches[sw]["tx"].append(agg["tx"])
            switches[sw]["drop"].append(agg["drop"])

    n = len(labels)
    for sw_data in switches.values():
        for key in ("rx", "tx", "drop"):
            sw_data[key] = _pad_series(sw_data[key], n)

    return jsonify({"labels": labels, "switches": switches})


# ── servidor ──────────────────────────────────────────────────────────────────

def _silence_werkzeug():
    try:
        import flask.cli as _fc
        _fc.show_server_banner = lambda *a, **kw: None
    except Exception:
        pass
    _wz = logging.getLogger("werkzeug")
    _wz.setLevel(logging.ERROR)
    _wz.disabled = True


def start_dashboard(port: int = 5000) -> threading.Thread:
    _silence_werkzeug()

    def _run():
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

    t = threading.Thread(target=_run, daemon=True, name="noc-dashboard")
    t.start()
    return t


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
