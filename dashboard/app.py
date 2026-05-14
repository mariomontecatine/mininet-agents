import os
import json
import logging
import threading
from collections import defaultdict

from flask import Flask, jsonify, render_template

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


@app.route("/api/qos/history")
def api_qos_history():
    """Historial de eventos QoS para el timeline (últimos 200 eventos)."""
    history = _load_json("qos_history.json", [])
    return jsonify(history[-200:])


@app.route("/api/live-metrics")
def api_live_metrics():
    """Serie temporal por puerto desde live_metrics.json (muestras cada ~5s)."""
    history = _load_json("live_metrics.json", [])[-60:]
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
    """Serie temporal agregada por switch desde live_metrics.json (muestras cada ~5s)."""
    history = _load_json("live_metrics.json", [])[-60:]
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
