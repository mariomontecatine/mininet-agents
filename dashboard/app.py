import os
import json
import logging
import threading

from flask import Flask, jsonify, render_template

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP_DIR = os.path.join(_PROJECT_ROOT, "tmp")

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    state_file = os.path.join(_TMP_DIR, "state.json")
    state = {}
    if os.path.exists(state_file):
        try:
            with open(state_file, encoding="utf-8") as f:
                state = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    log_lines = []
    for log_name in ("noc_audit.log",):
        log_path = os.path.join(_TMP_DIR, log_name)
        if os.path.exists(log_path):
            try:
                with open(log_path, encoding="utf-8") as f:
                    log_lines = [l.rstrip() for l in f.readlines()[-50:]]
            except IOError:
                pass

    return jsonify({**state, "log_lines": log_lines})


@app.route("/api/metrics")
def api_metrics():
    metrics_path = os.path.join(_TMP_DIR, "metrics_history.json")
    if not os.path.exists(metrics_path):
        return jsonify({"labels": [], "ports": {}})

    try:
        with open(metrics_path, encoding="utf-8") as f:
            history = json.load(f)
    except (json.JSONDecodeError, IOError):
        return jsonify({"labels": [], "ports": {}})

    if not history:
        return jsonify({"labels": [], "ports": {}})

    labels = [e["ts"].split("T")[-1] for e in history]
    ports: dict = {}

    for entry in history:
        for port, vals in entry.get("ports", {}).items():
            if port not in ports:
                ports[port] = {"rx": [], "tx": [], "drop": []}
            ports[port]["rx"].append(vals.get("rx", 0))
            ports[port]["tx"].append(vals.get("tx", 0))
            ports[port]["drop"].append(vals.get("drop", 0))

    # Rellenar con ceros los puertos que no aparecieron en todos los ciclos
    n = len(labels)
    for port_data in ports.values():
        for key in ("rx", "tx", "drop"):
            pad = n - len(port_data[key])
            if pad > 0:
                port_data[key] = [0] * pad + port_data[key]

    return jsonify({"labels": labels, "ports": ports})


@app.route("/api/topology-ready")
def api_topology_ready():
    ready = os.path.exists(os.path.join(_TMP_DIR, "topologia_interactiva.html"))
    return jsonify({"ready": ready})


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


def _silence_werkzeug():
    """Suprime el banner de arranque de Flask/werkzeug antes de lanzar el servidor."""
    # El banner (Serving Flask app / Debug mode) viene de flask.cli.show_server_banner
    # que usa click.echo() directo a stdout, sin pasar por el sistema de logging.
    try:
        import flask.cli as _fc
        _fc.show_server_banner = lambda *a, **kw: None
    except Exception:
        pass
    # Silenciar también el logger de werkzeug (accesos HTTP, etc.)
    _wz = logging.getLogger("werkzeug")
    _wz.setLevel(logging.ERROR)
    _wz.disabled = True


def start_dashboard(port: int = 5000) -> threading.Thread:
    """Lanza el servidor Flask en un hilo daemon y devuelve el hilo."""
    _silence_werkzeug()

    def _run():
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

    t = threading.Thread(target=_run, daemon=True, name="noc-dashboard")
    t.start()
    return t


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
