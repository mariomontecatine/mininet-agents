"""Identificación automática del tráfico por host, a partir de lo OBSERVADO.

Realista, sin "trampas": clasifica los flujos que sFlow ya muestrea en los
bridges (tmp/flows.json) por su par (ip_proto, puerto de servicio) — igual que
un router con NetFlow/sFlow. No hay DPI ni acceso privilegiado a la simulación.

Sirve a dos cosas:
  1. Un panel "¿qué hace cada host?" en el dashboard.
  2. Justificar la QoS automática: si se detecta VoIP (RTP) cruzando la red,
     tiene sentido priorizarlo en el router central.

Limitación honesta (heredada de apps_catalog): sin DPI mapeamos por puerto, así
que "youtube" se infiere por HTTPS/443, etc. Los flujos en puertos no catalogados
se agrupan como "otro".
"""

import json
import os
import re

from utils import config
from agents import apps_catalog
from agents.monitor_agent import _proto_to_service

TMP_DIR    = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
FLOWS_FILE = os.path.join(TMP_DIR, "flows.json")
TOPO_FILE  = os.path.join(TMP_DIR, "topology.json")

_IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

# service → app_id (cada app del catálogo usa un service distinto).
_SERVICE_TO_APP = {meta["service"]: app_id
                   for app_id, meta in apps_catalog.APPLICATIONS.items()}


def _build_ip_to_host(topo_path=TOPO_FILE):
    """Mapa IP → nombre de host a partir de topology.json (pseudo-links host→ip)."""
    if not os.path.exists(topo_path):
        return {}
    try:
        with open(topo_path, encoding="utf-8") as f:
            topo = json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}
    ip2host = {}
    for l in topo.get("links", []):
        frm, to = l.get("from"), l.get("to")
        if to and _IP_RE.match(str(to)) and frm and not _IP_RE.match(str(frm)):
            ip2host[to] = frm
    return ip2host


def identify_from_flows(flows_path=FLOWS_FILE, topo_path=TOPO_FILE, min_bytes=0):
    """Clasifica los flujos de la ventana sFlow y agrega por host de origen.

    Devuelve:
      {
        "hosts": {
           "h1": {"apps": {"voip": {"bytes":..,"pkts":..,"dsts":[..]}, ...},
                  "total_bytes": ..},
           ...
        },
        "detected_apps": ["voip", "web_browsing", ...],   # union global
        "ts": <ts de la ventana>,
      }
    """
    out = {"hosts": {}, "detected_apps": [], "ts": None}
    if not os.path.exists(flows_path):
        return out
    try:
        with open(flows_path, encoding="utf-8") as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError):
        return out

    out["ts"] = data.get("ts")
    ip2host = _build_ip_to_host(topo_path)
    detected = set()

    for fl in data.get("flows", []):
        if fl.get("bytes", 0) < min_bytes:
            continue
        svc = _proto_to_service(fl.get("proto"), fl.get("dport"))
        label = _SERVICE_TO_APP.get(svc) or svc or "otro"
        src = fl.get("src")
        src_host = ip2host.get(src, src)
        dst = fl.get("dst")
        dst_host = ip2host.get(dst, dst)

        host_entry = out["hosts"].setdefault(src_host, {"apps": {}, "total_bytes": 0})
        app_entry = host_entry["apps"].setdefault(
            label, {"bytes": 0, "pkts": 0, "dsts": set(), "service": svc})
        app_entry["bytes"] += fl.get("bytes", 0)
        app_entry["pkts"]  += fl.get("pkts", 0)
        app_entry["dsts"].add(dst_host)
        host_entry["total_bytes"] += fl.get("bytes", 0)
        if label in _SERVICE_TO_APP.values():
            detected.add(label)

    # Serializa sets → listas ordenadas y ordena apps por bytes desc.
    for host, he in out["hosts"].items():
        for label, ae in he["apps"].items():
            ae["dsts"] = sorted(ae["dsts"])
        he["apps"] = dict(sorted(he["apps"].items(),
                                 key=lambda kv: kv[1]["bytes"], reverse=True))

    out["hosts"] = dict(sorted(out["hosts"].items(),
                               key=lambda kv: kv[1]["total_bytes"], reverse=True))
    out["detected_apps"] = sorted(detected)
    return out


if __name__ == "__main__":
    import pprint
    pprint.pprint(identify_from_flows())
