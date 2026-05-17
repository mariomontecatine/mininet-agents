"""
Correlaciona las anomalías inyectadas con la respuesta del NOC y emite un
informe en `tmp/attack_report.md`.

Fuentes:
  - tmp/anomaly_injections.jsonl  (qué inyectó el attack_agent)
  - tmp/qos_history.json          (qué acciones aplicó el resolver)
  - tmp/flow_alerts.jsonl         (qué detectaron las heurísticas del monitor)
  - tmp/noc_audit.log             (texto del informe IA de cada ciclo)

Para cada inyección registra tres señales de detección independientes:
  1. RESOLVER  — hubo una acción QoS sobre el puerto del atacante o la víctima
                 dentro de [ts_start, ts_end + grace]
  2. HEURÍSTICA — el monitor emitió una alerta de flujo del mismo tipo en la
                 misma ventana involucrando al mismo host
  3. INFORME   — el texto del informe IA mencionó al host (nombre o IP) dentro
                 de la ventana

Una inyección cuenta como **detectada (TP)** si al menos una señal disparó.

Ejecuta:
    python3 -m agents.attack_report
o desde Python:
    from agents.attack_report import generate_report; generate_report()
"""

import os
import sys
import json
import re
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")

INJECTION_LOG = os.path.join(TMP_DIR, "anomaly_injections.jsonl")
QOS_HISTORY   = os.path.join(TMP_DIR, "qos_history.json")
FLOW_ALERTS   = os.path.join(TMP_DIR, "flow_alerts.jsonl")
AUDIT_LOG     = os.path.join(TMP_DIR, "noc_audit.log")
REPORT_MD     = os.path.join(TMP_DIR, "attack_report.md")

GRACE_SEC = 60      # margen para que la cadena monitor→resolver actúe tras ts_end


# ── Carga de fuentes ─────────────────────────────────────────────────────────

def _load_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except IOError:
        pass
    return out


def _load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return default


def _read_audit_lines():
    if not os.path.exists(AUDIT_LOG):
        return []
    try:
        with open(AUDIT_LOG, encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except IOError:
        return []


# ── Helpers de tiempo ────────────────────────────────────────────────────────

def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return None


def _audit_ts(line):
    m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]", line)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None


# ── Lógica de correlación ────────────────────────────────────────────────────

def _attacker_ports(rec):
    """Devuelve la lista de puertos OVS relevantes a la inyección."""
    out = []
    if rec.get("attacker_port"):  out.append(rec["attacker_port"])
    if rec.get("victim_port"):    out.append(rec["victim_port"])
    for p in rec.get("attacker_ports", []) or []:
        if p: out.append(p)
    return [p for p in out if p]


def _attacker_hosts(rec):
    out = []
    if rec.get("attacker"):
        out.append(rec["attacker"])
    if rec.get("attacker_ip"):
        out.append(rec["attacker_ip"])
    if rec.get("victim"):
        out.append(rec["victim"])
    if rec.get("victim_ip"):
        out.append(rec["victim_ip"])
    out.extend(rec.get("attackers", []) or [])
    out.extend(rec.get("attacker_ips", []) or [])
    return [h for h in out if h]


def _within(rec, ts):
    """¿ts cae dentro de [ts_start, ts_end_planned + GRACE_SEC]?"""
    start = rec.get("ts_start_epoch") or _parse_iso(rec.get("ts_start"))
    end_planned = _parse_iso(rec.get("ts_end_planned"))
    if start is None:
        return False
    if end_planned is None:
        end_planned = start + rec.get("duration_sec", 60)
    return start <= ts <= end_planned + GRACE_SEC


def classify_injection(rec, qos_events, flow_alerts, audit_lines):
    """
    Para UNA inyección, calcula las 3 señales de detección y devuelve:
      {signals: {resolver, heuristic, informe},
       detected: bool, first_detection_lag_sec: float|None}
    Reutilizable por correlate() y por /api/security (live).
    """
    ports = set(_attacker_ports(rec))
    hosts = set(_attacker_hosts(rec))
    type_ = rec.get("type")
    start = rec.get("ts_start_epoch") or _parse_iso(rec.get("ts_start"))

    signals = {"resolver": None, "heuristic": None, "informe": None}

    # 1. RESOLVER — acción QoS sobre puerto relevante en ventana
    for ev in qos_events:
        ts = _parse_iso(ev.get("ts"))
        if ts is None or not _within(rec, ts):
            continue
        if ev.get("event") == "apply" and ev.get("port") in ports:
            signals["resolver"] = {
                "ts":     ev.get("ts"),
                "port":   ev.get("port"),
                "action": ev.get("action"),
                "lag":    round(ts - start, 1) if start else None,
            }
            break

    # 2. HEURÍSTICA — alerta de flujo del mismo tipo y mismo host
    for a in flow_alerts:
        ts = _parse_iso(a.get("ts"))
        if ts is None or not _within(rec, ts):
            continue
        if a.get("type") != type_:
            continue
        host = a.get("host") or a.get("host_ip")
        if host and host in hosts:
            signals["heuristic"] = {
                "ts":   a.get("ts"),
                "host": host,
                "lag":  round(ts - start, 1) if start else None,
            }
            break

    # 3. INFORME — texto del audit menciona al host
    for line in audit_lines:
        ts = _audit_ts(line)
        if ts is None or not _within(rec, ts):
            continue
        for h in hosts:
            if re.search(rf"\b{re.escape(h)}\b", line):
                signals["informe"] = {
                    "ts":   line[1:20],
                    "host": h,
                    "lag":  round(ts - start, 1) if start else None,
                }
                break
        if signals["informe"]:
            break

    lags = [s["lag"] for s in signals.values() if s and s.get("lag") is not None]
    return {
        "signals":                 signals,
        "detected":                any(signals.values()),
        "first_detection_lag_sec": min(lags) if lags else None,
    }


def correlate():
    """
    Devuelve una lista de dicts:
      {injection: {...}, signals: {resolver, heuristic, informe},
       first_detection_lag_sec: float|None, detected: bool}
    """
    injections = _load_jsonl(INJECTION_LOG)
    qos_events = _load_json(QOS_HISTORY, [])
    flow_alerts = _load_jsonl(FLOW_ALERTS)
    audit_lines = _read_audit_lines()

    results = []
    for rec in injections:
        cls = classify_injection(rec, qos_events, flow_alerts, audit_lines)
        results.append({"injection": rec, **cls})
    return results


# ── Render del informe ───────────────────────────────────────────────────────

def _fmt_lag(x):
    if x is None: return " — "
    return f"{x:5.1f}s"


def render(results):
    total = len(results)
    if total == 0:
        return "# Anomaly Detection Report\n\n_No hay inyecciones registradas._\n"

    by_type = defaultdict(lambda: {"total": 0, "detected": 0, "lags": [],
                                   "resolver": 0, "heuristic": 0, "informe": 0})
    for r in results:
        t = r["injection"].get("type", "?")
        s = by_type[t]
        s["total"] += 1
        if r["detected"]:
            s["detected"] += 1
            s["lags"].append(r["first_detection_lag_sec"])
        for k in ("resolver", "heuristic", "informe"):
            if r["signals"].get(k):
                s[k] += 1

    detected_total = sum(1 for r in results if r["detected"])
    pct = (100.0 * detected_total / total) if total else 0.0

    out = []
    out.append("# Anomaly Detection Report")
    out.append("")
    out.append(f"Generado: {datetime.now().isoformat(timespec='seconds')}")
    out.append(f"Ventana de gracia tras fin del ataque: {GRACE_SEC}s")
    out.append("")
    out.append("## Resumen global")
    out.append("")
    out.append(f"- Total de ataques inyectados: **{total}**")
    out.append(f"- Detectados (al menos una señal): **{detected_total}** ({pct:.1f}%)")
    out.append(f"- No detectados: **{total - detected_total}** ({100.0 - pct:.1f}%)")
    out.append("")
    out.append("## Por tipo de ataque")
    out.append("")
    out.append("| Tipo | Inyectados | Detectados | Tasa | Resolver | Heurística | Informe | Lag medio |")
    out.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for t in ("port_scan", "dos_volumetric", "ddos_fanin"):
        s = by_type.get(t)
        if not s:
            out.append(f"| {t} | 0 | 0 | — | 0 | 0 | 0 | — |")
            continue
        avg_lag = (sum(s["lags"]) / len(s["lags"])) if s["lags"] else None
        rate = 100.0 * s["detected"] / s["total"] if s["total"] else 0.0
        out.append(
            f"| {t} | {s['total']} | {s['detected']} | {rate:.0f}% | "
            f"{s['resolver']} | {s['heuristic']} | {s['informe']} | "
            f"{_fmt_lag(avg_lag).strip()} |"
        )
    out.append("")
    out.append("## Línea temporal detallada")
    out.append("")
    out.append("Símbolos: ✅ detectado por esa señal, ❌ no.")
    out.append("")
    out.append("| ID | Tipo | Inicio | Atacante → Víctima | Dur | Res | Heur | Inf | First lag |")
    out.append("|---|---|---|---|---:|:---:|:---:|:---:|---:|")
    for r in results:
        inj = r["injection"]
        t = inj.get("type", "?")
        ts_start = inj.get("ts_start", "?")
        # actor / víctima legibles
        if t == "port_scan":
            actor = inj.get("attacker", "?")
            target = f"{len(inj.get('victims', []))} destinos"
        elif t == "dos_volumetric":
            actor = inj.get("attacker", "?")
            target = inj.get("victim", "?")
        elif t == "ddos_fanin":
            actor = ",".join(inj.get("attackers", []) or [])
            target = inj.get("victim", "?")
        else:
            actor, target = "?", "?"
        sig = r["signals"]
        out.append(
            f"| {inj.get('id','?')} | {t} | {ts_start} | "
            f"{actor} → {target} | {inj.get('duration_sec','?')}s | "
            f"{'✅' if sig['resolver']   else '❌'} | "
            f"{'✅' if sig['heuristic']  else '❌'} | "
            f"{'✅' if sig['informe']    else '❌'} | "
            f"{_fmt_lag(r['first_detection_lag_sec']).strip()} |"
        )
    out.append("")
    return "\n".join(out)


def generate_report():
    """Correlaciona y vuelca tmp/attack_report.md. Devuelve el path."""
    results = correlate()
    md = render(results)
    try:
        with open(REPORT_MD, "w", encoding="utf-8") as f:
            f.write(md)
    except IOError:
        pass
    return REPORT_MD, results


def _print_summary(results):
    total = len(results)
    if not total:
        print("No hay inyecciones registradas.")
        return
    det = sum(1 for r in results if r["detected"])
    print(f"\nTotal: {total}  Detectados: {det} ({100*det/total:.1f}%)")
    bt = defaultdict(lambda: [0, 0])
    for r in results:
        t = r["injection"].get("type", "?")
        bt[t][0] += 1
        if r["detected"]: bt[t][1] += 1
    for t, (tot, d) in bt.items():
        print(f"  {t:<18} {d}/{tot}  ({100*d/max(1,tot):.0f}%)")


if __name__ == "__main__":
    path, results = generate_report()
    print(f"Reporte escrito en {path}")
    _print_summary(results)
