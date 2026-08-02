"""Resumen compacto de la telemetría del NOC para consumo por un LLM.

Problema que resuelve: los ficheros de tmp/ son series temporales largas —
live_metrics.json llega a 2000 muestras y flows_history.json a 720. Volcarlos
crudos en un prompt no cabe en el contexto de qwen2.5:7b, y truncar por el final
pierde justo lo interesante. Aquí se agrega ANTES de prompt-ear: totales por
puerto en una ventana, top-N flujos, últimos eventos.

Todo es lectura pura de ficheros: sin SSH, sin estado global, sin LLM. Lo usan
tanto el servidor MCP (mcp_server/server.py) como el analista
(agents/noc_analyst.py), así que no debe importar a ninguno de los dos.

`source_dir` permite apuntar a un run guardado (saved_runs/<nombre>/) en vez de
a tmp/, que es lo que hace el dashboard cuando estás viendo un run archivado:
así se pueden pedir informes post-mortem de una ejecución pasada.
"""

import json
import os
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP_DIR = os.path.join(PROJECT_ROOT, "tmp")

# Cuántos elementos sobreviven al recorte. Calibrado para que el contexto
# completo ronde los 4-6 KB de texto: entra de sobra en 8k tokens dejando
# espacio para la pregunta, el historial y la respuesta.
TOP_PORTS = 8
TOP_FLOWS = 15
MAX_ALERTS = 20
MAX_QOS_EVENTS = 20
MAX_INJECTIONS = 10

# Perfil reducido. En inferencia por CPU el coste lo domina el procesado del
# prompt, no la generación: medido sobre esta máquina (8 núcleos, sin GPU), el
# contexto completo ronda los 6 KB (~1750 tokens) y dispara la latencia. El
# perfil compacto se queda en torno a la mitad conservando lo que de verdad
# hace falta para diagnosticar, y es el que usa el informe narrativo.
COMPACT_LIMITS = {
    "ports": 5,
    "flows": 6,
    "alerts": 6,
    "qos_events": 8,
    "injections": 5,
}

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _dir(source_dir=None) -> str:
    return source_dir or TMP_DIR


def read_json(name, default=None, source_dir=None):
    path = os.path.join(_dir(source_dir), name)
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return default


def read_jsonl(name, limit=None, source_dir=None):
    """Lee un .jsonl saltando líneas corruptas (se escriben en caliente)."""
    path = os.path.join(_dir(source_dir), name)
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
                    continue
    except IOError:
        return []
    return out[-limit:] if limit else out


def _parse_ts(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


# ─── Índices de nombres ──────────────────────────────────────────────────────
# El LLM debe hablar de 'h3' y 'srv1', no de '192.168.3.3'. Sin esto los
# informes son ilegibles para un humano y no se pueden contrastar con la
# topología del dashboard.

def host_ip_index(source_dir=None) -> dict:
    """{ip: nombre_de_host} a partir de topology.json.

    En topology.json cada enlace nodo↔IP aparece como un link {from, to} donde
    exactamente uno de los extremos es una dirección IP.
    """
    topo = read_json("topology.json", {}, source_dir) or {}
    index = {}
    for link in topo.get("links", []):
        a, b = str(link.get("from", "")), str(link.get("to", ""))
        a_ip, b_ip = _looks_like_ip(a), _looks_like_ip(b)
        if b_ip and not a_ip:
            index[b] = a
        elif a_ip and not b_ip:
            index[a] = b
    return index


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def port_host_index(source_dir=None) -> dict:
    """{puerto_ovs: nombre_de_host} — inverso de host_port_map.json."""
    hp = read_json("host_port_map.json", {}, source_dir) or {}
    return {port: host for host, port in hp.items()}


def _fmt_ts(value) -> str:
    """ISO → 'dd/mm HH:MM:SS'.

    Con el formato ISO crudo los modelos pequeños confunden la hora con el día:
    ante '2026-06-01T17:05:22' llegan a escribir 'el 17 de junio'. Separando
    fecha y hora deja de pasar.
    """
    ts = _parse_ts(value)
    return ts.strftime("%d/%m %H:%M:%S") if ts else str(value or "?")


def _describe_attacker(inj) -> str:
    """Origen de un ataque inyectado, sea uno o sean muchos.

    Un DoS trae `attacker` (un host) y un DDoS trae `attackers` (una lista de
    diez o más). Leer solo `attacker` dejaba 'None' en el digest para todos los
    DDoS. De la lista se citan tres y se cuenta el resto: nombrarlos todos
    gasta tokens sin añadir nada al diagnóstico.
    """
    one = inj.get("attacker")
    if one:
        return str(one)
    many = inj.get("attackers") or []
    if not many:
        return "origen desconocido"
    if len(many) <= 3:
        return ", ".join(many)
    return f"{len(many)} hosts ({', '.join(many[:3])}…)"


def _label_ip(ip, ip_index):
    name = ip_index.get(ip)
    return f"{name} ({ip})" if name else str(ip)


def format_bytes(size) -> str:
    size = float(size or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# ─── Agregados ───────────────────────────────────────────────────────────────

def summarize_ports(window_min=5, source_dir=None, top_n=TOP_PORTS):
    """Agrega live_metrics.json en la ventana pedida: totales y Mbps por puerto.

    live_metrics guarda deltas cada ~5 s. Sumamos por puerto dentro de la
    ventana y devolvemos solo los `top_n` con más bytes — el resto es ruido de
    fondo que no aporta nada al diagnóstico.
    """
    samples = read_json("live_metrics.json", [], source_dir) or []
    if not samples:
        return {"ports": [], "samples": 0, "window_min": window_min}

    # La ventana se ancla al ÚLTIMO timestamp del fichero, no a datetime.now():
    # así funciona igual sobre un run guardado hace semanas.
    last_ts = _parse_ts(samples[-1].get("ts"))
    cutoff = last_ts - timedelta(minutes=window_min) if last_ts else None

    agg = {}
    used = 0
    first_ts = None
    for snap in samples:
        ts = _parse_ts(snap.get("ts"))
        if cutoff and ts and ts < cutoff:
            continue
        used += 1
        if first_ts is None:
            first_ts = ts
        for port, vals in (snap.get("ports") or {}).items():
            entry = agg.setdefault(port, {"rx": 0, "tx": 0, "drop": 0})
            entry["rx"] += vals.get("rx", 0) or 0
            entry["tx"] += vals.get("tx", 0) or 0
            entry["drop"] += vals.get("drop", 0) or 0

    elapsed = 1.0
    if first_ts and last_ts and last_ts > first_ts:
        elapsed = (last_ts - first_ts).total_seconds()

    port_index = port_host_index(source_dir)
    rows = []
    for port, vals in agg.items():
        total = vals["rx"] + vals["tx"]
        if total == 0 and vals["drop"] == 0:
            continue
        rows.append({
            "port": port,
            "host": port_index.get(port),
            "rx_bytes": vals["rx"],
            "tx_bytes": vals["tx"],
            "drops": vals["drop"],
            "mbps": round(total * 8 / elapsed / 1e6, 2),
        })
    rows.sort(key=lambda r: r["rx_bytes"] + r["tx_bytes"], reverse=True)
    return {
        "ports": rows[:top_n],
        "samples": used,
        "window_min": window_min,
        "elapsed_sec": round(elapsed, 1),
        "total_ports_seen": len(rows),
    }


def summarize_flows(source_dir=None, top_n=TOP_FLOWS):
    """Top-N flujos del último muestreo sFlow, con IPs resueltas a nombres."""
    snap = read_json("flows.json", {}, source_dir) or {}
    flows = snap.get("flows") or []
    ip_index = host_ip_index(source_dir)
    rows = []
    for f in sorted(flows, key=lambda x: x.get("bytes", 0), reverse=True)[:top_n]:
        rows.append({
            "src": _label_ip(f.get("src"), ip_index),
            "dst": _label_ip(f.get("dst"), ip_index),
            "proto": _PROTO_NAMES.get(f.get("proto"), str(f.get("proto"))),
            "dport": f.get("dport"),
            "bytes": f.get("bytes", 0),
            "pkts": f.get("pkts", 0),
        })
    return {
        "ts": snap.get("ts"),
        "window_sec": snap.get("window_sec"),
        "flows": rows,
        "total_flows": len(flows),
    }


def recent_alerts(limit=MAX_ALERTS, source_dir=None):
    """Últimas detecciones de anomalía (flow_alerts.jsonl)."""
    return read_jsonl("flow_alerts.jsonl", limit=limit, source_dir=source_dir)


def recent_injections(limit=MAX_INJECTIONS, source_dir=None):
    """Ataques realmente inyectados: la verdad-terreno del experimento.

    Permite preguntas del tipo "¿detectaste el DDoS que lancé?" y que el
    analista pueda contrastar detección contra realidad en vez de especular.
    """
    return read_jsonl("anomaly_injections.jsonl", limit=limit, source_dir=source_dir)


def recent_qos_events(limit=MAX_QOS_EVENTS, source_dir=None):
    history = read_json("qos_history.json", [], source_dir) or []
    return history[-limit:]


def build_network_context(window_min=5, source_dir=None, compact=False) -> dict:
    """Digest completo de la red, listo para inyectar en un prompt.

    compact=True aplica COMPACT_LIMITS y omite el inventario de servicios: la
    mitad de tokens, que en CPU es aproximadamente la mitad de latencia.
    """
    lim = COMPACT_LIMITS if compact else {
        "ports": TOP_PORTS, "flows": TOP_FLOWS, "alerts": MAX_ALERTS,
        "qos_events": MAX_QOS_EVENTS, "injections": MAX_INJECTIONS,
    }
    state = read_json("state.json", {}, source_dir) or {}
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": os.path.basename(_dir(source_dir).rstrip("/")),
        "compact": compact,
        "cycle": state.get("ciclo"),
        "state_ts": state.get("timestamp"),
        "network_state": state.get("estado_red"),
        "cycle_interval_sec": state.get("intervalo_actual"),
        "active_rules": state.get("reglas_activas") or {},
        "last_report": state.get("ultimo_informe"),
        "traffic": summarize_ports(window_min, source_dir, top_n=lim["ports"]),
        "flows": summarize_flows(source_dir, top_n=lim["flows"]),
        "alerts": recent_alerts(limit=lim["alerts"], source_dir=source_dir),
        "injections": recent_injections(limit=lim["injections"],
                                        source_dir=source_dir),
        "qos_events": recent_qos_events(limit=lim["qos_events"],
                                        source_dir=source_dir),
        "services": {} if compact else (
            read_json("server_services.json", {}, source_dir) or {}),
        "central_link": read_json("central_link.json", None, source_dir),
        "failover": read_json("failover_state.json", {}, source_dir) or {},
        "qos_intent_plans": _intent_plan_summary(source_dir),
    }


def _intent_plan_summary(source_dir=None):
    """Planes QoS declarativos activos, en forma corta (sin comandos tc)."""
    data = read_json("qos_intent_state.json", {}, source_dir) or {}
    # Formato actual: {puerto: plan}. Formato antiguo: un único plan plano.
    plans = list(data.values()) if data and "target_port" not in data else (
        [data] if data else []
    )
    out = []
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        out.append({
            "target_host": plan.get("target_host"),
            "target_port": plan.get("target_port"),
            "scope": plan.get("scope"),
            "total_mbps": plan.get("total_mbps"),
            "apps": [
                {"app": a.get("app"), "tier": a.get("tier"),
                 "min_mbps": a.get("min_mbps"), "max_mbps": a.get("max_mbps")}
                for a in (plan.get("apps") or [])
            ],
        })
    return out


# ─── Render a texto ──────────────────────────────────────────────────────────

def render_context_text(ctx: dict) -> str:
    """Convierte el digest a texto plano compacto para el prompt.

    Texto y no JSON a propósito: los modelos pequeños siguen mucho mejor una
    tabla legible que un objeto anidado, y ocupa bastante menos.
    """
    L = []
    src = ctx.get("source")
    L.append(f"=== ESTADO GENERAL (fuente: {src}) ===")
    if ctx.get("cycle") is None:
        # Nunca escribir 'None' en el prompt: el modelo lo repite tal cual en la
        # respuesta o se inventa un valor para rellenar el hueco.
        L.append("El supervisor todavía no ha completado ningún ciclo.")
    else:
        L.append(f"Ciclo: {ctx.get('cycle')} | Estado: {ctx.get('network_state')} "
                 f"| Intervalo: {ctx.get('cycle_interval_sec')}s "
                 f"| Instante: {_fmt_ts(ctx.get('state_ts'))}")

    rules = ctx.get("active_rules") or {}
    if rules:
        L.append("\n=== MITIGACIONES ACTIVAS (aplicadas por el resolver) ===")
        for port, r in rules.items():
            proto = f", protocolo {r.get('protocol')}" if r.get("protocol") else ""
            L.append(f"- {port}: {r.get('action')} desde el ciclo {r.get('ciclo')}{proto}")
    else:
        L.append("\n=== MITIGACIONES ACTIVAS === ninguna")

    plans = ctx.get("qos_intent_plans") or []
    if plans:
        L.append("\n=== PLANES QoS DECLARATIVOS (pedidos por el usuario) ===")
        for p in plans:
            apps = ", ".join(f"{a['app']}({a['tier']}, min {a['min_mbps']}Mbps)"
                             for a in p.get("apps") or [])
            L.append(f"- {p.get('target_host')} en {p.get('target_port')} "
                     f"[{p.get('scope')}], línea {p.get('total_mbps')} Mbps: {apps}")

    traffic = ctx.get("traffic") or {}
    rows = traffic.get("ports") or []
    if rows:
        # Se avisa de que la lista ya viene ordenada: si el modelo tiene que
        # ordenarla él, se equivoca y mezcla el 4º con el 2º.
        L.append(f"\n=== TRÁFICO POR PUERTO, DE MAYOR A MENOR (últimos "
                 f"{traffic.get('window_min')} min, {traffic.get('samples')} "
                 f"muestras, top {len(rows)} de "
                 f"{traffic.get('total_ports_seen')}) ===")
        for r in rows:
            host = f" [{r['host']}]" if r.get("host") else ""
            drops = f", drops={r['drops']}" if r.get("drops") else ""
            L.append(f"- {r['port']}{host}: rx={format_bytes(r['rx_bytes'])}, "
                     f"tx={format_bytes(r['tx_bytes'])}, {r['mbps']} Mbps medios{drops}")
    else:
        L.append("\n=== TRÁFICO POR PUERTO === sin muestras todavía")

    flows = ctx.get("flows") or {}
    frows = flows.get("flows") or []
    if frows:
        L.append(f"\n=== TOP FLUJOS sFlow (ventana {flows.get('window_sec')}s, "
                 f"muestreo {_fmt_ts(flows.get('ts'))}) ===")
        for f in frows:
            L.append(f"- {f['src']} -> {f['dst']} {f['proto']}/{f['dport']}: "
                     f"{format_bytes(f['bytes'])} en {f['pkts']} paquetes")

    alerts = ctx.get("alerts") or []
    if alerts:
        L.append(f"\n=== ANOMALÍAS QUE EL SISTEMA DETECTÓ (últimas {len(alerts)}) ===")
        for a in alerts:
            victim = f" -> víctima {a.get('victim')}" if a.get("victim") else ""
            L.append(f"- [{_fmt_ts(a.get('ts'))}] {a.get('type')} origen {a.get('host')} "
                     f"en {a.get('port')}{victim}, "
                     f"{format_bytes(a.get('bytes', 0))}, servicio {a.get('service')}")

    inj = ctx.get("injections") or []
    if inj:
        # Se separa de la lista anterior a propósito: una cosa es el ataque que
        # de verdad se lanzó y otra si el sistema llegó a verlo. Confundirlas es
        # el error típico del modelo, así que se etiqueta de forma explícita.
        L.append(f"\n=== ATAQUES QUE SE LANZARON DE VERDAD (verdad-terreno, "
                 f"últimos {len(inj)}) ===")
        L.append("(Compara esta lista con la anterior para saber cuáles se "
                 "detectaron y cuáles pasaron desapercibidos.)")
        for i in inj:
            L.append(f"- [{_fmt_ts(i.get('ts_start'))}] {i.get('type')} "
                     f"{_describe_attacker(i)} "
                     f"-> {i.get('victim')} ({i.get('victim_service')}), "
                     f"{i.get('duration_sec')}s, método {i.get('method')}")

    qos = ctx.get("qos_events") or []
    if qos:
        L.append(f"\n=== HISTORIAL QoS (últimos {len(qos)} eventos) ===")
        for e in qos:
            # Los eventos 'remove' vienen sin acción y algunos sin protocolo:
            # se omiten en vez de imprimir 'None', que el modelo copia literal.
            action = f" {e.get('action')}" if e.get("action") else ""
            proto = f" proto={e.get('protocol')}" if e.get("protocol") else ""
            extra = f" app={e.get('app')}" if e.get("app") else ""
            L.append(f"- [{_fmt_ts(e.get('ts'))}] ciclo {e.get('cycle')}: "
                     f"{e.get('event')}{action} en {e.get('port')}"
                     f"{proto}{extra}")

    svcs = ctx.get("services") or {}
    if svcs:
        L.append("\n=== SERVICIOS DESPLEGADOS ===")
        L.append(", ".join(f"{n}={s.get('type')}:{s.get('port')}@{s.get('ip')}"
                           for n, s in svcs.items()))

    central = ctx.get("central_link")
    if central and not ctx.get("compact"):
        L.append(f"\n=== ENLACE TRONCAL CENTRAL (topología, no es tráfico) ===\n"
                 f"El switch {central.get('central_switch')} concentra el tráfico "
                 f"entre subredes; su puerto "
                 f"{central.get('shaping_port')} tiene "
                 f"{central.get('hosts_behind', {}).get(central.get('shaping_port'), '?')} "
                 f"hosts por detrás.")

    fo = (ctx.get("failover") or {}).get("servers") or {}
    down = {n: s for n, s in fo.items() if s.get("status") != "up"}
    if down:
        L.append("\n=== SERVIDORES CAÍDOS ===")
        for n, s in down.items():
            L.append(f"- {n}: {s.get('status')}, redirigido a {s.get('redirected_to')}")

    return "\n".join(L)
