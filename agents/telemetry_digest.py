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
# Tope de las listas de excepciones (ataques no detectados / no mitigados).
# Son las únicas que recorren TODA la ejecución, así que sin tope crecen sin
# límite en un run largo.
MAX_EXCEPTIONS = 5
# Tope de puertos con mitigación activa que se enumeran (hay 26 puertos).
MAX_ACTIVE_RULES = 8

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
    # "desde N hosts a la vez" y no "N hosts": escrito de la forma corta, el
    # modelo leía "ddos 10 hosts (…)" como si fuesen DIEZ ataques ddos.
    return f"desde {len(many)} hosts a la vez ({', '.join(many[:3])}…)"


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
    # Puertos del enlace troncal central. Sin esta marca, preguntado por qué
    # un puerto va más cargado, el modelo no podía contestar: veía el número
    # pero no que ese puerto es por donde pasa TODO el tráfico entre subredes.
    central = read_json("central_link.json", {}, source_dir) or {}
    trunk_ports = set(central.get("ports") or [])

    rows = []
    for port, vals in agg.items():
        total = vals["rx"] + vals["tx"]
        if total == 0 and vals["drop"] == 0:
            continue
        rows.append({
            "port": port,
            "host": port_index.get(port),
            "trunk": port in trunk_ports,
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


def _within_window(rows, window_min, ts_key, source_dir=None):
    """Filtra `rows` a los últimos `window_min` minutos.

    Igual que summarize_ports, la ventana se ancla al ÚLTIMO elemento de la
    lista y no al reloj: así el recorte funciona idéntico sobre un run que se
    archivó hace semanas.

    window_min=None desactiva el filtro (lo usan los contadores globales, que
    deben abarcar la ejecución entera).
    """
    if not window_min or not rows:
        return rows
    last = None
    for row in reversed(rows):
        last = _parse_ts(row.get(ts_key))
        if last:
            break
    if not last:
        return rows
    cutoff = last - timedelta(minutes=window_min)
    return [r for r in rows
            if (_parse_ts(r.get(ts_key)) or last) >= cutoff]


def recent_alerts(limit=MAX_ALERTS, source_dir=None, window_min=None):
    """Últimas detecciones de anomalía (flow_alerts.jsonl)."""
    rows = read_jsonl("flow_alerts.jsonl", source_dir=source_dir)
    rows = _within_window(rows, window_min, "ts", source_dir)
    return rows[-limit:] if limit else rows


def recent_injections(limit=MAX_INJECTIONS, source_dir=None, window_min=None):
    """Ataques realmente inyectados: la verdad-terreno del experimento.

    Permite preguntas del tipo "¿detectaste el DDoS que lancé?" y que el
    analista pueda contrastar detección contra realidad en vez de especular.

    OJO: esto es el DETALLE recortado a la ventana. El recuento global de la
    ejecución lo lleva correlate_attacks(), que lee el fichero entero.
    """
    rows = read_jsonl("anomaly_injections.jsonl", source_dir=source_dir)
    rows = _within_window(rows, window_min, "ts_start", source_dir)
    return rows[-limit:] if limit else rows


def recent_qos_events(limit=MAX_QOS_EVENTS, source_dir=None, window_min=None):
    history = read_json("qos_history.json", [], source_dir) or []
    history = _within_window(history, window_min, "ts", source_dir)
    return history[-limit:] if limit else history


# ─── Conclusiones precalculadas ──────────────────────────────────────────────
# Todo lo que sigue son cuentas que un modelo de 3B no sabe hacer sobre listas:
# comparar dos conjuntos, restar tiempos, agrupar repetidos. Se resuelven aquí,
# en Python, y al modelo se le entrega la conclusión ya redactada. Es la misma
# decisión que resolver IP→nombre de host antes de prompt-ear.

def _reference_now(source_dir=None):
    """Instante contra el que se juzga si algo 'está pasando ahora'.

    En la sesión viva es el reloj. En un run archivado el reloj no sirve —el
    run terminó hace semanas—, así que se usa la marca más reciente que haya
    en los propios datos.
    """
    if _dir(source_dir) == TMP_DIR:
        return datetime.now()
    candidates = []
    state = read_json("state.json", {}, source_dir) or {}
    candidates.append(_parse_ts(state.get("timestamp")))
    for rec in read_jsonl("flow_alerts.jsonl", source_dir=source_dir):
        candidates.append(_parse_ts(rec.get("ts")))
    for ev in read_json("qos_history.json", [], source_dir) or []:
        candidates.append(_parse_ts(ev.get("ts")))
    valid = [c for c in candidates if c]
    return max(valid) if valid else datetime.now()


def correlate_attacks(source_dir=None) -> dict:
    """Cruza los ataques lanzados con lo que el sistema llegó a detectar.

    Reutiliza attack_report.classify_injection(), que es exactamente la misma
    función que alimenta el marcador de /api/security en el dashboard: así el
    informe del analista y el panel de ciberseguridad nunca pueden discrepar.
    """
    from agents import attack_report as ar

    src = _dir(source_dir)
    injections = ar._load_jsonl(os.path.join(src, "anomaly_injections.jsonl"))
    if not injections:
        return {"total": 0, "detected": 0, "mitigated": 0, "missed": [],
                "detection_rate": None}

    qos_events = ar._load_json(os.path.join(src, "qos_history.json"), [])
    flow_alerts = ar._load_jsonl(os.path.join(src, "flow_alerts.jsonl"))
    audit_lines = []
    audit_path = os.path.join(src, "noc_audit.log")
    if os.path.exists(audit_path):
        try:
            with open(audit_path, encoding="utf-8", errors="replace") as f:
                audit_lines = f.readlines()
        except IOError:
            pass

    detected = mitigated = 0
    missed = []
    unmitigated = []
    for inj in injections:
        cls = ar.classify_injection(inj, qos_events, flow_alerts, audit_lines)
        entry = {
            "type": inj.get("type"),
            "attacker": _describe_attacker(inj),
            "victim": inj.get("victim"),
            "ts": inj.get("ts_start"),
        }
        if cls["detected"]:
            detected += 1
        else:
            missed.append(entry)
        if cls["signals"].get("resolver"):
            mitigated += 1
        else:
            # Nombrarlos importa: diciéndole solo "se mitigaron 8 de 9", el
            # modelo se inventaba CUÁL era el que faltaba.
            unmitigated.append(entry)

    total = len(injections)
    # Los contadores abarcan la ejecución ENTERA (es lo que responde a "¿se
    # detectaron los ataques?"), pero las listas de excepciones se recortan:
    # son lo único del digest que crecía sin tope en un run largo.
    return {
        "total": total,
        "detected": detected,
        "mitigated": mitigated,
        "missed": missed[-MAX_EXCEPTIONS:],
        "missed_total": len(missed),
        "unmitigated": unmitigated[-MAX_EXCEPTIONS:],
        "unmitigated_total": len(unmitigated),
        "detection_rate": round(100 * detected / total) if total else None,
    }


def attacks_in_progress(source_dir=None, reference=None) -> list:
    """Ataques cuyo intervalo [inicio, inicio+duración] cubre el instante actual.

    Un modelo pequeño no sabe restar un timestamp de otro: preguntado por
    "¿hay algún ataque en curso?" respondía que no mientras uno seguía
    corriendo. Aquí se calcula y se le da hecho.
    """
    reference = reference or _reference_now(source_dir)
    running = []
    for inj in read_jsonl("anomaly_injections.jsonl", source_dir=source_dir):
        start = _parse_ts(inj.get("ts_start"))
        if not start:
            continue
        end = start + timedelta(seconds=inj.get("duration_sec") or 0)
        if start <= reference <= end:
            running.append({
                "type": inj.get("type"),
                "attacker": _describe_attacker(inj),
                "victim": inj.get("victim"),
                "service": inj.get("victim_service"),
                "started_ago_sec": int((reference - start).total_seconds()),
                "remaining_sec": int((end - reference).total_seconds()),
            })
    return running


def group_alerts(alerts) -> list:
    """Agrupa detecciones repetidas del mismo suceso en una sola entrada.

    El detector dispara varias veces sobre el mismo ataque mientras dura. Sin
    agrupar, el modelo las lee como incidentes distintos y las enumera
    repetidas — llegó a citar dos veces el mismo ataque como si fueran dos.
    """
    grouped = {}
    order = []
    for a in alerts:
        key = (a.get("type"), a.get("host"), a.get("victim"), a.get("service"))
        if key not in grouped:
            grouped[key] = {
                "type": a.get("type"), "host": a.get("host"),
                "victim": a.get("victim"), "service": a.get("service"),
                "port": a.get("port"), "count": 0,
                "first_ts": a.get("ts"), "last_ts": a.get("ts"),
                "max_bytes": 0,
            }
            order.append(key)
        g = grouped[key]
        g["count"] += 1
        g["last_ts"] = a.get("ts")
        g["max_bytes"] = max(g["max_bytes"], a.get("bytes") or 0)
    return [grouped[k] for k in order]


def effective_mitigations(source_dir=None) -> dict:
    """Mitigaciones activas, completadas con las acciones posteriores al ciclo.

    state.json se reescribe una vez por ciclo, pero las acciones rápidas
    [FLOW] del watcher ocurren ENTRE ciclos. Leyendo solo el estado, el digest
    llegaba a decir 'mitigaciones activas: ninguna' quince segundos antes de
    listar un 'apply SHAPING' en el historial: se contradecía a sí mismo.
    """
    state = read_json("state.json", {}, source_dir) or {}
    rules = dict(state.get("reglas_activas") or {})
    state_ts = _parse_ts(state.get("timestamp"))
    if not state_ts:
        return rules

    for ev in read_json("qos_history.json", [], source_dir) or []:
        ts = _parse_ts(ev.get("ts"))
        if not ts or ts <= state_ts:
            continue
        port = ev.get("port")
        if not port:
            continue
        if ev.get("event") in ("apply", "intent_apply"):
            rules[port] = {"action": ev.get("action"), "ciclo": ev.get("cycle"),
                           "protocol": ev.get("protocol"), "posterior": True}
        elif ev.get("event") == "remove":
            rules.pop(port, None)
    return rules


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
        "active_rules": effective_mitigations(source_dir),
        "last_report": state.get("ultimo_informe"),
        # Conclusiones ya calculadas: el modelo las lee, no las deduce.
        "correlation": correlate_attacks(source_dir),
        "in_progress": attacks_in_progress(source_dir),
        "window_min": window_min,
        "traffic": summarize_ports(window_min, source_dir, top_n=lim["ports"]),
        "flows": summarize_flows(source_dir, top_n=lim["flows"]),
        # El DETALLE se recorta a la ventana; los contadores de 'correlation'
        # siguen abarcando la ejecución entera.
        "alerts": recent_alerts(limit=lim["alerts"], source_dir=source_dir,
                                window_min=window_min),
        "injections": recent_injections(limit=lim["injections"],
                                        source_dir=source_dir,
                                        window_min=window_min),
        "qos_events": recent_qos_events(limit=lim["qos_events"],
                                        source_dir=source_dir,
                                        window_min=window_min),
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

    # Lo primero que debe leer el modelo: si hay algo pasando AHORA. Va arriba
    # porque es la respuesta a la pregunta más frecuente del operador.
    running = ctx.get("in_progress") or []
    L.append("\n=== ¿HAY ALGÚN ATAQUE EN CURSO AHORA MISMO? ===")
    if running:
        L.append(f"SÍ — {len(running)} ataque(s) en curso en este instante:")
        for r in running:
            L.append(f"- {r['type']}: {r['attacker']} -> {r['victim']} "
                     f"({r['service']}), empezó hace {r['started_ago_sec']}s, "
                     f"le quedan unos {r['remaining_sec']}s")
    else:
        L.append("NO. Ningún ataque está activo en este instante. "
                 "(Los que aparecen más abajo ya terminaron.)")

    corr = ctx.get("correlation") or {}
    if corr.get("total"):
        # El encabezado repite los tres términos que usa el operador
        # —inyectados / lanzados / detectados— a propósito. Con el título solo
        # en "lanzados", preguntado por "los ataques que se INYECTARON" el
        # modelo no ligaba pregunta y sección, y respondía lo contrario de lo
        # que ponía dos líneas más abajo. La coincidencia léxica le ahorra
        # tener que resolver el sinónimo.
        L.append("\n=== ¿SE DETECTARON LOS ATAQUES INYECTADOS (LANZADOS)? "
                 "(ya calculado, no lo recalcules) ===")
        # Concordancia y matiz exactos. Con "De 1 ataqueS" y un "en su mayoría"
        # fijo aunque la tasa fuese del 100%, el modelo copiaba la vaguedad y
        # respondía "detectó 1 de los ataques" en vez de "detectó el único".
        n = corr["total"]
        plural = "ataques inyectados (lanzados)" if n != 1 else \
                 "ataque inyectado (lanzado)"
        if not corr["detected"]:
            L.append(f"NO. De {n} {plural} contra la red, el sistema no "
                     f"detectó ninguno.")
        else:
            cabecera = ("SÍ, TODOS." if corr["detection_rate"] == 100
                        else "SÍ, la mayoría.")
            L.append(f"{cabecera} De {n} {plural} contra la red, el sistema "
                     f"DETECTÓ {corr['detected']} de {n} "
                     f"({corr['detection_rate']}%), y de esos aplicó QoS para "
                     f"mitigar {corr['mitigated']} de {n}. Detectar y mitigar "
                     f"son cosas distintas: no digas 'todos' para las dos si "
                     f"los números no coinciden.")
        if corr.get("missed"):
            n_missed = corr.get("missed_total", len(corr["missed"]))
            L.append(f"Pasaron desapercibidos {n_missed}"
                     + (f" (se listan los {len(corr['missed'])} últimos):"
                        if n_missed > len(corr["missed"]) else ":"))
            for m in corr["missed"]:
                L.append(f"- {m['type']} {m['attacker']} -> {m['victim']} "
                         f"[{_fmt_ts(m['ts'])}]")
        else:
            L.append("Ninguno pasó desapercibido.")
        if corr.get("unmitigated"):
            n = corr.get("unmitigated_total", len(corr["unmitigated"]))
            mostrados = len(corr["unmitigated"])
            L.append(f"El único ataque SIN mitigar es exactamente este, y "
                     f"ningún otro:" if n == 1 else
                     f"Hay {n} ataques SIN mitigar; estos son los "
                     f"{mostrados} últimos:" if n > mostrados else
                     f"Los {n} ataques SIN mitigar son exactamente estos, y "
                     f"ningún otro:")
            # Sin coletillas sobre el resolver: la aclaración "puede que aún no
            # haya reaccionado" hacía que el modelo rematase la frase con "…y
            # se aplicó QoS para mitigarlo", contradiciendo el propio titular.
            # Solo el hecho, y el matiz temporal aparte y sin verbos de acción.
            for m in corr["unmitigated"]:
                L.append(f"- {m['type']} {m['attacker']} -> {m['victim']} "
                         f"[{_fmt_ts(m['ts'])}]: NO tiene ninguna acción de QoS "
                         f"asociada.")
            L.append("Si alguno acaba de empezar, es normal que todavía no la "
                     "tenga.")
        else:
            L.append("Todos ellos recibieron mitigación QoS.")

    rules = ctx.get("active_rules") or {}
    if rules:
        L.append("\n=== MITIGACIONES ACTIVAS (aplicadas por el resolver) ===")
        items = list(rules.items())
        for port, r in items[:MAX_ACTIVE_RULES]:
            proto = f", protocolo {r.get('protocol')}" if r.get("protocol") else ""
            L.append(f"- {port}: {r.get('action')} desde el ciclo {r.get('ciclo')}{proto}")
        if len(items) > MAX_ACTIVE_RULES:
            L.append(f"- …y {len(items) - MAX_ACTIVE_RULES} puertos más con "
                     f"mitigación activa.")
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
        # La leyenda de los roles va UNA vez arriba y cada puerto lleva solo su
        # etiqueta corta: repetir la explicación en cada línea inflaba el
        # contexto un 35%, y en inferencia por CPU eso son segundos.
        L.append("(troncal = por ahí pasa el tráfico entre subredes, por eso "
                 "va cargado; host = el cable de una máquina; enlace = unión "
                 "entre switches o hacia un router)")
        for r in rows:
            if r.get("trunk"):
                etiqueta = " [troncal central]"
            elif r.get("host"):
                etiqueta = f" [host {r['host']}]"
            else:
                etiqueta = " [enlace]"
            drops = f", {r['drops']} descartes" if r.get("drops") else ""
            L.append(f"- {r['port']}{etiqueta}: recibe "
                     f"{format_bytes(r['rx_bytes'])}, envía "
                     f"{format_bytes(r['tx_bytes'])}, "
                     f"{r['mbps']} Mbps medios{drops}")
    else:
        L.append("\n=== TRÁFICO POR PUERTO === sin muestras todavía")

    flows = ctx.get("flows") or {}
    frows = flows.get("flows") or []
    if frows:
        # Sin hora absoluta a propósito: flows.json la estampa el colector que
        # corre DENTRO de la VM (agents/sflow.py), con el reloj de la VM. Si
        # ese reloj va desfasado del anfitrión —lo estaba en 21 h— el digest
        # acaba con dos líneas temporales incompatibles y el modelo mezcla el
        # "ahora" de un sitio con el del otro. Siempre es el último muestreo,
        # así que la hora no aporta nada al diagnóstico.
        L.append(f"\n=== TOP FLUJOS sFlow, ÚLTIMO MUESTREO "
                 f"(ventana {flows.get('window_sec')}s) ===")
        for f in frows:
            L.append(f"- {f['src']} -> {f['dst']} {f['proto']}/{f['dport']}: "
                     f"{format_bytes(f['bytes'])} en {f['pkts']} paquetes")

    alerts = group_alerts(ctx.get("alerts") or [])
    if alerts:
        L.append(f"\n=== ANOMALÍAS DETECTADAS EN LOS ÚLTIMOS {ctx.get('window_min')} MIN ({len(alerts)} distintas) ===")
        for a in alerts:
            victim = f" -> víctima {a.get('victim')}" if a.get("victim") else ""
            veces = f", detectado {a['count']} veces" if a["count"] > 1 else ""
            L.append(f"- [{_fmt_ts(a.get('first_ts'))}] {a.get('type')} "
                     f"origen {a.get('host')} en {a.get('port')}{victim}, "
                     f"hasta {format_bytes(a.get('max_bytes', 0))}, "
                     f"servicio {a.get('service')}{veces}")

    inj = ctx.get("injections") or []
    if inj:
        # Se separa de la lista anterior a propósito: una cosa es el ataque que
        # de verdad se lanzó y otra si el sistema llegó a verlo. Confundirlas es
        # el error típico del modelo, así que se etiqueta de forma explícita.
        # Mismo nombre que en la sección del recuento, a propósito. Cuando esta
        # lista se titulaba "ataques que se lanzaron de verdad" y la de arriba
        # hablaba de "ataques inyectados", el modelo las tomaba por DOS
        # poblaciones distintas y llegó a responder que había "ataques
        # inyectados y además ataques reales". Son los mismos.
        cuantos = ("el único de los últimos" if len(inj) == 1
                   else f"los {len(inj)} de los últimos")
        L.append(f"\n=== DETALLE DE ESOS MISMOS ATAQUES INYECTADOS "
                 f"({cuantos} {ctx.get('window_min')} min) ===")
        L.append("(Solo detalle. El recuento de cuántos se detectaron y "
                 "mitigaron ya está resuelto arriba: no lo recalcules ni "
                 "cuentes estos como ataques aparte.)")
        for i in inj:
            L.append(f"- [{_fmt_ts(i.get('ts_start'))}] {i.get('type')} "
                     f"{_describe_attacker(i)} "
                     f"-> {i.get('victim')} ({i.get('victim_service')}), "
                     f"{i.get('duration_sec')}s, método {i.get('method')}")

    qos = ctx.get("qos_events") or []
    if qos:
        L.append(f"\n=== HISTORIAL QoS ({len(qos)} eventos de los últimos "
                 f"{ctx.get('window_min')} min) ===")
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
