"""QoS declarativa por intent del usuario.

Flujo: el usuario describe en NL qué va a usar (YouTube, VoIP, descargar Linux).
El LLM mapea esa descripción a una lista de apps del catálogo
(agents.apps_catalog). Esta tool construye una jerarquía HTB en el puerto OVS
que conecta su host con el switch y filtra por (ip_proto, dport) cada app a su
clase. El resultado: cada tier (interactive / streaming / bulk / best_effort)
tiene su propia clase con rate garantizada y ceil hasta la velocidad total de
línea. HTB redistribuye el ancho de banda libre entre clases con borrow.

NO se solapa con la mitigación reactiva de resolver_agent: las reglas user-intent
se aplican en el puerto del host objetivo, las reactivas en el puerto del atacante
(normalmente otro). Si coincidiesen, la última en aplicarse gana porque ambas
usan `tc qdisc del dev <port> root` antes de añadir su raíz. Se documenta como
limitación conocida en una demo educativa.
"""

import json
import os
import re
import sys
import time
from datetime import datetime

import ollama

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config
from utils.ssh_client import get_ssh_connection, send_tmux_command
from agents import apps_catalog


TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
STATE_FILE      = os.path.join(TMP_DIR, "qos_intent_state.json")
HOST_PORT_FILE  = os.path.join(TMP_DIR, "host_port_map.json")
QOS_HISTORY     = os.path.join(TMP_DIR, "qos_history.json")
SERVER_SERVICES = os.path.join(TMP_DIR, "server_services.json")

MODEL_NAME = config.MODEL_RESOLVER

# Timeout más generoso que el resolver: el system prompt es grande (catálogo
# + reglas) y qwen2.5:3b puede tardar 30-60s en su primera respuesta. Si aún
# así expira, hay un fallback heurístico por keywords más abajo.
_QOS_LLM_TIMEOUT = 120

_ollama_client = ollama.Client(host="http://localhost:11434",
                               timeout=_QOS_LLM_TIMEOUT)


# ─── Parser heurístico (fallback sin LLM) ───────────────────────────────────
# Cuando el LLM expira o falla, mapeamos texto → apps por keywords. Es
# determinista y nunca cuelga; cubre la mayoría de demos típicas.
_KEYWORD_MAP = {
    "voip":         ["voip", "voz", "llamada", "llamadas", "teléfono", "telefono",
                     "sip", "videollamada", "video llamada", "skype", "zoom",
                     "meet", "whatsapp call"],
    "dns":          ["dns", "resolución", "resolucion", "nameserver", "bind"],
    "ssh":          ["ssh", "shell", "terminal", "acceso remoto"],
    "youtube":      ["youtube", "netflix", "twitch", "stream", "streaming",
                     "vídeo", "video", "4k", "1080p", "hbo", "prime video",
                     "disney"],
    "web_browsing": ["navegar", "navegación", "navegacion", "web", "navegador",
                     "browser", "http general"],
    "linux_iso":    ["linux", "iso", "distribución", "distribucion", "ubuntu",
                     "debian", "descarga grande", "torrent", "bittorrent",
                     "actualización", "actualizacion", "update grande"],
    "ftp_download": ["ftp", "transferencia ftp", "descarga ftp"],
    "email":        ["email", "correo", "smtp", "mail"],
}


def parse_qos_intent_heuristic(text):
    """Detecta apps por keywords. Devuelve lista [{'app': str}, ...].

    Determinista, sin Ollama. Tres reglas para evitar falsos positivos:
      1. Boundaries de palabra (\\b…\\b) → "videollamada" no matchea "video".
      2. Match más largo primero → "video llamada" cuenta como voip; "video"
         de youtube ya no ve ese span porque lo tachamos al consumirlo.
      3. Cada app se registra una sola vez aunque tenga múltiples keywords.
    """
    import re as _re
    t = (text or "").lower()
    if not t:
        return []

    # Aplanamos catálogo a (len_descendente, app_id, keyword) — frases largas
    # primero para que se consuman antes de las palabras sueltas.
    all_keys = []
    for app_id, keys in _KEYWORD_MAP.items():
        for kw in keys:
            all_keys.append((len(kw), app_id, kw))
    all_keys.sort(reverse=True)

    found = []
    seen  = set()
    masked = t   # cada match consume su span (lo sustituye por espacios)
    for _ln, app_id, kw in all_keys:
        pattern = r"\b" + _re.escape(kw) + r"\b"
        m = _re.search(pattern, masked)
        if not m:
            continue
        if app_id not in seen:
            found.append({"app": app_id})
            seen.add(app_id)
        masked = masked[:m.start()] + (" " * (m.end() - m.start())) + masked[m.end():]
    return found


def _resolve_default_host(default_host=None):
    """Elige host por defecto: el indicado, o el primer host disponible.

    Prefiere h* sobre srv* — la QoS por intent es para "el usuario", no para
    los servidores.
    """
    hp = _load_host_port_map()
    if default_host and default_host in hp:
        return default_host
    hosts = sorted([h for h in hp.keys() if h.startswith("h")])
    if hosts:
        return hosts[0]
    return next(iter(sorted(hp.keys())), None)


# ─── Helpers de catálogo / topología ────────────────────────────────────────

def _load_host_port_map():
    if not os.path.exists(HOST_PORT_FILE):
        return {}
    try:
        with open(HOST_PORT_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}


def _resolve_host_port(host):
    """Resuelve `host` (p.ej. 'h1') al puerto OVS adyacente (p.ej. 's1-eth2')."""
    hp = _load_host_port_map()
    if host in hp:
        return hp[host]
    # tolera 'srv1' u otros endpoints igual
    return None


def _write_qos_event(port, event_type, app_id=None, tier=None, classid=None):
    """Persiste un evento en qos_history.json (visible en el timeline del dashboard)."""
    history = []
    if os.path.exists(QOS_HISTORY):
        try:
            with open(QOS_HISTORY, encoding="utf-8") as f:
                history = json.load(f)
        except (IOError, json.JSONDecodeError):
            pass
    history.append({
        "ts":     datetime.now().isoformat(timespec="seconds"),
        "port":   port,
        "event":  event_type,
        "action": "USER_INTENT",
        "app":    app_id,
        "tier":   tier,
        "classid": classid,
    })
    if len(history) > 300:
        history = history[-300:]
    try:
        with open(QOS_HISTORY, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False)
    except IOError:
        pass


def _save_state(plan):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(plan, f, ensure_ascii=False, indent=2)
    except IOError:
        pass


def load_state():
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None


def _clear_state():
    try:
        os.remove(STATE_FILE)
    except FileNotFoundError:
        pass


# ─── Construcción y validación del plan ──────────────────────────────────────

def build_qos_plan(target_host, apps_request, total_mbps=50.0):
    """Construye un plan QoS estructurado a partir de una solicitud de alto nivel.

    target_host:    nombre del host destinatario (ej. 'h1').
    apps_request:   lista de {"app": str, "min_mbps"?: float, "max_mbps"?: float}.
                    Solo "app" es obligatorio; el resto cae a los defaults del
                    catálogo.
    total_mbps:     velocidad total de línea para el HTB raíz.

    Devuelve un dict listo para apply_qos_plan(), o lanza ValueError describiendo
    el primer problema encontrado.
    """
    if total_mbps is None or total_mbps <= 0:
        raise ValueError("total_mbps debe ser > 0")

    target_port = _resolve_host_port(target_host)
    if not target_port:
        # En vez de fallar, intentamos describir qué hosts hay disponibles
        # — útil para el LLM si se equivoca de nombre.
        available = sorted(_load_host_port_map().keys())
        raise ValueError(
            f"Host '{target_host}' no está en host_port_map.json. "
            f"Hosts disponibles: {available}"
        )

    if not apps_request:
        raise ValueError("La lista de apps está vacía. Indica al menos una.")

    resolved = []
    used_services = {}
    for item in apps_request:
        if isinstance(item, str):
            app_id = item
            override = {}
        else:
            app_id  = item.get("app")
            override = item
        if not app_id:
            raise ValueError("Entrada sin 'app'.")
        meta = apps_catalog.get_app(app_id)
        if not meta:
            raise ValueError(
                f"App '{app_id}' no está en el catálogo. "
                f"Apps válidas: {apps_catalog.list_apps()}"
            )
        svc = apps_catalog.resolve_service(app_id)
        if not svc:
            raise ValueError(f"App '{app_id}' apunta a un servicio desconocido.")
        if svc.get("dport") is None:
            raise ValueError(
                f"App '{app_id}' usa un protocolo sin dport (ej. ICMP); "
                "no se puede separar en HTB por filtro u32."
            )
        if meta["service"] in used_services:
            raise ValueError(
                f"Conflicto: '{app_id}' y '{used_services[meta['service']]}' "
                f"comparten el servicio '{meta['service']}'. Elige solo una."
            )
        used_services[meta["service"]] = app_id

        tier   = meta["tier"]
        classid = apps_catalog.TIER_CLASSID[tier]
        min_m = float(override.get("min_mbps") if override.get("min_mbps") is not None else meta["min_mbps"])
        max_m = override.get("max_mbps", meta["max_mbps"])
        if max_m is not None:
            max_m = float(max_m)
        if min_m <= 0:
            raise ValueError(f"min_mbps de '{app_id}' debe ser > 0")
        if max_m is not None and max_m < min_m:
            raise ValueError(f"max_mbps < min_mbps en '{app_id}'")

        resolved.append({
            "app":         app_id,
            "description": meta["description"],
            "service":     meta["service"],
            "tier":        tier,
            "classid":     classid,
            "priority":    apps_catalog.TIER_PRIORITY[tier],
            "min_mbps":    min_m,
            "max_mbps":    max_m,
            "ip_proto":    svc["ip_proto"],
            "dport":       svc["dport"],
            "transport":   svc.get("transport"),
        })

    # Si la suma de mínimos excede la línea, escalamos proporcionalmente.
    total_min = sum(a["min_mbps"] for a in resolved)
    capped = False
    if total_min > total_mbps:
        factor = total_mbps / total_min
        for a in resolved:
            a["min_mbps"] = round(a["min_mbps"] * factor, 2)
        capped = True

    return {
        "target_host": target_host,
        "target_port": target_port,
        "total_mbps":  float(total_mbps),
        "apps":        resolved,
        "capped":      capped,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }


# ─── Aplicación del plan vía tc ──────────────────────────────────────────────

def _tc_proto_match(ip_proto, dport):
    parts = [f"match ip protocol {ip_proto} 0xff"]
    if dport is not None:
        parts.append(f"match ip dport {dport} 0xffff")
    return " ".join(parts)


def apply_qos_plan(plan):
    """Traduce el plan a comandos tc y los ejecuta sobre el puerto del host.

    Idempotente: borra cualquier qdisc raíz previo antes de construir el árbol.
    Persiste el estado en STATE_FILE y deja eventos en qos_history.json para
    que el dashboard los muestre en el timeline.
    """
    port    = plan["target_port"]
    total   = plan["total_mbps"]
    apps    = plan["apps"]

    # Default tier: best_effort. Las apps sin filtro caen aquí, igual que el
    # resto de tráfico del puerto. Si ninguna app es best_effort, se crea
    # vacía con rate mínima para no romper la jerarquía.
    tiers_in_plan = {a["tier"] for a in apps}
    if "best_effort" not in tiers_in_plan:
        tiers_in_plan.add("best_effort")

    ssh = get_ssh_connection()

    # Limpia qdisc previo (idempotencia).
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
    time.sleep(0.2)

    # Raíz HTB, default → best_effort (1:40).
    send_tmux_command(
        ssh, f"sh tc qdisc add dev {port} root handle 1: htb default 40"
    )
    time.sleep(0.1)

    # Crea las clases para los tiers presentes en el plan. Cada tier obtiene
    # una "rate garantizada" igual a la suma de mínimos de sus apps (o un
    # mínimo simbólico de 0.5 Mbps si no hay apps) y ceil = total_mbps para
    # permitir borrow.
    tier_rates = {t: 0.0 for t in tiers_in_plan}
    for a in apps:
        tier_rates[a["tier"]] += a["min_mbps"]
    for t, rate in tier_rates.items():
        if rate <= 0:
            tier_rates[t] = 0.5

    for tier in sorted(tiers_in_plan, key=lambda t: apps_catalog.TIER_PRIORITY[t]):
        classid = apps_catalog.TIER_CLASSID[tier]
        prio    = apps_catalog.TIER_PRIORITY[tier]
        rate    = tier_rates[tier]
        send_tmux_command(
            ssh,
            f"sh tc class add dev {port} parent 1: classid {classid} htb "
            f"rate {rate:.2f}mbit ceil {total:.2f}mbit prio {prio}",
        )
        time.sleep(0.05)

    # Un filtro u32 por app: matchea (ip_proto, dport) → flowid del tier.
    for a in apps:
        match = _tc_proto_match(a["ip_proto"], a["dport"])
        send_tmux_command(
            ssh,
            f"sh tc filter add dev {port} parent 1: protocol ip prio 1 u32 "
            f"{match} flowid {a['classid']}",
        )
        time.sleep(0.05)
        _write_qos_event(
            port, "intent_apply",
            app_id=a["app"], tier=a["tier"], classid=a["classid"],
        )

    ssh.close()
    _save_state(plan)
    return plan


def clear_qos_intent():
    """Elimina el HTB user-intent y borra el estado persistente.

    Devuelve el plan que estaba activo (o None si no había nada).
    """
    plan = load_state()
    if not plan:
        return None
    port = plan.get("target_port")
    if not port:
        _clear_state()
        return plan
    try:
        ssh = get_ssh_connection()
        send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
        ssh.close()
    except Exception as _e:
        # No fallar el clear por SSH caída: igualmente borramos estado local.
        print(f"[QoS-INTENT] WARN clear vía SSH falló: {_e}")
    _write_qos_event(port, "intent_clear")
    _clear_state()
    return plan


# ─── LLM: NL → JSON estructurado ─────────────────────────────────────────────

_TOOL_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "build_qos_plan",
            "description": (
                "Construye un plan QoS para un host. Selecciona apps del "
                "catálogo y opcionalmente ajusta sus mínimos/máximos."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_host": {
                        "type": "string",
                        "description": "Host del usuario (ej. 'h1', 'h2')."
                    },
                    "total_mbps": {
                        "type": "number",
                        "description": "Velocidad total de línea en Mbps."
                    },
                    "apps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "app": {
                                    "type": "string",
                                    "description": "Clave del catálogo de aplicaciones.",
                                },
                                "min_mbps": {"type": "number"},
                                "max_mbps": {"type": "number"},
                            },
                            "required": ["app"],
                        },
                        "description": "Lista de apps que el usuario quiere usar.",
                    },
                },
                "required": ["target_host", "apps"],
            },
        },
    }
]


def parse_qos_intent_llm(user_text, default_host=None, default_total_mbps=50.0):
    """Convierte NL → plan estructurado.

    Intenta primero con Ollama tool calling; si el modelo no responde a
    tiempo o falla, cae a parse_qos_intent_heuristic (keywords) sin levantar
    excepción. El plan resultante lleva el campo `parsed_by`:
      - "llm"        → el modelo emitió el tool call
      - "heuristic"  → fallback por keywords
    """
    available_hosts = sorted(_load_host_port_map().keys())
    catalog_lines   = apps_catalog.describe_catalog()

    fallback_host = _resolve_default_host(default_host)

    def _from_heuristic(reason):
        apps = parse_qos_intent_heuristic(user_text)
        if not apps:
            raise ValueError(
                f"No pude identificar ninguna app del catálogo en tu mensaje. "
                f"{reason} Apps soportadas: {apps_catalog.list_apps()}"
            )
        plan = build_qos_plan(fallback_host, apps, default_total_mbps)
        plan["parsed_by"] = "heuristic"
        plan["fallback_reason"] = reason
        return plan

    system_prompt = (
        "Eres un planificador de QoS para una red Mininet. Recibes en lenguaje "
        "natural lo que un usuario quiere hacer (apps, servicios) en su host "
        "y devuelves un plan estructurado llamando a build_qos_plan.\n\n"
        f"HOSTS DISPONIBLES: {available_hosts}\n"
        f"VELOCIDAD POR DEFECTO: {default_total_mbps} Mbps "
        "(úsala salvo que el usuario indique otra).\n"
        f"HOST POR DEFECTO si no se menciona: {fallback_host or 'el primero disponible'}\n\n"
        "CATÁLOGO DE APPS (usa SOLO estas claves):\n"
        f"{catalog_lines}\n\n"
        "REGLAS:\n"
        "1. Mapea cada descripción del usuario a una clave EXACTA del catálogo. "
        "Ejemplos: 'YouTube'/'Netflix'/'streaming' → youtube; 'llamada'/"
        "'teléfono'/'voz' → voip; 'descargar Linux'/'ISO'/'descarga grande' → "
        "linux_iso; 'navegar'/'web' → web_browsing.\n"
        "2. NO inventes apps fuera del catálogo. Si el usuario pide algo que no "
        "encaja, ignóralo o aproxima al más parecido.\n"
        "3. Cada app aparece UNA SOLA VEZ. Si el usuario menciona dos cosas que "
        "mapearían al mismo servicio, elige la más adecuada.\n"
        "4. Si el usuario no da números, omite min_mbps/max_mbps (se usarán los "
        "del catálogo).\n"
        "5. LLAMA SIEMPRE a build_qos_plan. NO respondas en texto plano."
    )

    try:
        response = _ollama_client.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_text},
            ],
            tools=_TOOL_SCHEMA,
            options={"temperature": 0},
        )
    except Exception as e:
        # Timeout, connection refused, etc. → cae al fallback heurístico.
        return _from_heuristic(
            f"El LLM no respondió ({type(e).__name__}). Usé reconocimiento "
            "por palabras clave."
        )

    msg = response.get("message", {}) or {}
    tool_calls = msg.get("tool_calls") or []
    if not tool_calls:
        return _from_heuristic(
            "El LLM no llamó a la herramienta. Usé reconocimiento por palabras clave."
        )

    args = tool_calls[0]["function"].get("arguments") or {}
    target_host = args.get("target_host") or fallback_host
    if not target_host and available_hosts:
        target_host = available_hosts[0]
    total = args.get("total_mbps") or default_total_mbps
    apps  = args.get("apps") or []

    try:
        plan = build_qos_plan(target_host, apps, total)
        plan["parsed_by"] = "llm"
        return plan
    except ValueError as ve:
        # El LLM devolvió algo válido pero no parseable (apps inventadas,
        # conflictos…). Intentamos rescatarlo con el fallback.
        return _from_heuristic(
            f"El LLM dio un plan inválido ({ve}). Usé reconocimiento por "
            "palabras clave."
        )
