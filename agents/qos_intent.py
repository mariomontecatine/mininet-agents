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
from agents.central_link import load_central_link


TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
STATE_FILE      = os.path.join(TMP_DIR, "qos_intent_state.json")
HOST_PORT_FILE  = os.path.join(TMP_DIR, "host_port_map.json")
QOS_HISTORY     = os.path.join(TMP_DIR, "qos_history.json")
SERVER_SERVICES = os.path.join(TMP_DIR, "server_services.json")

MODEL_NAME = getattr(config, "MODEL_QOS_INTENT", config.MODEL_RESOLVER)

# Timeout generoso (config.QOS_INTENT_LLM_TIMEOUT). Priorizamos que el LLM
# conteste sobre la velocidad — esto es una prueba de concepto donde interesa
# medir la precisión real del modelo, no la latencia. El fallback heurístico
# solo entra si el LLM agota el tiempo o devuelve algo imposible de parsear, y
# se puede desactivar del todo con config.QOS_INTENT_LLM_ONLY.
_QOS_LLM_TIMEOUT = getattr(config, "QOS_INTENT_LLM_TIMEOUT", 600)

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

# Frases que indican que la prioridad es para TODA la red (ámbito 'network'):
# se aplica en el troncal del router central, no en un host concreto.
_NETWORK_SCOPE_PATTERNS = [
    "en la red", "toda la red", "red entera", "a nivel de red", "en toda la red",
    "para la red", "de la red", "a partir de ahora", "todo el tráfico",
    "todo el trafico", "global", "en todos los hosts", "siempre que haya",
]


def _detect_network_scope(text):
    """True si el usuario pide priorizar a nivel de red (no en un host)."""
    t = (text or "").lower()
    return any(p in t for p in _NETWORK_SCOPE_PATTERNS)


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


# ─── Estado multi-plan ───────────────────────────────────────────────────────
# qos_intent_state.json guarda AHORA un dict {target_port: plan}. Así pueden
# coexistir varios planes a la vez (uno por host/puerto). Aplicar un plan a un
# puerto que ya tiene uno FUSIONA las apps en vez de reemplazarlas.
#
# Compat: si el fichero trae el formato antiguo (un único plan plano con
# 'target_port'), lo migramos a {port: plan} al leerlo.

def normalize_plans(data) -> dict:
    """Normaliza el contenido de qos_intent_state.json a {target_port: plan}.

    Acepta el formato actual (dict por puerto) y el antiguo (un único plan
    plano con 'target_port'). Reutilizable por el dashboard para leer el
    estado de un run guardado sin tocar la ruta fija de tmp/.
    """
    if not isinstance(data, dict):
        return {}
    if "target_port" in data and "apps" in data:   # formato antiguo
        return {data["target_port"]: data}
    return data


def _load_plans() -> dict:
    """Devuelve {target_port: plan}. Migra el formato antiguo si hace falta."""
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}
    return normalize_plans(data)


def _save_plans(plans: dict):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(plans, f, ensure_ascii=False, indent=2)
    except IOError:
        pass


def load_active_plans() -> list:
    """Lista de planes activos (para el dashboard)."""
    return list(_load_plans().values())


def load_state():
    """Compat: devuelve el primer plan activo o None (API antigua)."""
    plans = load_active_plans()
    return plans[0] if plans else None


def _clear_state():
    try:
        os.remove(STATE_FILE)
    except FileNotFoundError:
        pass


# ─── Construcción y validación del plan ──────────────────────────────────────

def build_qos_plan(target_host, apps_request, total_mbps=50.0, scope="host"):
    """Construye un plan QoS estructurado a partir de una solicitud de alto nivel.

    target_host:    nombre del host destinatario (ej. 'h1'). Se ignora si
                    scope='network'.
    apps_request:   lista de {"app": str, "min_mbps"?: float, "max_mbps"?: float}.
                    Solo "app" es obligatorio; el resto cae a los defaults del
                    catálogo.
    total_mbps:     velocidad total de línea para el HTB raíz.
    scope:          'host'    → se aplica en el puerto OVS del host (borde).
                    'network' → se aplica en el troncal del router CENTRAL
                                (tmp/central_link.json), donde se concentra y
                                satura el tráfico entre subredes.

    Devuelve un dict listo para apply_qos_plan(), o lanza ValueError describiendo
    el primer problema encontrado.
    """
    if total_mbps is None or total_mbps <= 0:
        raise ValueError("total_mbps debe ser > 0")

    central = None
    if scope == "network":
        central = load_central_link()
        if not central or not central.get("shaping_port"):
            raise ValueError(
                "No hay enlace central calculado todavía. Despliega la red "
                "(se calcula al arrancar) y reintenta."
            )
        target_port = central["shaping_port"]
        # Etiqueta legible para el dashboard: el troncal del switch central.
        target_host = f"RED · {central['central_switch']}"
    else:
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
        "scope":       scope,
        "central":     central if scope == "network" else None,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }


# ─── Aplicación del plan vía tc ──────────────────────────────────────────────

def _tc_proto_match(ip_proto, dport):
    parts = [f"match ip protocol {ip_proto} 0xff"]
    if dport is not None:
        parts.append(f"match ip dport {dport} 0xffff")
    return " ".join(parts)


def build_tc_commands(plan):
    """Devuelve la lista EXACTA de comandos tc que aplicarían el plan.

    Es la única fuente de verdad: _emit_tc_for_plan los ejecuta y la interfaz
    los muestra. El prefijo "sh " es el comando de la CLI de Mininet para
    ejecutarlos en el shell de la VM (los puertos OVS viven en el root netns).

    Cada entrada es {"cmd": <str>, "note": <explicación corta en español>}.
    """
    port  = plan["target_port"]
    total = plan["total_mbps"]
    apps  = plan["apps"]

    tiers_in_plan = {a["tier"] for a in apps}
    if "best_effort" not in tiers_in_plan:
        tiers_in_plan.add("best_effort")

    tier_rates = {t: 0.0 for t in tiers_in_plan}
    for a in apps:
        tier_rates[a["tier"]] += a["min_mbps"]
    for t, rate in tier_rates.items():
        if rate <= 0:
            tier_rates[t] = 0.5

    cmds = []
    cmds.append({
        "cmd": f"sh tc qdisc del dev {port} root 2>/dev/null; true",
        "note": "Borra cualquier QoS previa en el puerto (idempotencia).",
    })
    cmds.append({
        "cmd": f"sh tc qdisc add dev {port} root handle 1: htb default 40",
        "note": ("Crea el árbol HTB raíz. El tráfico sin filtro cae en la clase "
                 "1:40 (tier 'normal')."),
    })
    # Clase raíz 1:1 = la línea total. Todas los carriles cuelgan de ella, así
    # que su ceil impone el techo agregado (la suma nunca pasa de la línea) y
    # los carriles se prestan entre sí el ancho libre (el préstamo HTB es del
    # padre común).
    cmds.append({
        "cmd": (f"sh tc class add dev {port} parent 1: classid 1:1 htb "
                f"rate {total:.2f}mbit ceil {total:.2f}mbit"),
        "note": (f"Clase raíz = la línea total ({total:.2f} Mbps). Techo agregado: "
                 "la suma de los carriles nunca lo supera, y entre ellos se "
                 "prestan el ancho que sobre."),
    })
    for tier in sorted(tiers_in_plan, key=lambda t: apps_catalog.TIER_PRIORITY[t]):
        classid = apps_catalog.TIER_CLASSID[tier]
        prio    = apps_catalog.TIER_PRIORITY[tier]
        rate    = tier_rates[tier]
        label   = apps_catalog.TIER_LABEL.get(tier, tier)
        cmds.append({
            "cmd": (f"sh tc class add dev {port} parent 1:1 classid {classid} htb "
                    f"rate {rate:.2f}mbit ceil {total:.2f}mbit prio {prio}"),
            "note": (f"Carril '{label}': garantiza {rate:.2f} Mbps, puede subir hasta "
                     f"{total:.2f} Mbps si hay hueco. prio {prio} = "
                     f"{'máxima' if prio == 0 else 'prioridad ' + str(prio)}."),
        })
    for a in apps:
        match = _tc_proto_match(a["ip_proto"], a["dport"])
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(a["ip_proto"], str(a["ip_proto"]))
        cmds.append({
            "cmd": (f"sh tc filter add dev {port} parent 1: protocol ip prio 1 u32 "
                    f"{match} flowid {a['classid']}"),
            "note": (f"{a['app']}: envía el tráfico {proto_name} puerto {a['dport']} "
                     f"al carril {a['classid']} ({apps_catalog.TIER_LABEL.get(a['tier'], a['tier'])})."),
        })
    return cmds


def _emit_tc_for_plan(ssh, plan):
    """Emite el árbol HTB completo de un plan sobre su puerto. No toca estado.

    Idempotente: borra el qdisc raíz previo y reconstruye con TODAS las apps
    del plan (clases por tier + un filtro u32 por app). Usa build_tc_commands
    como fuente única de los comandos.
    """
    port  = plan["target_port"]
    cmds  = build_tc_commands(plan)
    for i, entry in enumerate(cmds):
        send_tmux_command(ssh, entry["cmd"])
        # El borrado inicial necesita más margen; el resto va rápido.
        time.sleep(0.2 if i == 0 else 0.05)
    # Eventos para el timeline (uno por app).
    for a in plan["apps"]:
        _write_qos_event(port, "intent_apply",
                         app_id=a["app"], tier=a["tier"], classid=a["classid"])


def _merge_apps(existing_apps, new_apps):
    """Fusiona apps de un plan existente con las nuevas; las nuevas ganan.

    Una app vieja se descarta si colisiona con una nueva por app_id o por
    servicio (mismo dport) — así el HTB nunca tiene dos filtros para el mismo
    servicio. Devuelve lista de dicts {app, min_mbps, max_mbps} reaplicable.
    """
    new_ids      = {a["app"] for a in new_apps}
    new_services = {a["service"] for a in new_apps}
    merged = []
    for a in existing_apps:
        if a["app"] in new_ids or a["service"] in new_services:
            continue
        merged.append({"app": a["app"], "min_mbps": a["min_mbps"], "max_mbps": a["max_mbps"]})
    for a in new_apps:
        merged.append({"app": a["app"], "min_mbps": a["min_mbps"], "max_mbps": a["max_mbps"]})
    return merged


def apply_qos_plan(plan):
    """Aplica un plan al puerto de su host. Si el puerto YA tenía un plan,
    fusiona las apps (las nuevas ganan) y reconstruye el árbol completo, de
    modo que planes de hosts distintos coexisten y aplicar al mismo host
    acumula servicios en vez de reemplazarlos.

    Devuelve el plan efectivamente aplicado (fusionado si procede).
    """
    port = plan["target_port"]
    host = plan["target_host"]

    plans = _load_plans()
    if port in plans:
        merged_apps = _merge_apps(plans[port].get("apps", []), plan["apps"])
        # Reconstruye (revalida + recalcula capping con la línea más reciente).
        merged = build_qos_plan(host, merged_apps, plan["total_mbps"],
                                scope=plan.get("scope", "host"))
        merged["parsed_by"] = plan.get("parsed_by")
        merged["merged_from"] = len(plans[port].get("apps", []))
        plan = merged

    # Adjuntamos los comandos tc al plan para que la interfaz los muestre y se
    # persistan junto al estado.
    plan["tc_commands"] = build_tc_commands(plan)

    ssh = get_ssh_connection()
    _emit_tc_for_plan(ssh, plan)
    ssh.close()

    plans[port] = plan
    _save_plans(plans)
    return plan


def clear_qos_intent(target=None):
    """Elimina planes user-intent.

    target=None      → limpia TODOS los planes activos.
    target='h1'      → limpia solo el del host h1.
    target='s1-eth2' → limpia solo el de ese puerto OVS.

    Devuelve la lista de planes eliminados (vacía si no había nada).
    """
    plans = _load_plans()
    if not plans:
        return []

    if target is None:
        ports = list(plans.keys())
    else:
        port = target if target in plans else _resolve_host_port(target)
        ports = [port] if port in plans else []

    if not ports:
        return []

    ssh = None
    try:
        ssh = get_ssh_connection()
    except Exception as _e:
        print(f"[QoS-INTENT] WARN clear vía SSH falló: {_e}")

    cleared = []
    for port in ports:
        if ssh:
            send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
        _write_qos_event(port, "intent_clear")
        cleared.append(plans.pop(port))
    if ssh:
        ssh.close()

    if plans:
        _save_plans(plans)
    else:
        _clear_state()
    return cleared


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
                        "description": "Host del usuario (ej. 'h1', 'h2'). Solo si scope='host'."
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["host", "network"],
                        "description": ("'host' = priorizar para un host concreto. "
                                        "'network' = priorizar ese tráfico en TODA la "
                                        "red (se aplica en el router central). Usa "
                                        "'network' si el usuario dice 'en la red', "
                                        "'toda la red' o 'a partir de ahora'."),
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


def _extract_args_from_text(text):
    """Intenta sacar {target_host?, total_mbps?, apps:[...]} de texto plano.

    Algunos modelos pequeños no emiten tool_call y devuelven el JSON dentro de
    la respuesta (a veces en un bloque ```json). Buscamos el primer objeto JSON
    que contenga la clave "apps". Devuelve el dict o None.
    """
    if not text:
        return None
    # 1) Bloques ```json ... ``` o ``` ... ```
    candidates = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    # 2) Cualquier objeto {...} con "apps" dentro (búsqueda con balance simple)
    if not candidates:
        candidates = re.findall(r"(\{[^{}]*\"apps\"[^{}]*\[.*?\][^{}]*\})", text, re.DOTALL)
    for cand in candidates:
        try:
            data = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("apps"):
            return data
    return None


def parse_qos_intent_llm(user_text, default_host=None, default_total_mbps=50.0,
                         llm_only=None):
    """Convierte NL → plan estructurado usando el LLM como motor principal.

    Orden de resolución:
      1. tool_call de Ollama (lo ideal).
      2. JSON embebido en la respuesta de texto (modelos que ignoran tools=).
      3. Fallback heurístico por keywords — SOLO si llm_only es False.

    El plan resultante lleva `parsed_by`: "llm", "llm_text" o "heuristic".

    llm_only: si True, nunca usa el heurístico (lanza ValueError si el LLM
    falla). Por defecto toma config.QOS_INTENT_LLM_ONLY.
    """
    if llm_only is None:
        llm_only = getattr(config, "QOS_INTENT_LLM_ONLY", False)

    available_hosts = sorted(_load_host_port_map().keys())
    catalog_lines   = apps_catalog.describe_catalog()
    fallback_host   = _resolve_default_host(default_host)
    # El ámbito de red lo decide en última instancia el texto del usuario: si
    # menciona "la red"/"a partir de ahora", forzamos scope='network' aunque el
    # LLM no lo haya marcado (los modelos pequeños lo olvidan a menudo).
    text_network_scope = _detect_network_scope(user_text)

    def _from_heuristic(reason):
        if llm_only:
            raise ValueError(
                f"{reason} (Modo LLM-only activado: no se usa el reconocimiento "
                "por palabras clave. Reintenta o revisa el modelo en config.)"
            )
        apps = parse_qos_intent_heuristic(user_text)
        if not apps:
            raise ValueError(
                f"No pude identificar ninguna app del catálogo en tu mensaje. "
                f"{reason} Apps soportadas: {apps_catalog.list_apps()}"
            )
        scope = "network" if text_network_scope else "host"
        plan = build_qos_plan(fallback_host, apps, default_total_mbps, scope=scope)
        plan["parsed_by"] = "heuristic"
        plan["fallback_reason"] = reason
        return plan

    def _build_from_args(args, source):
        scope = "network" if (text_network_scope or args.get("scope") == "network") else "host"
        target_host = args.get("target_host") or fallback_host
        if not target_host and available_hosts:
            target_host = available_hosts[0]
        total = args.get("total_mbps") or default_total_mbps
        apps  = args.get("apps") or []
        plan = build_qos_plan(target_host, apps, total, scope=scope)
        plan["parsed_by"] = source
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
        "5. ÁMBITO: si el usuario habla de un host concreto ('en h1', 'para h3') "
        "usa scope='host' con ese target_host. Si habla de TODA la red ('en la "
        "red', 'toda la red', 'a partir de ahora prioriza...') usa "
        "scope='network' (no hace falta target_host: se aplica en el router "
        "central).\n"
        "6. LLAMA a build_qos_plan. Si por algún motivo no puedes, responde con "
        "el JSON {\"scope\":..., \"target_host\":..., \"total_mbps\":..., \"apps\":[{\"app\":...}]}."
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
        return _from_heuristic(f"El LLM no respondió ({type(e).__name__}).")

    msg = response.get("message", {}) or {}

    # 1) tool_call
    tool_calls = msg.get("tool_calls") or []
    if tool_calls:
        args = tool_calls[0]["function"].get("arguments") or {}
        try:
            return _build_from_args(args, "llm")
        except ValueError as ve:
            return _from_heuristic(f"El LLM dio un plan inválido ({ve}).")

    # 2) JSON embebido en texto plano
    args = _extract_args_from_text(msg.get("content") or "")
    if args:
        try:
            return _build_from_args(args, "llm_text")
        except ValueError as ve:
            return _from_heuristic(f"El LLM dio un plan inválido en texto ({ve}).")

    # 3) Heurístico (si está permitido)
    return _from_heuristic("El LLM no llamó a la herramienta ni devolvió JSON.")
