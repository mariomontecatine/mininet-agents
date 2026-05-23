"""Catálogo de aplicaciones soportadas por el plan QoS declarativo.

Cada entrada describe una "app" en lenguaje de usuario (youtube, voip…) y la
asocia a:
  - service: clave de utils.config.SERVICE_DEFS (define ip_proto + dport)
  - tier:    'interactive' | 'streaming' | 'bulk' | 'best_effort'
  - priority: 0 (top) .. 3. Determina la clase HTB de destino.
  - min_mbps / max_mbps: garantía y techo orientativos por defecto.

El LLM mapea texto en NL a estas claves. La tool de tc construye HTB a partir
del tier+priority y filtra por (ip_proto, dport) usando SERVICE_DEFS.

Limitación honesta: en una sim Mininet sin DPI no podemos identificar
"YouTube" por SNI. Mapeamos cada app a un servicio distinto del catálogo
SERVICE_DEFS (https/sip/http_alt/…) para que las clases sean separables por
puerto. En una demo educativa esto basta y se documenta como aproximación.
"""

from utils import config


# Mapping app_id → metadata.
# Mantener cada app sobre un service DISTINTO siempre que sea posible, para que
# el filtro u32 por (ip_proto, dport) los pueda separar en clases HTB.
APPLICATIONS = {
    "voip": {
        "description":  "Llamadas de voz/vídeo en tiempo real (SIP/RTP). Latencia baja, BW pequeño.",
        "service":      "sip",
        "tier":         "interactive",
        "priority":     0,
        "min_mbps":     1.0,
        "max_mbps":     4.0,
    },
    "dns": {
        "description":  "Resolución DNS. Mínimo absoluto, prioridad máxima.",
        "service":      "dns",
        "tier":         "interactive",
        "priority":     0,
        "min_mbps":     0.5,
        "max_mbps":     2.0,
    },
    "ssh": {
        "description":  "Sesiones SSH interactivas. Latencia baja, ráfagas cortas.",
        "service":      "ssh",
        "tier":         "interactive",
        "priority":     0,
        "min_mbps":     0.5,
        "max_mbps":     2.0,
    },
    "youtube": {
        "description":  "Streaming de vídeo (YouTube/Netflix). Necesita BW estable, tolera 1-2s buffer.",
        "service":      "https",
        "tier":         "streaming",
        "priority":     1,
        "min_mbps":     5.0,
        "max_mbps":     25.0,
    },
    "web_browsing": {
        "description":  "Navegación HTTP general (no descarga grande).",
        "service":      "http",
        "tier":         "streaming",
        "priority":     1,
        "min_mbps":     2.0,
        "max_mbps":     10.0,
    },
    "linux_iso": {
        "description":  "Descarga grande (ISO, backups). Tolerante a latencia, debe ceder ante interactivo.",
        "service":      "http_alt",
        "tier":         "bulk",
        "priority":     2,
        "min_mbps":     1.0,
        "max_mbps":     None,
    },
    "ftp_download": {
        "description":  "Transferencia FTP de archivos. Bulk, sin requisitos de latencia.",
        "service":      "ftp",
        "tier":         "bulk",
        "priority":     2,
        "min_mbps":     1.0,
        "max_mbps":     None,
    },
    "email": {
        "description":  "Envío/recepción de correo (SMTP). Tolerante a latencia.",
        "service":      "smtp",
        "tier":         "best_effort",
        "priority":     2,
        "min_mbps":     0.5,
        "max_mbps":     5.0,
    },
}


# Tier → classid HTB (la tool de qos_intent construye la jerarquía con estas).
# 0/1/2 ya están reservados por HTB; usamos 10/20/30/40 igual que apply_shaping.
TIER_CLASSID = {
    "interactive":  "1:10",
    "streaming":    "1:20",
    "bulk":         "1:30",
    "best_effort":  "1:40",
}

TIER_PRIORITY = {
    "interactive":  0,
    "streaming":    1,
    "bulk":         2,
    "best_effort":  3,
}


def list_apps():
    """Lista las claves del catálogo (para enseñar al LLM y para el frontend)."""
    return sorted(APPLICATIONS.keys())


def get_app(app_id):
    """Devuelve la metadata de una app o None si no existe."""
    return APPLICATIONS.get(app_id)


def resolve_service(app_id):
    """Devuelve la entrada de SERVICE_DEFS asociada a la app, o None."""
    app = APPLICATIONS.get(app_id)
    if not app:
        return None
    svc_key = app.get("service")
    return config.SERVICE_DEFS.get(svc_key)


def describe_catalog():
    """Devuelve una vista compacta para inyectar en el system prompt del LLM."""
    lines = []
    for key in list_apps():
        a = APPLICATIONS[key]
        max_s = f"{a['max_mbps']}" if a.get("max_mbps") is not None else "∞"
        lines.append(
            f"  - {key}: {a['description']} "
            f"[service={a['service']} tier={a['tier']} "
            f"min={a['min_mbps']}Mbps max={max_s}Mbps]"
        )
    return "\n".join(lines)
