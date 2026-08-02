"""Servidor MCP del NOC: QoS y telemetría como capacidades estándar.

Hasta ahora las capacidades de QoS vivían dentro de un esquema de tools escrito
a mano (agents/qos_intent.py, _TOOL_SCHEMA) para una llamada concreta a Ollama:
el contrato estaba acoplado al modelo y al proceso. Aquí se publican por MCP
(Model Context Protocol), de modo que cualquier cliente compatible — el
Inspector, un editor, o el analista de agents/noc_analyst.py — descubre las
mismas herramientas sin conocer nada del código.

Reparto de responsabilidades:
  · Tools de LECTURA y de construcción de plan → importan los módulos de
    agents/ directamente. Son funciones puras sobre ficheros: sin SSH ni estado
    compartido, así que no hay carrera posible.
  · Tools de ESCRITURA → van por la API del dashboard (mcp_server/api_client.py).
    El porqué está documentado en ese módulo: evitar un segundo escritor
    concurrente sobre la sesión tmux de la VM y sobre qos_intent_state.json.

Arranque:
    python -m mcp_server.server                          # stdio (Inspector)
    python -m mcp_server.server --transport streamable-http
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from utils import config
from agents import apps_catalog, qos_intent, telemetry_digest
from agents.central_link import load_central_link
from mcp_server import api_client


mcp = MCPServer(
    "noc-mininet",
    version="1.0.0",
    instructions=(
        "Herramientas de un centro de operaciones de red (NOC) sobre una "
        "topología Mininet. Permiten consultar telemetría en vivo (tráfico por "
        "puerto, flujos sFlow, anomalías detectadas, mitigaciones activas) y "
        "gestionar la calidad de servicio (QoS) mediante jerarquías HTB de tc.\n\n"
        "Para cambiar QoS, el flujo correcto es: preview_qos_plan para ver el "
        "plan y los comandos tc exactos, y solo después apply_qos_plan. "
        "Los hosts se llaman h1..hN, los servidores srv1..srvN y los puertos "
        "OVS sN-ethM."
    ),
)


def _read_only() -> bool:
    """MCP_READ_ONLY puede venir de config o del entorno (para lanzarlo suelto)."""
    env = os.environ.get("MCP_READ_ONLY")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "si", "sí")
    return bool(getattr(config, "MCP_READ_ONLY", False))


# ═══════════════════════════════════════════════════════════════════════════
# Tools de lectura
# ═══════════════════════════════════════════════════════════════════════════

@mcp.tool(
    description=(
        "Devuelve el catálogo de aplicaciones que se pueden priorizar (voip, "
        "youtube, dns, ssh, linux_iso…), con su categoría de prioridad (tier), "
        "su servicio de red y sus anchos de banda por defecto. Consúltalo antes "
        "de construir un plan QoS para usar identificadores válidos."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def list_qos_catalog() -> dict:
    return {
        "apps": apps_catalog.APPLICATIONS,
        "tiers": apps_catalog.TIER_LABEL,
        "tier_classids": apps_catalog.TIER_CLASSID,
    }


@mcp.tool(
    description=(
        "Lista los hosts y servidores desplegados con el puerto OVS al que "
        "está conectado cada uno, y qué servicio ofrece cada servidor."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def list_hosts() -> dict:
    host_port = telemetry_digest.read_json("host_port_map.json", {}) or {}
    services = telemetry_digest.read_json("server_services.json", {}) or {}
    ip_index = telemetry_digest.host_ip_index()
    name_to_ip = {name: ip for ip, name in ip_index.items()}
    return {
        "hosts": [
            {
                "name": name,
                "ovs_port": port,
                "ip": name_to_ip.get(name),
                "service": services.get(name, {}).get("type"),
            }
            for name, port in sorted(host_port.items())
        ],
        "count": len(host_port),
    }


@mcp.tool(
    description=(
        "Estado actual del NOC: ciclo, estado de la red, intervalo del bucle y "
        "las mitigaciones QoS que el resolver tiene aplicadas ahora mismo."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def get_network_state() -> dict:
    state = telemetry_digest.read_json("state.json", {}) or {}
    return {
        "cycle": state.get("ciclo"),
        "timestamp": state.get("timestamp"),
        "network_state": state.get("estado_red"),
        "cycle_interval_sec": state.get("intervalo_actual"),
        "active_rules": state.get("reglas_activas") or {},
        "last_report": state.get("ultimo_informe"),
    }


@mcp.tool(
    description=(
        "Resumen del tráfico por puerto OVS en los últimos N minutos: bytes "
        "recibidos y transmitidos, Mbps medios y paquetes descartados. Devuelve "
        "solo los puertos más cargados."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def get_traffic_summary(window_min: int = 5) -> dict:
    return telemetry_digest.summarize_ports(window_min=window_min)


@mcp.tool(
    description=(
        "Flujos extremo a extremo del último muestreo sFlow, ordenados por "
        "volumen, con las IPs ya resueltas a nombres de host. Sirve para saber "
        "quién habla con quién y por qué servicio."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def get_top_flows(limit: int = 15) -> dict:
    return telemetry_digest.summarize_flows(top_n=limit)


@mcp.tool(
    description=(
        "Anomalías detectadas por el monitor sobre los flujos sFlow: escaneos "
        "de puertos, DDoS por concentración de orígenes y DoS volumétricos, con "
        "origen, víctima y volumen."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def get_recent_alerts(limit: int = 20) -> dict:
    alerts = telemetry_digest.recent_alerts(limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@mcp.tool(
    description=(
        "Historial de eventos de QoS: cuándo se aplicó, relajó o eliminó cada "
        "restricción y sobre qué puerto y protocolo."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def get_qos_history(limit: int = 20) -> dict:
    events = telemetry_digest.recent_qos_events(limit=limit)
    return {"events": events, "count": len(events)}


@mcp.tool(
    description=(
        "Planes QoS declarativos activos ahora mismo (los pedidos por el "
        "usuario), con las apps priorizadas en cada puerto."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def get_active_qos() -> dict:
    plans = qos_intent.load_active_plans()
    return {"plans": plans, "count": len(plans)}


@mcp.tool(
    description=(
        "Enlace troncal donde se concentra el tráfico entre subredes. Es el "
        "punto correcto para aplicar QoS con alcance de red completa."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def get_central_link() -> dict:
    central = load_central_link()
    return {"central_link": central} if central else {
        "central_link": None,
        "note": "Aún no se ha calculado: requiere una topología desplegada.",
    }


@mcp.tool(
    description=(
        "Construye un plan QoS y devuelve los comandos tc EXACTOS que se "
        "aplicarían, SIN tocar la red. Úsalo siempre antes de apply_qos_plan "
        "para que el operador pueda revisar el reparto de ancho de banda. "
        "Los anchos de banda salen del catálogo; scope 'host' aplica en el "
        "puerto del host y 'network' en el troncal central."
    ),
    annotations=ToolAnnotations(read_only_hint=True),
)
def preview_qos_plan(
    target_host: str,
    apps: list[str],
    total_mbps: float = 50.0,
    scope: str = "host",
) -> dict:
    plan = qos_intent.build_qos_plan(target_host, list(apps), total_mbps, scope=scope)
    plan["tc_commands"] = qos_intent.build_tc_commands(plan)
    return {"plan": plan, "applied": False}


# ═══════════════════════════════════════════════════════════════════════════
# Tools de escritura (vía API del dashboard)
# ═══════════════════════════════════════════════════════════════════════════

def _register_write_tools():
    @mcp.tool(
        description=(
            "APLICA un plan QoS en la red real: instala la jerarquía HTB en el "
            "puerto correspondiente. Si el puerto ya tenía un plan, las apps se "
            "fusionan. Requiere que el NOC esté corriendo. Ejecuta antes "
            "preview_qos_plan y confirma con el operador."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True,
                                    idempotent_hint=True),
    )
    def apply_qos_plan(
        target_host: str,
        apps: list[str],
        total_mbps: float = 50.0,
        scope: str = "host",
    ) -> dict:
        # Se valida en local (función pura) para dar un error claro antes de
        # llegar a la red; el dashboard lo revalida por su cuenta.
        plan = qos_intent.build_qos_plan(target_host, list(apps), total_mbps,
                                         scope=scope)
        result = api_client.post("/api/qos-intent/apply", {"plan": plan})
        return {"plan": result.get("plan"), "applied": True}

    @mcp.tool(
        description=(
            "Aplica QoS a partir de una descripción en lenguaje natural, por "
            "ejemplo 'prioriza las videollamadas en h1' o 'YouTube en 4K sin "
            "cortes'. El NOC traduce el texto a apps del catálogo. Úsala cuando "
            "el usuario describe necesidades en vez de nombrar apps concretas."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True),
    )
    def apply_qos_from_text(
        text: str,
        host: str = "",
        total_mbps: float = 50.0,
    ) -> dict:
        payload = {"text": text, "total_mbps": total_mbps}
        if host:
            payload["host"] = host
        result = api_client.post("/api/qos-intent/apply", payload)
        return {"plan": result.get("plan"), "applied": True}

    @mcp.tool(
        description=(
            "Elimina planes QoS declarativos. Con target vacío borra TODOS los "
            "planes activos; con 'h1' o 's3-eth2' borra solo el de ese host o "
            "puerto. No afecta a las mitigaciones automáticas del resolver."
        ),
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True,
                                    idempotent_hint=True),
    )
    def clear_qos(target: str = "") -> dict:
        payload = {"target": target} if target else {}
        result = api_client.post("/api/qos-intent/clear", payload)
        return {"cleared": result.get("cleared", []),
                "count": result.get("count", 0)}


if not _read_only():
    _register_write_tools()


# ═══════════════════════════════════════════════════════════════════════════
# Resources — telemetría de solo lectura, ya resumida
# ═══════════════════════════════════════════════════════════════════════════

def _as_json(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


@mcp.resource("noc://state", description="Estado actual del NOC y mitigaciones activas",
              mime_type="application/json")
def resource_state() -> str:
    return _as_json(get_network_state())


@mcp.resource("noc://traffic", description="Tráfico agregado por puerto (últimos 5 min)",
              mime_type="application/json")
def resource_traffic() -> str:
    return _as_json(telemetry_digest.summarize_ports())


@mcp.resource("noc://flows", description="Top flujos extremo a extremo (sFlow)",
              mime_type="application/json")
def resource_flows() -> str:
    return _as_json(telemetry_digest.summarize_flows())


@mcp.resource("noc://alerts", description="Anomalías detectadas recientemente",
              mime_type="application/json")
def resource_alerts() -> str:
    return _as_json(telemetry_digest.recent_alerts())


@mcp.resource("noc://qos/history", description="Historial de eventos de QoS",
              mime_type="application/json")
def resource_qos_history() -> str:
    return _as_json(telemetry_digest.recent_qos_events())


@mcp.resource("noc://topology", description="Hosts, servidores y puertos OVS",
              mime_type="application/json")
def resource_topology() -> str:
    return _as_json(list_hosts())


@mcp.resource("noc://digest", description="Digest completo de la red para diagnóstico",
              mime_type="text/plain")
def resource_digest() -> str:
    return telemetry_digest.render_context_text(
        telemetry_digest.build_network_context()
    )


# ═══════════════════════════════════════════════════════════════════════════
# Prompts
# ═══════════════════════════════════════════════════════════════════════════

@mcp.prompt(description="Diagnostica el estado de la red a partir de la telemetría")
def diagnose_network() -> str:
    return (
        "Eres un analista senior de un NOC. Usa las herramientas disponibles "
        "(get_network_state, get_traffic_summary, get_top_flows, "
        "get_recent_alerts) para diagnosticar la red.\n\n"
        "Indica: 1) si hay algún incidente en curso y de qué tipo; 2) qué "
        "puertos y hosts están implicados, nombrándolos exactamente como "
        "aparecen en los datos; 3) qué mitigaciones hay activas y desde cuándo; "
        "4) si recomiendas alguna acción.\n\n"
        "No inventes cifras: cita solo valores que hayas obtenido de las "
        "herramientas. Si un dato no está disponible, dilo."
    )


@mcp.prompt(description="Propone un plan QoS para una necesidad concreta")
def qos_recommendation(necesidad: str = "", host: str = "") -> str:
    destino = f" para el host {host}" if host else ""
    return (
        f"Un usuario necesita lo siguiente{destino}: {necesidad}\n\n"
        "Consulta list_qos_catalog para ver qué aplicaciones existen y "
        "list_hosts para confirmar el destino. Después llama a preview_qos_plan "
        "con las apps adecuadas y explica al operador, en lenguaje llano, qué "
        "hace el plan: qué se prioriza, cuánto ancho de banda garantiza cada "
        "carril y qué pasa en caso de congestión.\n\n"
        "No apliques nada todavía: primero muestra el plan para que lo aprueben."
    )


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Servidor MCP del NOC Mininet")
    parser.add_argument("--transport", default="stdio",
                        choices=["stdio", "streamable-http", "sse"],
                        help="stdio para el Inspector/editores; streamable-http "
                             "para exponerlo en red")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int,
                        default=getattr(config, "MCP_SERVER_PORT", 5001))
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
