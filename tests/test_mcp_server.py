"""Tests del servidor MCP: esquemas, lectura de telemetría y ruta de escritura.

Todo mockeado: no hace falta la VM, ni el dashboard, ni Ollama.
"""

import json
import os

import anyio
import pytest
from mcp import Client

from mcp_server import api_client, server as mcp_server


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_tmp(tmp_path, monkeypatch):
    """Un tmp/ sintético con lo mínimo para que las tools tengan qué leer."""
    (tmp_path / "host_port_map.json").write_text(json.dumps({
        "h1": "s1-eth2", "h2": "s1-eth3", "srv1": "s2-eth2",
    }))
    (tmp_path / "topology.json").write_text(json.dumps({
        "nodes": ["h1", "192.168.1.1", "h2", "192.168.1.2", "srv1", "192.168.2.1"],
        "links": [
            {"from": "h1", "to": "192.168.1.1"},
            {"from": "h2", "to": "192.168.1.2"},
            {"from": "srv1", "to": "192.168.2.1"},
            {"from": "h1", "to": "s1"},
        ],
    }))
    (tmp_path / "state.json").write_text(json.dumps({
        "ciclo": 42, "timestamp": "2026-06-01T12:00:00", "estado_red": "QoS Activa",
        "intervalo_actual": 10,
        "reglas_activas": {"s1-eth3": {"action": "SHAPING", "ciclo": 40,
                                       "protocol": "http"}},
        "ultimo_informe": "Red estable.",
    }))
    (tmp_path / "server_services.json").write_text(json.dumps({
        "srv1": {"type": "http", "ip": "192.168.2.1", "port": 80, "transport": "tcp"},
    }))
    monkeypatch.setattr(mcp_server.telemetry_digest, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(mcp_server.qos_intent, "HOST_PORT_FILE",
                        str(tmp_path / "host_port_map.json"))
    return tmp_path


def call(tool, args=None):
    """Invoca una tool a través de una sesión MCP real (transporte en memoria)."""
    async def _run():
        async with Client(mcp_server.mcp) as c:
            result = await c.call_tool(tool, args or {})
            text = result.content[0].text if result.content else ""
            return result.is_error, text
    return anyio.run(_run)


def list_tool_names():
    async def _run():
        async with Client(mcp_server.mcp) as c:
            return [t.name for t in (await c.list_tools()).tools]
    return anyio.run(_run)


# ─── Esquema publicado ───────────────────────────────────────────────────────

def test_tools_expuestas_incluyen_lectura_y_escritura():
    names = list_tool_names()
    for expected in ("list_qos_catalog", "list_hosts", "get_network_state",
                     "get_traffic_summary", "get_top_flows", "get_recent_alerts",
                     "preview_qos_plan", "apply_qos_plan", "clear_qos"):
        assert expected in names


def test_preview_declara_sus_parametros_obligatorios():
    async def _run():
        async with Client(mcp_server.mcp) as c:
            tools = {t.name: t for t in (await c.list_tools()).tools}
            return tools["preview_qos_plan"].input_schema
    schema = anyio.run(_run)
    assert set(schema.get("required", [])) == {"target_host", "apps"}
    assert "total_mbps" in schema["properties"]
    assert schema["properties"]["apps"]["type"] == "array"


def test_las_tools_de_escritura_se_marcan_como_destructivas():
    async def _run():
        async with Client(mcp_server.mcp) as c:
            return {t.name: t.annotations for t in (await c.list_tools()).tools}
    ann = anyio.run(_run)
    assert ann["apply_qos_plan"].destructive_hint is True
    assert ann["get_network_state"].read_only_hint is True


def test_read_only_desactiva_las_tools_de_escritura(monkeypatch):
    """Con MCP_READ_ONLY el servidor no debe registrar nada que toque la red."""
    monkeypatch.setenv("MCP_READ_ONLY", "1")
    assert mcp_server._read_only() is True
    monkeypatch.setenv("MCP_READ_ONLY", "0")
    assert mcp_server._read_only() is False


# ─── Tools de lectura ────────────────────────────────────────────────────────

def test_list_hosts_resuelve_puerto_ip_y_servicio(fake_tmp):
    is_error, text = call("list_hosts")
    assert not is_error
    data = json.loads(text)
    by_name = {h["name"]: h for h in data["hosts"]}
    assert by_name["h1"]["ovs_port"] == "s1-eth2"
    assert by_name["h1"]["ip"] == "192.168.1.1"
    assert by_name["srv1"]["service"] == "http"


def test_get_network_state_traduce_las_claves_al_ingles(fake_tmp):
    is_error, text = call("get_network_state")
    assert not is_error
    data = json.loads(text)
    assert data["cycle"] == 42
    assert data["active_rules"]["s1-eth3"]["action"] == "SHAPING"


def test_el_catalogo_expone_apps_y_tiers():
    is_error, text = call("list_qos_catalog")
    assert not is_error
    data = json.loads(text)
    assert "voip" in data["apps"]
    assert data["apps"]["voip"]["tier"] == "interactive"


# ─── Construcción de plan ────────────────────────────────────────────────────

def test_preview_devuelve_comandos_tc_y_no_aplica_nada(fake_tmp):
    is_error, text = call("preview_qos_plan",
                          {"target_host": "h1", "apps": ["voip", "youtube"],
                           "total_mbps": 50})
    assert not is_error
    data = json.loads(text)
    assert data["applied"] is False
    plan = data["plan"]
    assert plan["target_port"] == "s1-eth2"
    cmds = [c["cmd"] for c in plan["tc_commands"]]
    assert any("htb default 40" in c for c in cmds)
    # Un filtro u32 por app: VoIP va a RTP/UDP 16384, YouTube a HTTPS/TCP 443.
    assert any("match ip dport 16384" in c for c in cmds)
    assert any("match ip dport 443" in c for c in cmds)


def test_preview_con_host_inexistente_da_error_util(fake_tmp):
    is_error, text = call("preview_qos_plan",
                          {"target_host": "h99", "apps": ["voip"]})
    assert is_error
    # El mensaje debe listar los hosts válidos para que el modelo se corrija.
    assert "h1" in text


def test_preview_con_app_fuera_del_catalogo_da_error_util(fake_tmp):
    is_error, text = call("preview_qos_plan",
                          {"target_host": "h1", "apps": ["spotify"]})
    assert is_error
    assert "catálogo" in text.lower() or "catalogo" in text.lower()


# ─── Ruta de escritura ───────────────────────────────────────────────────────

def test_apply_pasa_por_la_api_del_dashboard_y_no_por_ssh(fake_tmp, monkeypatch):
    """La tool de escritura NO debe abrir SSH: debe delegar en el endpoint."""
    llamadas = []

    def fake_post(path, payload=None, timeout=None):
        llamadas.append((path, payload))
        return {"ok": True, "plan": {"target_host": "h1", "applied": True}}

    monkeypatch.setattr(api_client, "post", fake_post)
    # Si alguien intentara aplicar por SSH, esto reventaría el test.
    monkeypatch.setattr(mcp_server.qos_intent, "apply_qos_plan",
                        lambda plan: pytest.fail("no debe aplicarse por SSH"))

    is_error, text = call("apply_qos_plan",
                          {"target_host": "h1", "apps": ["voip"], "total_mbps": 20})
    assert not is_error
    assert len(llamadas) == 1
    path, payload = llamadas[0]
    assert path == "/api/qos-intent/apply"
    # El plan viaja ya validado y con el puerto resuelto.
    assert payload["plan"]["target_port"] == "s1-eth2"


def test_clear_sin_target_limpia_todo(fake_tmp, monkeypatch):
    llamadas = []
    monkeypatch.setattr(api_client, "post",
                        lambda path, payload=None, timeout=None:
                        (llamadas.append((path, payload)),
                         {"ok": True, "cleared": [], "count": 0})[1])
    is_error, _ = call("clear_qos", {})
    assert not is_error
    assert llamadas[0] == ("/api/qos-intent/clear", {})


def test_error_claro_si_el_dashboard_no_esta_arrancado(fake_tmp, monkeypatch):
    def boom(path, payload=None, timeout=None):
        raise api_client.NocApiUnavailable("No hay respuesta en http://127.0.0.1:5000")

    monkeypatch.setattr(api_client, "post", boom)
    is_error, text = call("apply_qos_plan", {"target_host": "h1", "apps": ["voip"]})
    assert is_error
    assert "127.0.0.1:5000" in text


# ─── Resources ───────────────────────────────────────────────────────────────

def test_los_resources_se_publican_y_devuelven_json(fake_tmp):
    async def _run():
        async with Client(mcp_server.mcp) as c:
            uris = [str(r.uri) for r in (await c.list_resources()).resources]
            state = await c.read_resource("noc://state")
            return uris, state.contents[0].text
    uris, state_text = anyio.run(_run)
    assert "noc://state" in uris
    assert "noc://digest" in uris
    assert json.loads(state_text)["cycle"] == 42


def test_el_prompt_de_diagnostico_esta_disponible():
    async def _run():
        async with Client(mcp_server.mcp) as c:
            names = [p.name for p in (await c.list_prompts()).prompts]
            got = await c.get_prompt("diagnose_network", {})
            return names, got
    names, got = anyio.run(_run)
    assert "diagnose_network" in names
    assert got.messages
