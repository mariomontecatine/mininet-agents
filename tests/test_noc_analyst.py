"""Tests del analista NOC, del digest de telemetría y del puente MCP↔Ollama.

Sin VM y sin Ollama: la llamada al modelo se mockea siempre.
"""

import json

import pytest

from agents import mcp_ollama_bridge, noc_analyst, telemetry_digest


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _write(tmp_path, name, data):
    (tmp_path / name).write_text(json.dumps(data), encoding="utf-8")


def _write_lines(tmp_path, name, rows):
    (tmp_path / name).write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


@pytest.fixture
def run_dir(tmp_path):
    """Directorio de run sintético con telemetría representativa."""
    _write(tmp_path, "state.json", {
        "ciclo": 68, "timestamp": "2026-06-01T17:05:31",
        "estado_red": "QoS Activa", "intervalo_actual": 10,
        "reglas_activas": {"s1-eth3": {"action": "SHAPING", "ciclo": 65,
                                       "protocol": "ssh"}},
        "ultimo_informe": "Red estable.",
    })
    _write(tmp_path, "host_port_map.json", {
        "h1": "s3-eth2", "srv2": "s1-eth3", "srv4": "s5-eth2",
    })
    _write(tmp_path, "topology.json", {
        "links": [
            {"from": "h1", "to": "192.168.3.1"},
            {"from": "srv2", "to": "192.168.1.2"},
            {"from": "srv4", "to": "192.168.5.1"},
            {"from": "s3", "to": "r2"},
        ],
    })
    _write(tmp_path, "live_metrics.json", [
        {"ts": "2026-06-01T17:00:00",
         "ports": {"s1-eth3": {"rx": 1000, "tx": 500, "drop": 0}}},
        {"ts": "2026-06-01T17:05:00",
         "ports": {"s1-eth3": {"rx": 2000, "tx": 1000, "drop": 3},
                   "s3-eth2": {"rx": 10, "tx": 20, "drop": 0}}},
    ])
    _write(tmp_path, "flows.json", {
        "ts": "2026-06-01T17:05:20", "window_sec": 20, "datagrams": 100,
        "flows": [
            {"src": "192.168.1.2", "dst": "192.168.5.1", "proto": 6,
             "dport": 22, "bytes": 41311264, "pkts": 3313},
            {"src": "192.168.3.1", "dst": "192.168.1.2", "proto": 6,
             "dport": 80, "bytes": 2048, "pkts": 4},
        ],
    })
    _write_lines(tmp_path, "flow_alerts.jsonl", [{
        "type": "dos_volumetric", "host": "srv2", "port": "s1-eth3",
        "victim": "srv4", "bytes": 41311264, "service": "ssh",
        "ts": "2026-06-01T17:05:32",
    }])
    _write_lines(tmp_path, "anomaly_injections.jsonl", [{
        "id": "INJ-1", "type": "dos_volumetric", "ts_start": "2026-06-01T17:05:22",
        "duration_sec": 57, "attacker": "srv2", "victim": "srv4",
        "victim_service": "ssh", "method": "hping3",
    }])
    _write(tmp_path, "qos_history.json", [{
        "ts": "2026-06-01T17:05:35", "cycle": 68, "port": "s1-eth3",
        "action": "SHAPING", "event": "apply", "protocol": "ssh",
    }])
    _write(tmp_path, "server_services.json", {
        "srv2": {"type": "http", "ip": "192.168.1.2", "port": 80},
    })
    _write(tmp_path, "central_link.json", {
        "central_switch": "s2", "shaping_port": "s2-eth2",
        "hosts_behind": {"s2-eth2": 14},
    })
    return tmp_path


# ─── Digest: nombres y recorte ───────────────────────────────────────────────

def test_las_ips_se_resuelven_a_nombres_de_host(run_dir):
    """El informe debe hablar de 'srv2', no de '192.168.1.2'."""
    flows = telemetry_digest.summarize_flows(source_dir=str(run_dir))
    top = flows["flows"][0]
    assert "srv2" in top["src"]
    assert "srv4" in top["dst"]
    assert top["proto"] == "TCP"


def test_el_trafico_se_agrega_por_puerto_y_ordena_por_volumen(run_dir):
    summary = telemetry_digest.summarize_ports(window_min=60,
                                               source_dir=str(run_dir))
    rows = {r["port"]: r for r in summary["ports"]}
    # Se suman las dos muestras del mismo puerto.
    assert rows["s1-eth3"]["rx_bytes"] == 3000
    assert rows["s1-eth3"]["drops"] == 3
    assert rows["s1-eth3"]["host"] == "srv2"
    assert summary["ports"][0]["port"] == "s1-eth3"


def test_la_ventana_se_ancla_al_ultimo_dato_no_al_reloj(run_dir):
    """Debe funcionar igual sobre un run archivado hace semanas."""
    summary = telemetry_digest.summarize_ports(window_min=1,
                                               source_dir=str(run_dir))
    # Solo entra la muestra de las 17:05, no la de las 17:00.
    rows = {r["port"]: r for r in summary["ports"]}
    assert rows["s1-eth3"]["rx_bytes"] == 2000
    assert summary["samples"] == 1


def test_el_digest_recorta_series_largas(tmp_path):
    """Con live_metrics al tope no se puede volcar todo en el prompt."""
    samples = [
        {"ts": f"2026-06-01T17:{m // 60:02d}:{m % 60:02d}",
         "ports": {f"s1-eth{p}": {"rx": 1000 * p, "tx": 0, "drop": 0}
                   for p in range(1, 30)}}
        for m in range(2000)
    ]
    _write(tmp_path, "live_metrics.json", samples)
    summary = telemetry_digest.summarize_ports(window_min=600,
                                               source_dir=str(tmp_path))
    assert len(summary["ports"]) == telemetry_digest.TOP_PORTS
    assert summary["total_ports_seen"] == 29


def test_el_contexto_en_texto_cabe_en_el_prompt(run_dir):
    ctx = telemetry_digest.build_network_context(source_dir=str(run_dir))
    text = telemetry_digest.render_context_text(ctx)
    assert len(text) < 12000, "el digest no debe desbordar el contexto del modelo"
    # Y debe contener lo esencial para diagnosticar.
    assert "SHAPING" in text
    assert "dos_volumetric" in text
    assert "srv2" in text
    # Detección y verdad-terreno van en secciones separadas y etiquetadas: sin
    # eso el modelo las mezcla y afirma que no hubo ataques.
    assert "ANOMALÍAS QUE EL SISTEMA DETECTÓ" in text
    assert "ATAQUES QUE SE LANZARON DE VERDAD" in text


def test_el_perfil_compacto_reduce_el_contexto_a_la_mitad(run_dir):
    """En CPU manda el tamaño del prompt: el informe usa el perfil reducido."""
    full = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    compact = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir),
                                               compact=True))
    assert len(compact) < len(full)
    # Lo esencial para diagnosticar sobrevive al recorte.
    assert "SHAPING" in compact
    assert "dos_volumetric" in compact


def test_las_marcas_de_tiempo_separan_fecha_y_hora(run_dir):
    """Con ISO crudo el modelo lee '...T17:05' como 'el 17 de junio'."""
    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    assert "01/06 17:05:32" in text
    assert "2026-06-01T17:05:32" not in text


def test_un_ddos_multiorigen_no_aparece_como_atacante_None(tmp_path):
    """Un DoS trae 'attacker'; un DDoS trae 'attackers' (lista de diez)."""
    _write_lines(tmp_path, "anomaly_injections.jsonl", [
        {"type": "ddos", "ts_start": "2026-06-01T17:00:00", "duration_sec": 45,
         "attackers": ["h4", "h11", "h1", "h14", "h9"], "victim": "srv6",
         "victim_service": "ssh", "method": "hping3"},
        {"type": "dos_volumetric", "ts_start": "2026-06-01T17:05:00",
         "duration_sec": 57, "attacker": "srv2", "victim": "srv4",
         "victim_service": "ssh", "method": "hping3"},
    ])
    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(tmp_path)))
    assert "None" not in text
    assert "5 hosts (h4, h11, h1…)" in text
    assert "srv2 -> srv4" in text


def test_el_digest_aguanta_un_directorio_vacio(tmp_path):
    ctx = telemetry_digest.build_network_context(source_dir=str(tmp_path))
    assert ctx["cycle"] is None
    assert telemetry_digest.render_context_text(ctx)  # no revienta


def test_jsonl_con_lineas_corruptas_no_rompe_la_lectura(tmp_path):
    (tmp_path / "flow_alerts.jsonl").write_text(
        '{"type": "ddos"}\n{ROTO\n{"type": "dos_volumetric"}\n', encoding="utf-8")
    alerts = telemetry_digest.read_jsonl("flow_alerts.jsonl",
                                         source_dir=str(tmp_path))
    assert [a["type"] for a in alerts] == ["ddos", "dos_volumetric"]


# ─── Analista ────────────────────────────────────────────────────────────────

class _FakeOllama:
    """Cliente Ollama de mentira: registra lo que recibe y devuelve un texto."""

    def __init__(self, reply="Informe de prueba."):
        self.reply = reply
        self.calls = []

    def chat(self, model=None, messages=None, tools=None, options=None):
        self.calls.append({"model": model, "messages": messages, "tools": tools})
        return {"message": {"content": self.reply}}


def test_summarize_pasa_la_telemetria_al_modelo(run_dir, monkeypatch):
    fake = _FakeOllama("La red sufre un DoS volumétrico de srv2 hacia srv4.")
    monkeypatch.setattr(noc_analyst, "_client", lambda: fake)

    out = noc_analyst.summarize(source_dir=str(run_dir))

    assert "DoS" in out["report"]
    assert out["context_chars"] > 0
    # Trazabilidad: se declara de qué ficheros salió la respuesta.
    assert "flow_alerts.jsonl" in out["sources"]
    assert "state.json" in out["sources"]
    # El prompt debe llevar la telemetría real, no un placeholder.
    user_msg = fake.calls[0]["messages"][1]["content"]
    assert "s1-eth3" in user_msg


def test_summarize_no_llama_al_modelo_si_no_hay_datos(tmp_path, monkeypatch):
    fake = _FakeOllama()
    monkeypatch.setattr(noc_analyst, "_client", lambda: fake)
    out = noc_analyst.summarize(source_dir=str(tmp_path))
    assert fake.calls == []
    assert "telemetría suficiente" in out["report"]


def test_answer_incluye_historial_y_pregunta(run_dir, monkeypatch):
    capturado = {}

    def fake_bridge(server, messages, allowed_tools=None, **kw):
        capturado["messages"] = messages
        capturado["allowed"] = allowed_tools
        return "El puerto s1-eth3 es el más cargado.", [{"tool": "get_traffic_summary",
                                                        "arguments": {}, "ok": True}]

    monkeypatch.setattr(mcp_ollama_bridge, "chat_with_tools", fake_bridge)

    out = noc_analyst.answer(
        "¿Y cuál es el puerto más cargado?",
        history=[{"role": "user", "content": "hola"},
                 {"role": "assistant", "content": "buenas"}],
        source_dir=str(run_dir),
    )

    assert "s1-eth3" in out["answer"]
    assert out["tool_calls"][0]["tool"] == "get_traffic_summary"
    roles = [m["role"] for m in capturado["messages"]]
    assert roles[0] == "system"
    assert capturado["messages"][-1]["content"] == "¿Y cuál es el puerto más cargado?"
    assert "hola" in json.dumps(capturado["messages"], ensure_ascii=False)


def test_el_analista_solo_recibe_herramientas_de_lectura(run_dir, monkeypatch):
    """No debe poder aplicar QoS: quien actúa es el resolver."""
    capturado = {}

    def fake_bridge(server, messages, allowed_tools=None, **kw):
        capturado["allowed"] = allowed_tools
        return "ok", []

    monkeypatch.setattr(mcp_ollama_bridge, "chat_with_tools", fake_bridge)
    noc_analyst.answer("¿qué tal?", source_dir=str(run_dir))

    allowed = capturado["allowed"]
    assert "get_traffic_summary" in allowed
    for prohibida in ("apply_qos_plan", "apply_qos_from_text", "clear_qos"):
        assert prohibida not in allowed


def test_si_el_puente_falla_el_analista_responde_igual(run_dir, monkeypatch):
    """Lo esencial ya está en el contexto: nunca debe quedarse mudo."""
    def boom(*a, **kw):
        raise RuntimeError("ollama caído")

    monkeypatch.setattr(mcp_ollama_bridge, "chat_with_tools", boom)
    monkeypatch.setattr(noc_analyst, "_client",
                        lambda: _FakeOllama("Respuesta sin herramientas."))

    out = noc_analyst.answer("¿qué pasa?", source_dir=str(run_dir))
    assert "Respuesta sin herramientas." in out["answer"]
    assert "Sin herramientas" in out["answer"]


def test_pregunta_vacia_se_rechaza(run_dir):
    with pytest.raises(ValueError):
        noc_analyst.answer("   ", source_dir=str(run_dir))


# ─── Registro auditable ──────────────────────────────────────────────────────

def test_cada_consulta_archiva_el_digest_que_vio_el_modelo(run_dir, monkeypatch):
    """Sin el digest no se puede juzgar la respuesta a posteriori."""
    monkeypatch.setattr(mcp_ollama_bridge, "chat_with_tools",
                        lambda *a, **kw: ("No hubo ataques.", []))

    noc_analyst.answer("¿Hubo ataques?", source_dir=str(run_dir))

    rows = noc_analyst.load_history(source_dir=str(run_dir))
    assert len(rows) == 1
    entry = rows[0]
    assert entry["kind"] == "ask"
    assert entry["question"] == "¿Hubo ataques?"
    assert entry["answer"] == "No hubo ataques."
    assert entry["cycle"] == 68
    # La prueba del delito: el contexto archivado contiene los ataques que SÍ
    # había, así que la respuesta se puede refutar después.
    assert "dos_volumetric" in entry["context"]
    assert "ATAQUES QUE SE LANZARON DE VERDAD" in entry["context"]
    assert "flow_alerts.jsonl" in entry["sources"]


def test_el_resumen_tambien_se_archiva(run_dir, monkeypatch):
    monkeypatch.setattr(noc_analyst, "_client", lambda: _FakeOllama("Todo bien."))
    noc_analyst.summarize(source_dir=str(run_dir))
    rows = noc_analyst.load_history(source_dir=str(run_dir))
    assert rows[0]["kind"] == "summary"
    assert rows[0]["question"] is None
    assert rows[0]["context"]


def test_el_archivo_se_acota_y_conserva_las_mas_recientes(run_dir, monkeypatch):
    monkeypatch.setattr(mcp_ollama_bridge, "chat_with_tools",
                        lambda *a, **kw: ("ok", []))
    monkeypatch.setattr(noc_analyst, "HISTORY_MAX", 3)
    for i in range(5):
        noc_analyst.answer(f"pregunta {i}", source_dir=str(run_dir))
    rows = noc_analyst.load_history(source_dir=str(run_dir))
    assert len(rows) == 3
    assert [r["question"] for r in rows] == ["pregunta 2", "pregunta 3",
                                             "pregunta 4"]


def test_un_fallo_al_archivar_no_rompe_la_respuesta(run_dir, monkeypatch):
    """Auditar es deseable; dejar al usuario sin respuesta, no."""
    monkeypatch.setattr(mcp_ollama_bridge, "chat_with_tools",
                        lambda *a, **kw: ("respuesta", []))
    monkeypatch.setattr(noc_analyst, "_history_path",
                        lambda source_dir=None: "/ruta/que/no/existe/h.jsonl")
    out = noc_analyst.answer("¿qué tal?", source_dir=str(run_dir))
    assert out["answer"] == "respuesta"


def test_historial_vacio_si_no_se_ha_preguntado_nada(run_dir):
    assert noc_analyst.load_history(source_dir=str(run_dir)) == []


# ─── Puente MCP ↔ Ollama ─────────────────────────────────────────────────────

class _FakeTool:
    def __init__(self, name, description, schema):
        self.name = name
        self.description = description
        self.input_schema = schema


def test_traduccion_de_tools_mcp_al_formato_de_ollama():
    schema = {"type": "object",
              "properties": {"window_min": {"type": "integer"}},
              "required": []}
    out = mcp_ollama_bridge.mcp_tools_to_ollama(
        [_FakeTool("get_traffic_summary", "Resumen de tráfico", schema)])
    assert out == [{
        "type": "function",
        "function": {
            "name": "get_traffic_summary",
            "description": "Resumen de tráfico",
            "parameters": schema,
        },
    }]


def test_una_tool_sin_esquema_recibe_uno_vacio_valido():
    out = mcp_ollama_bridge.mcp_tools_to_ollama([_FakeTool("ping", None, None)])
    params = out[0]["function"]["parameters"]
    assert params == {"type": "object", "properties": {}}
    assert out[0]["function"]["description"] == ""


def test_el_bucle_ejecuta_la_tool_y_devuelve_la_respuesta_final(monkeypatch):
    """Primera vuelta pide la tool, segunda redacta con el resultado."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("test")

    @server.tool(description="Devuelve el puerto más cargado")
    def top_port() -> dict:
        return {"port": "s1-eth3", "mbps": 6.07}

    respuestas = [
        {"message": {"content": "",
                     "tool_calls": [{"function": {"name": "top_port",
                                                  "arguments": {}}}]}},
        {"message": {"content": "El más cargado es s1-eth3 con 6.07 Mbps."}},
    ]

    class _Seq:
        def __init__(self):
            self.vistos = []

        def chat(self, model=None, messages=None, tools=None, options=None):
            self.vistos.append(messages)
            return respuestas.pop(0)

    seq = _Seq()
    monkeypatch.setattr(mcp_ollama_bridge.ollama, "Client",
                        lambda **kw: seq)

    reply, trace = mcp_ollama_bridge.chat_with_tools(
        server, [{"role": "user", "content": "¿qué puerto va más cargado?"}],
        model="fake", max_rounds=3)

    assert reply == "El más cargado es s1-eth3 con 6.07 Mbps."
    assert trace == [{"tool": "top_port", "arguments": {}, "ok": True}]
    # El resultado de la tool se reinyecta como mensaje role=tool.
    ultimos = seq.vistos[-1]
    assert any(m["role"] == "tool" and "s1-eth3" in m["content"] for m in ultimos)


def test_una_tool_inventada_no_rompe_el_bucle(monkeypatch):
    """Los modelos pequeños alucinan nombres: hay que decírselo, no petar."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("test")

    @server.tool(description="Nada")
    def real_tool() -> dict:
        return {"ok": True}

    respuestas = [
        {"message": {"content": "",
                     "tool_calls": [{"function": {"name": "tool_inventada",
                                                  "arguments": {}}}]}},
        {"message": {"content": "Perdón, ya lo tengo."}},
    ]

    class _Seq:
        def __init__(self):
            self.vistos = []

        def chat(self, model=None, messages=None, tools=None, options=None):
            self.vistos.append(messages)
            return respuestas.pop(0)

    seq = _Seq()
    monkeypatch.setattr(mcp_ollama_bridge.ollama, "Client", lambda **kw: seq)

    reply, trace = mcp_ollama_bridge.chat_with_tools(
        server, [{"role": "user", "content": "hola"}], model="fake", max_rounds=3)

    assert reply == "Perdón, ya lo tengo."
    assert trace[0]["ok"] is False
    # Se le devuelve la lista de herramientas válidas para que se corrija.
    mensaje_tool = [m for m in seq.vistos[-1] if m["role"] == "tool"][0]
    assert "real_tool" in mensaje_tool["content"]


def test_solo_se_ofrecen_las_tools_permitidas(monkeypatch):
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("test")

    @server.tool(description="lectura")
    def leer() -> dict:
        return {}

    @server.tool(description="escritura")
    def escribir() -> dict:
        return {}

    capturado = {}

    class _One:
        def chat(self, model=None, messages=None, tools=None, options=None):
            capturado["tools"] = tools
            return {"message": {"content": "listo"}}

    monkeypatch.setattr(mcp_ollama_bridge.ollama, "Client", lambda **kw: _One())

    mcp_ollama_bridge.chat_with_tools(
        server, [{"role": "user", "content": "hola"}],
        model="fake", allowed_tools={"leer"})

    nombres = [t["function"]["name"] for t in capturado["tools"]]
    assert nombres == ["leer"]
