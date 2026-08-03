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
    assert "ANOMALÍAS DETECTADAS EN LOS ÚLTIMOS" in text
    assert "DETALLE DE ESOS MISMOS ATAQUES INYECTADOS" in text
    # Un solo nombre para el conjunto: con dos, el modelo los tomaba por
    # poblaciones distintas y sumaba ataques que no existían.
    assert "DE VERDAD" not in text


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
    assert "desde 5 hosts a la vez (h4, h11, h1…)" in text
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


# ─── Conclusiones precalculadas ──────────────────────────────────────────────
# Cada test de aquí corresponde a un fallo REAL observado del modelo local, que
# tenía el dato delante y aun así respondía mal por no saber calcular.

def test_la_correlacion_se_da_hecha_y_coincide_con_el_scorecard(run_dir):
    """El 3b decía 'no se detectó ninguno' teniendo ambas listas delante."""
    corr = telemetry_digest.correlate_attacks(source_dir=str(run_dir))
    assert corr["total"] == 1
    assert corr["detected"] == 1
    assert corr["detection_rate"] == 100
    assert corr["missed"] == []

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    assert "DETECTÓ 1 de 1 (100%)" in text
    assert "Ninguno pasó desapercibido" in text
    # Detección y mitigación se dan por separado: el modelo las fundía en un
    # "los mitigó todos" que exageraba el rendimiento del sistema.
    assert f"mitigar {corr['mitigated']} de {corr['total']}" in text
    assert "Detectar y mitigar son cosas distintas" in text


def test_los_ataques_sin_mitigar_se_nombran_uno_a_uno(tmp_path):
    """Con solo el recuento ('8 de 9'), el modelo se inventaba CUÁL faltaba."""
    _write_lines(tmp_path, "anomaly_injections.jsonl", [{
        "type": "ddos", "ts_start": "2026-06-01T17:00:00",
        "ts_start_epoch": 1780326000.0, "duration_sec": 40,
        "attackers": ["h9", "h7", "h6", "h1"], "attacker_ports": ["s3-eth9"],
        "victim": "srv6", "victim_service": "ssh",
    }])
    corr = telemetry_digest.correlate_attacks(source_dir=str(tmp_path))
    assert corr["mitigated"] == 0
    assert corr["unmitigated"][0]["victim"] == "srv6"

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(tmp_path)))
    assert "El único ataque SIN mitigar es exactamente este" in text
    assert "-> srv6" in text


def test_si_todos_se_mitigaron_se_dice_explicitamente(run_dir):
    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    corr = telemetry_digest.correlate_attacks(source_dir=str(run_dir))
    if corr["unmitigated"]:
        assert "SIN mitigar" in text
    else:
        assert "Todos ellos recibieron mitigación QoS." in text
    # El operador pregunta por ataques "inyectados"; el sistema los llama
    # "lanzados". Con el término solo en una forma, el modelo no ligaba la
    # pregunta con la sección y respondía justo lo contrario de lo que ponía.
    # Se comprueba la raíz para que valga en singular y en plural.
    for raiz in ("INYECTADOS", "LANZADOS", "inyectad", "lanzad", "DETECTÓ"):
        assert raiz in text


def test_la_concordancia_y_el_matiz_se_ajustan_al_recuento(tmp_path):
    """Con "De 1 ataqueS" y un "en su mayoría" fijo aunque fuese 100%, el
    modelo copiaba la vaguedad: respondía "detectó 1 de los ataques"."""
    def _texto():
        return telemetry_digest.render_context_text(
            telemetry_digest.build_network_context(source_dir=str(tmp_path)))

    uno = {"type": "dos_volumetric", "ts_start": "2026-06-01T17:00:00",
           "ts_start_epoch": 1780326000.0, "duration_sec": 30,
           "attacker": "h1", "attacker_ports": ["s3-eth2"], "victim": "srv1",
           "victim_service": "http"}
    _write_lines(tmp_path, "anomaly_injections.jsonl", [uno])
    _write_lines(tmp_path, "flow_alerts.jsonl", [{
        "type": "dos_volumetric", "host": "h1", "victim": "srv1",
        "ts": "2026-06-01T17:00:10",
    }])
    text = _texto()
    assert "De 1 ataque inyectado (lanzado)" in text   # singular
    assert "SÍ, TODOS." in text                        # 100%, sin vaguedades
    assert "en su mayoría" not in text

    # Con uno detectado y otro que no, el matiz cambia.
    otro = dict(uno, ts_start="2026-06-01T18:00:00",
                ts_start_epoch=1780329600.0, attacker="h9",
                attacker_ports=["s3-eth9"], victim="srv2")
    _write_lines(tmp_path, "anomaly_injections.jsonl", [uno, otro])
    text = _texto()
    assert "De 2 ataques inyectados (lanzados)" in text  # plural
    assert "SÍ, la mayoría." in text
    assert "(50%)" in text


def test_los_puertos_troncales_se_marcan_para_explicar_la_carga(run_dir):
    """Preguntado "¿qué puerto va más cargado Y POR QUÉ?", contestaba solo el
    qué: veía el número pero no que ese puerto es el troncal."""
    _write(run_dir, "central_link.json", {
        "central_switch": "s2", "shaping_port": "s1-eth3",
        "ports": ["s1-eth3", "s1-eth4"], "hosts_behind": {"s1-eth3": 14},
    })
    summary = telemetry_digest.summarize_ports(window_min=60,
                                               source_dir=str(run_dir))
    fila = {r["port"]: r for r in summary["ports"]}["s1-eth3"]
    assert fila["trunk"] is True

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    assert "s1-eth3 [troncal central]" in text
    # La explicación del rol va una sola vez, no repetida en cada línea.
    assert text.count("por ahí pasa el tráfico entre subredes") == 1


def test_un_ataque_no_detectado_se_nombra_explicitamente(tmp_path):
    _write_lines(tmp_path, "anomaly_injections.jsonl", [{
        "id": "INJ-9", "type": "dos_volumetric",
        "ts_start": "2026-06-01T10:00:00",
        "ts_start_epoch": 1780300800.0, "duration_sec": 30,
        "attacker": "h9", "attacker_ports": ["s3-eth9"],
        "victim": "srv1", "victim_service": "http",
    }])
    corr = telemetry_digest.correlate_attacks(source_dir=str(tmp_path))
    assert corr["detected"] == 0
    assert corr["missed"][0]["attacker"] == "h9"

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(tmp_path)))
    assert "Pasaron desapercibidos 1" in text
    assert "h9 -> srv1" in text


def test_un_ataque_vivo_se_marca_como_en_curso(tmp_path):
    """Preguntado por '¿hay ataques en curso?' respondía que no mientras uno
    seguía corriendo: tenía inicio y duración, pero no sabía restarlos."""
    from datetime import datetime as _dt, timedelta as _td
    hace_10s = _dt.now() - _td(seconds=10)
    _write_lines(tmp_path, "anomaly_injections.jsonl", [{
        "type": "dos_volumetric", "ts_start": hace_10s.isoformat(timespec="seconds"),
        "duration_sec": 60, "attacker": "h2", "victim": "srv3",
        "victim_service": "http",
    }])
    # source_dir distinto de tmp/ usa la marca más reciente de los datos, así
    # que forzamos la referencia al reloj para simular la sesión viva.
    running = telemetry_digest.attacks_in_progress(source_dir=str(tmp_path),
                                                   reference=_dt.now())
    assert len(running) == 1
    assert running[0]["victim"] == "srv3"
    assert 8 <= running[0]["started_ago_sec"] <= 12
    assert running[0]["remaining_sec"] > 0


def test_en_un_run_archivado_la_referencia_sale_de_los_datos(run_dir):
    """El reloj no sirve para juzgar un run de hace semanas: el instante de
    referencia es la marca más reciente del propio run. Aquí el ataque empezó
    a las 17:05:22 y dura 57 s, y el último evento del run es 17:05:35, así
    que en ese instante seguía en curso."""
    running = telemetry_digest.attacks_in_progress(source_dir=str(run_dir))
    assert len(running) == 1
    assert running[0]["victim"] == "srv4"

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    assert "SÍ — 1 ataque(s) en curso" in text


def test_un_ataque_terminado_no_figura_en_curso(run_dir):
    """Mismo run, pero con un ataque muy anterior al último evento."""
    _write_lines(run_dir, "anomaly_injections.jsonl", [{
        "type": "dos_volumetric", "ts_start": "2026-06-01T16:00:00",
        "duration_sec": 30, "attacker": "h1", "victim": "srv1",
        "victim_service": "http",
    }])
    assert telemetry_digest.attacks_in_progress(source_dir=str(run_dir)) == []
    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    assert "NO. Ningún ataque está activo" in text


def test_las_detecciones_repetidas_se_agrupan(run_dir):
    """El detector dispara varias veces por ataque; sin agrupar, el modelo las
    enumeraba como incidentes distintos."""
    alerts = [
        {"type": "ddos", "host": "srv1", "victim": "srv2", "service": "http",
         "port": "s1-eth2", "bytes": 100, "ts": "2026-06-01T17:00:00"},
        {"type": "ddos", "host": "srv1", "victim": "srv2", "service": "http",
         "port": "s1-eth2", "bytes": 500, "ts": "2026-06-01T17:00:30"},
        {"type": "dos_volumetric", "host": "h3", "victim": "srv4",
         "service": "ssh", "port": "s3-eth4", "bytes": 90,
         "ts": "2026-06-01T17:01:00"},
    ]
    grouped = telemetry_digest.group_alerts(alerts)
    assert len(grouped) == 2
    assert grouped[0]["count"] == 2
    assert grouped[0]["max_bytes"] == 500      # se conserva el pico
    assert grouped[0]["first_ts"] == "2026-06-01T17:00:00"
    assert grouped[1]["count"] == 1


def test_las_acciones_posteriores_al_ciclo_cuentan_como_activas(tmp_path):
    """state.json se escribe por ciclo, pero las acciones [FLOW] van entre
    ciclos: el digest decía 'ninguna' y acto seguido listaba un apply."""
    _write(tmp_path, "state.json", {
        "ciclo": 3, "timestamp": "2026-06-01T17:00:00",
        "estado_red": "ESTABLE", "reglas_activas": {},
    })
    _write(tmp_path, "qos_history.json", [
        {"ts": "2026-06-01T17:00:15", "cycle": 3, "port": "s3-eth2",
         "action": "SHAPING", "event": "apply", "protocol": "ssh"},
    ])
    rules = telemetry_digest.effective_mitigations(source_dir=str(tmp_path))
    assert rules["s3-eth2"]["action"] == "SHAPING"

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(tmp_path)))
    assert "MITIGACIONES ACTIVAS === ninguna" not in text
    assert "s3-eth2: SHAPING" in text


def test_una_retirada_posterior_desactiva_la_regla(tmp_path):
    _write(tmp_path, "state.json", {
        "ciclo": 3, "timestamp": "2026-06-01T17:00:00",
        "reglas_activas": {"s3-eth2": {"action": "SHAPING", "ciclo": 2}},
    })
    _write(tmp_path, "qos_history.json", [
        {"ts": "2026-06-01T17:00:20", "port": "s3-eth2", "event": "remove"},
    ])
    assert telemetry_digest.effective_mitigations(source_dir=str(tmp_path)) == {}


def test_no_se_expone_la_hora_del_muestreo_sflow(run_dir):
    """flows.json la estampa el reloj de la VM, que puede ir desfasado del
    anfitrión (se midieron 21 h): dos líneas temporales confunden al modelo."""
    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(run_dir)))
    assert "ÚLTIMO MUESTREO" in text
    assert "17:05:20" not in text          # la ts de flows.json del fixture
    assert "01/06 17:05:20" not in text


# ─── Ventana temporal y topes ────────────────────────────────────────────────

def test_la_ventana_recorta_el_detalle_pero_no_el_marcador(tmp_path):
    """Lo delicado del recorte: si al acotar a N minutos el marcador global
    dijese '0 ataques', se rompería la pregunta clave del TFG. La ventana
    recorta el DETALLE; los contadores siguen siendo de toda la ejecución."""
    viejo = {"type": "ddos", "ts_start": "2026-06-01T10:00:00",
             "ts_start_epoch": 1780300800.0, "duration_sec": 30,
             "attacker": "h1", "attacker_ports": ["s3-eth2"], "victim": "srv1",
             "victim_service": "http"}
    nuevo = dict(viejo, ts_start="2026-06-01T12:00:00",
                 ts_start_epoch=1780308000.0, attacker="h2",
                 attacker_ports=["s3-eth3"], victim="srv2")
    _write_lines(tmp_path, "anomaly_injections.jsonl", [viejo, nuevo])

    # Detalle: solo el de dentro de la ventana de 5 min.
    detalle = telemetry_digest.recent_injections(source_dir=str(tmp_path),
                                                 window_min=5)
    assert [d["victim"] for d in detalle] == ["srv2"]

    # Marcador: los dos, porque correlate_attacks no mira la ventana.
    corr = telemetry_digest.correlate_attacks(source_dir=str(tmp_path))
    assert corr["total"] == 2

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(tmp_path),
                                               window_min=5))
    assert "De 2 ataques inyectados" in text     # contador global intacto
    assert "srv1" not in text.split("=== DETALLE")[1]  # detalle recortado


def test_sin_ventana_no_se_recorta_nada(tmp_path):
    _write_lines(tmp_path, "flow_alerts.jsonl", [
        {"type": "ddos", "host": "h1", "ts": "2026-06-01T10:00:00"},
        {"type": "ddos", "host": "h2", "ts": "2026-06-01T12:00:00"},
    ])
    assert len(telemetry_digest.recent_alerts(source_dir=str(tmp_path))) == 2
    assert len(telemetry_digest.recent_alerts(source_dir=str(tmp_path),
                                              window_min=5)) == 1


def test_la_ventana_se_ancla_al_ultimo_evento_no_al_reloj(tmp_path):
    """Sobre un run archivado hace semanas el reloj no sirve de referencia."""
    _write_lines(tmp_path, "flow_alerts.jsonl", [
        {"type": "ddos", "host": "h1", "ts": "2020-01-01T10:00:00"},
        {"type": "ddos", "host": "h2", "ts": "2020-01-01T10:02:00"},
    ])
    rows = telemetry_digest.recent_alerts(source_dir=str(tmp_path),
                                          window_min=5)
    assert len(rows) == 2, "ambas están dentro de 5 min del último evento"


def test_las_listas_de_excepciones_tienen_tope(tmp_path):
    """missed y unmitigated recorren TODA la ejecución: sin tope crecían sin
    límite en un run largo."""
    inyecciones = [{
        "type": "dos_volumetric", "ts_start": f"2026-06-01T10:{i:02d}:00",
        "ts_start_epoch": 1780300800.0 + i * 60, "duration_sec": 30,
        "attacker": f"h{i}", "attacker_ports": [f"s3-eth{i}"],
        "victim": "srv1", "victim_service": "http",
    } for i in range(20)]
    _write_lines(tmp_path, "anomaly_injections.jsonl", inyecciones)

    corr = telemetry_digest.correlate_attacks(source_dir=str(tmp_path))
    assert corr["missed_total"] == 20                    # el recuento, entero
    assert len(corr["missed"]) == telemetry_digest.MAX_EXCEPTIONS

    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(tmp_path)))
    assert "Pasaron desapercibidos 20" in text
    assert "se listan los 5 últimos" in text


def test_las_mitigaciones_activas_tienen_tope(tmp_path):
    _write(tmp_path, "state.json", {
        "ciclo": 9, "timestamp": "2026-06-01T17:00:00",
        "reglas_activas": {f"s1-eth{i}": {"action": "SHAPING", "ciclo": i}
                           for i in range(12)},
    })
    text = telemetry_digest.render_context_text(
        telemetry_digest.build_network_context(source_dir=str(tmp_path)))
    assert "puertos más con mitigación activa" in text


# ─── Caché de contexto ───────────────────────────────────────────────────────

def test_el_ttl_supera_el_tiempo_de_una_respuesta(monkeypatch):
    """Regresión de un error real: con TTL=60 s y respuestas de 240-400 s, el
    contexto caducaba mientras el modelo aún contestaba la pregunta anterior,
    así que la caché nunca llegaba viva a la siguiente consulta."""
    from utils import config as cfg
    assert cfg.ANALYST_CACHE_TTL > cfg.ANALYST_LLM_TIMEOUT / 2, (
        "el TTL debe cubrir al menos una respuesta lenta o la caché es inútil"
    )


def test_dos_consultas_seguidas_comparten_contexto_identico(run_dir, monkeypatch):
    """La medida que gana la latencia: Ollama solo reutiliza su caché si el
    prompt coincide carácter a carácter desde el principio."""
    monkeypatch.setattr(noc_analyst.config, "ANALYST_CACHE_TTL", 60)
    noc_analyst.invalidate_context_cache()

    _, texto1, edad1 = noc_analyst._context_block(source_dir=str(run_dir))
    _, texto2, edad2 = noc_analyst._context_block(source_dir=str(run_dir))

    assert texto1 == texto2, "el prompt debe ser idéntico byte a byte"
    assert edad1 == 0        # la primera lo construye
    assert edad2 >= 0        # la segunda lo reutiliza


def test_el_ttl_a_cero_desactiva_la_cache(run_dir, monkeypatch):
    monkeypatch.setattr(noc_analyst.config, "ANALYST_CACHE_TTL", 0)
    noc_analyst.invalidate_context_cache()
    _, _, edad1 = noc_analyst._context_block(source_dir=str(run_dir))
    _, _, edad2 = noc_analyst._context_block(source_dir=str(run_dir))
    assert edad1 == edad2 == 0, "sin caché, siempre recién construido"


def test_la_cache_caduca(run_dir, monkeypatch):
    monkeypatch.setattr(noc_analyst.config, "ANALYST_CACHE_TTL", 60)
    noc_analyst.invalidate_context_cache()
    noc_analyst._context_block(source_dir=str(run_dir))

    # Envejecemos la entrada más allá del TTL.
    for entrada in noc_analyst._context_cache.values():
        entrada["built_at"] -= 120
    _, _, edad = noc_analyst._context_block(source_dir=str(run_dir))
    assert edad == 0, "pasado el TTL debe reconstruirse"


def test_cambiar_de_run_invalida_la_cache(run_dir, tmp_path, monkeypatch):
    """Al cargar un run archivado el analista debe hablar de ESE run."""
    monkeypatch.setattr(noc_analyst.config, "ANALYST_CACHE_TTL", 60)
    noc_analyst.invalidate_context_cache()

    otro = tmp_path / "otro_run"
    otro.mkdir()
    _write(otro, "state.json", {"ciclo": 999, "timestamp": "2026-06-01T20:00:00",
                                "estado_red": "ESTABLE"})

    _, texto_a, _ = noc_analyst._context_block(source_dir=str(run_dir))
    _, texto_b, _ = noc_analyst._context_block(source_dir=str(otro))
    assert texto_a != texto_b
    assert "Ciclo: 999" in texto_b


def test_la_antiguedad_del_contexto_llega_a_la_respuesta(run_dir, monkeypatch):
    """Si la respuesta describe datos de hace un rato, hay que poder saberlo."""
    monkeypatch.setattr(noc_analyst.config, "ANALYST_CACHE_TTL", 60)
    monkeypatch.setattr(mcp_ollama_bridge, "chat_with_tools",
                        lambda *a, **kw: ("ok", []))
    noc_analyst.invalidate_context_cache()

    primera = noc_analyst.answer("¿qué tal?", source_dir=str(run_dir))
    assert primera["context_age_sec"] == 0

    for entrada in noc_analyst._context_cache.values():
        entrada["built_at"] -= 20
    segunda = noc_analyst.answer("¿y ahora?", source_dir=str(run_dir))
    assert segunda["context_age_sec"] >= 20


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
    assert "DETALLE DE ESOS MISMOS ATAQUES INYECTADOS" in entry["context"]
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
