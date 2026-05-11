"""
Test de integración: valida el pipeline NOC completo con una topología mínima.

Flujo cubierto:
  1. collect_telemetry()   — SSH mockeado con tráfico intenso en s1-eth2
  2. generate_network_report() — Ollama mockeado
  3. analyze_and_decide()  — Ollama mockeado con tool_call
  4. resolve_multiple()    — SSH mockeado; verifica que se emiten comandos tc
"""

import ast
from unittest.mock import MagicMock

import pytest

# ── Salida dpctl con tráfico intenso en s1-eth2 (>10 MB) y drops ────────────
DPCTL_HEAVY = """\
mininet> dpctl dump-ports
*** s1 ------------------------------------------------------------------------
port  "s1-eth1": rx pkts=100, bytes=5000, drop=0, errs=0, frame=0, over=0, crc=0
         tx pkts=50, bytes=2500, drop=0, errs=0, colls=0
port  "s1-eth2": rx pkts=500, bytes=15000000, drop=10, errs=0, frame=0, over=0, crc=0
         tx pkts=250, bytes=7500000, drop=0, errs=0, colls=0
port  LOCAL: rx pkts=10, bytes=500, drop=0, errs=0, frame=0, over=0, crc=0
         tx pkts=5, bytes=250, drop=0, errs=0, colls=0
mininet>
"""


def _mock_ollama(model, messages, tools=None, options=None, **kwargs):
    """Simula Ollama: sin tools → respuesta de texto; con tools → tool_call POLICING."""
    if tools:
        return {
            "message": {
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "apply_network_actions",
                        "arguments": {
                            "actions": [{
                                "action": "POLICING",
                                "target_port": "s1-eth2",
                                "rate_mbps": 20,
                                "reason": "Tráfico intenso detectado en s1-eth2",
                            }]
                        },
                    }
                }],
            }
        }
    return {"message": {"content": "TRÁFICO INTENSO detectado en: s1-eth2"}}


# ── Fixture: topología mínima genera Python válido ───────────────────────────
def test_script_minimal_es_valido():
    """build_python_script con topología minimal produce Python sintácticamente correcto."""
    from agents.deploy_agent import build_python_script

    script = build_python_script({"tipo": "estandar", "topologia": "minimal"})
    assert "MinimalTopo" in script
    ast.parse(script)


# ── Test de integración del pipeline completo ────────────────────────────────
def test_pipeline_noc_completo(tmp_path, monkeypatch):
    """
    Valida el pipeline completo: telemetría → informe → decisión → ejecución.
    Se ejecuta sin VM real ni Ollama; todo mockeado a nivel de función.
    """
    # Redirigir ficheros de estado a tmp_path
    monkeypatch.setattr("agents.monitor_agent.HISTORY_FILE", str(tmp_path / "hist.json"))
    monkeypatch.setattr("agents.monitor_agent.METRICS_FILE",  str(tmp_path / "metrics.json"))

    mock_ssh = MagicMock()
    monitor_cmds: list[str] = []
    resolver_cmds: list[str] = []

    # Mockear capa SSH del monitor
    monkeypatch.setattr("agents.monitor_agent.get_ssh_connection",    lambda: mock_ssh)
    monkeypatch.setattr("agents.monitor_agent.send_tmux_command",
                        lambda ssh, cmd, session="sesion_mininet": monitor_cmds.append(cmd))
    monkeypatch.setattr("agents.monitor_agent.capture_tmux_output",
                        lambda ssh, session="sesion_mininet": DPCTL_HEAVY)
    monkeypatch.setattr("agents.monitor_agent.wait_for_mininet_prompt",
                        lambda ssh, timeout=90: True)

    # Mockear Ollama globalmente
    monkeypatch.setattr("ollama.chat", _mock_ollama)

    # ── Etapa 1: recolección de telemetría ──────────────────────────────────
    from agents.monitor_agent import collect_telemetry
    telemetry = collect_telemetry()

    assert telemetry is not None, "collect_telemetry() no debe devolver None"
    assert "s1-eth2" in telemetry
    assert "TRÁFICO INTENSO" in telemetry or "ALERTA ROJA" in telemetry

    # Verificar que la serie temporal se guardó
    assert (tmp_path / "metrics.json").exists()

    # ── Etapa 2: informe del monitor ─────────────────────────────────────────
    from agents.monitor_agent import generate_network_report
    report = generate_network_report(telemetry)

    assert isinstance(report, str) and len(report) > 0

    # ── Etapa 3: decisión del resolver ───────────────────────────────────────
    monkeypatch.setattr("agents.resolver_agent.get_ssh_connection", lambda: mock_ssh)
    monkeypatch.setattr("agents.resolver_agent.send_tmux_command",
                        lambda ssh, cmd, session="sesion_mininet": resolver_cmds.append(cmd))

    from agents.resolver_agent import analyze_and_decide, resolve_multiple
    decision = analyze_and_decide(report, telemetry, reglas_activas={})

    assert decision is not None and len(decision) >= 1
    assert decision[0]["action"] == "POLICING"
    assert decision[0]["target_port"] == "s1-eth2"

    # ── Etapa 4: ejecución de la decisión ────────────────────────────────────
    resolve_multiple(decision)

    tc_ingress = [c for c in resolver_cmds if "tc" in c and "ingress" in c]
    assert len(tc_ingress) > 0, (
        f"Se esperaban comandos tc ingress para policing, recibidos: {resolver_cmds}"
    )
