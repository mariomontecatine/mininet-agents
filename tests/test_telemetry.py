"""Tests unitarios para el parsing de telemetría y el cálculo de deltas."""

import json
import pytest
from agents.monitor_agent import parse_telemetry_to_dict, calculate_delta


SAMPLE_DPCTL = """\
mininet> dpctl dump-ports
*** s1 ------------------------------------------------------------------------
port  "s1-eth1": rx pkts=100, bytes=5000, drop=0, errs=0, frame=0, over=0, crc=0
         tx pkts=50, bytes=2500, drop=0, errs=0, colls=0
port  "s1-eth2": rx pkts=200, bytes=15000000, drop=10, errs=0, frame=0, over=0, crc=0
         tx pkts=100, bytes=7500000, drop=0, errs=0, colls=0
port  LOCAL: rx pkts=10, bytes=500, drop=0, errs=0, frame=0, over=0, crc=0
         tx pkts=5, bytes=250, drop=0, errs=0, colls=0
mininet>
"""


class TestParseTelemetry:
    def test_detecta_puertos_normales(self):
        stats = parse_telemetry_to_dict(SAMPLE_DPCTL)
        assert "s1-eth1" in stats
        assert "s1-eth2" in stats

    def test_valores_rx(self):
        stats = parse_telemetry_to_dict(SAMPLE_DPCTL)
        assert stats["s1-eth1"]["rx_bytes"] == 5000
        assert stats["s1-eth2"]["rx_bytes"] == 15_000_000

    def test_valores_tx(self):
        stats = parse_telemetry_to_dict(SAMPLE_DPCTL)
        assert stats["s1-eth1"]["tx_bytes"] == 2500

    def test_drops_acumulados(self):
        stats = parse_telemetry_to_dict(SAMPLE_DPCTL)
        assert stats["s1-eth2"]["drop"] == 10
        assert stats["s1-eth1"]["drop"] == 0

    def test_puerto_local_ignorado(self):
        stats = parse_telemetry_to_dict(SAMPLE_DPCTL)
        assert not any("LOCAL" in k.upper() for k in stats)

    def test_output_vacio(self):
        stats = parse_telemetry_to_dict("")
        assert stats == {}


class TestCalculateDelta:
    def test_primera_lectura_delta_igual_a_actual(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "agents.monitor_agent.HISTORY_FILE", str(tmp_path / "history.json")
        )
        current = {"s1-eth1": {"rx_bytes": 1000, "tx_bytes": 500, "drop": 0}}
        delta = calculate_delta(current)
        assert delta["s1-eth1"]["rx"] == 1000
        assert delta["s1-eth1"]["tx"] == 500

    def test_delta_entre_dos_lecturas(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "agents.monitor_agent.HISTORY_FILE", str(tmp_path / "history.json")
        )
        base = {"s1-eth1": {"rx_bytes": 1000, "tx_bytes": 500, "drop": 0}}
        calculate_delta(base)  # establece snapshot anterior

        current = {"s1-eth1": {"rx_bytes": 3500, "tx_bytes": 1500, "drop": 3}}
        delta = calculate_delta(current)
        assert delta["s1-eth1"]["rx"] == 2500
        assert delta["s1-eth1"]["tx"] == 1000
        assert delta["s1-eth1"]["drop"] == 3

    def test_delta_no_negativo_en_reset_contador(self, tmp_path, monkeypatch):
        """Si el switch reinicia y los contadores bajan, el delta debe ser >= 0."""
        monkeypatch.setattr(
            "agents.monitor_agent.HISTORY_FILE", str(tmp_path / "history.json")
        )
        calculate_delta({"s1-eth1": {"rx_bytes": 9000, "tx_bytes": 0, "drop": 0}})
        delta = calculate_delta({"s1-eth1": {"rx_bytes": 100, "tx_bytes": 0, "drop": 0}})
        assert delta["s1-eth1"]["rx"] >= 0
