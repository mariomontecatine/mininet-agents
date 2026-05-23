"""Regresión: víctimas DDoS recientes silencian DoS volumétricos hacia ellas
durante 60s, evitando los 'DoS fantasma' del mismo ataque distribuido.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import monitor_agent as ma
from utils import config


def _make_flow(src, dst, b, proto=17, dport=53):
    return {"src": src, "dst": dst, "bytes": b, "pkts": b // 1000,
            "proto": proto, "dport": dport}


def _reset_state():
    ma._RECENT_DDOS_VICTIMS.clear()


def test_ddos_silences_subsequent_individual_dos():
    """Snapshot 1 dispara DDoS hacia srv3; snapshot 2 mantiene 1 src grande
    hacia srv3. El segundo NO debe contar como dos_volumetric individual.
    """
    _reset_state()

    victim = "10.0.0.30"
    host_port = {}

    # Snapshot 1 — fan_in_threshold=6 srcs, cada uno con tráfico > SURGE.
    surge = config.SURGE_BYTES_THRESHOLD + 1_000_000
    flows1 = [
        _make_flow(f"10.0.0.{10+i}", victim, surge)
        for i in range(config.FAN_IN_THRESHOLD)
    ]
    alerts1 = ma.detect_flow_anomalies(flows1, host_port)
    types1 = sorted(a["type"] for a in alerts1)
    # Esperamos UN ddos y NINGÚN dos_volumetric (mismo snapshot, dedup intra).
    assert "ddos" in types1, f"expected ddos in {types1}"
    assert "dos_volumetric" not in types1, f"DoS no debería emitirse: {types1}"

    # Snapshot 2 — solo 1 src enviando volumen alto a la misma víctima
    # (debajo del fan-in threshold pero por encima del SURGE individual).
    flows2 = [_make_flow("10.0.0.10", victim, surge)]
    alerts2 = ma.detect_flow_anomalies(flows2, host_port)
    types2 = [a["type"] for a in alerts2]
    # Sin la memoria persistente esto generaría un dos_volumetric.
    assert "dos_volumetric" not in types2, (
        f"DoS fantasma hacia víctima DDoS reciente: {alerts2}"
    )


def test_ttl_expira_recupera_deteccion_dos():
    """Tras el TTL de la memoria de víctimas, un DoS hacia esa IP vuelve a
    contar como dos_volumetric.
    """
    _reset_state()

    victim = "10.0.0.99"
    ma._RECENT_DDOS_VICTIMS[victim] = time.time() - (ma._DDOS_VICTIM_TTL + 5)

    surge = config.SURGE_BYTES_THRESHOLD + 1_000_000
    flows = [_make_flow("10.0.0.10", victim, surge)]
    alerts = ma.detect_flow_anomalies(flows, {})
    types = [a["type"] for a in alerts]
    assert "dos_volumetric" in types, (
        f"Tras TTL la víctima debe poder volver a dispararse: {alerts}"
    )


def test_dos_volumetrico_aislado_se_detecta_normalmente():
    """Un DoS volumétrico hacia una IP que nunca fue víctima DDoS NO debe
    silenciarse — regresión de no haber tocado el flujo normal.
    """
    _reset_state()

    surge = config.SURGE_BYTES_THRESHOLD + 1_000_000
    flows = [_make_flow("10.0.0.10", "10.0.0.42", surge)]
    alerts = ma.detect_flow_anomalies(flows, {})
    types = [a["type"] for a in alerts]
    assert "dos_volumetric" in types
