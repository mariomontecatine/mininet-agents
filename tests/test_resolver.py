"""Tests unitarios para las cadenas de escalado y desescalado del resolver."""

from agents.resolver_agent import ESCALATION, RELAXATION


def test_cadena_escalado_completa():
    # Cadena de gentil a brutal: SHAPING → POLICING → BLOCK
    assert ESCALATION["SHAPING"]  == "POLICING"
    assert ESCALATION["POLICING"] == "BLOCK"
    assert ESCALATION["BLOCK"]    == "BLOCK"   # techo: no sube más


def test_cadena_desescalado_completa():
    assert RELAXATION["BLOCK"]    == "POLICING"
    assert RELAXATION["POLICING"] == "SHAPING"
    assert RELAXATION["SHAPING"]  is None       # suelo: restricción eliminada


def test_desescalado_es_inverso_de_escalado():
    """Subir un nivel y luego desescalarlo debe devolver al nivel original."""
    assert RELAXATION[ESCALATION["SHAPING"]]  == "SHAPING"
    assert RELAXATION[ESCALATION["POLICING"]] == "POLICING"


def test_escalado_desde_block_no_cambia():
    """BLOCK es el nivel máximo; escalar desde él no modifica el estado."""
    assert ESCALATION["BLOCK"] == "BLOCK"


def test_desescalado_desde_shaping_libera_puerto():
    """Desescalar desde el nivel más bajo (SHAPING) elimina la restricción."""
    assert RELAXATION["SHAPING"] is None
