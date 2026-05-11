"""Tests unitarios para las cadenas de escalado y relajación del resolver."""

from agents.resolver_agent import ESCALATION, RELAXATION


def test_cadena_escalado_completa():
    assert ESCALATION["POLICING"] == "SHAPING"
    assert ESCALATION["SHAPING"]  == "BLOCK"
    assert ESCALATION["BLOCK"]    == "BLOCK"   # techo: no sube más


def test_cadena_relajacion_completa():
    assert RELAXATION["BLOCK"]    == "SHAPING"
    assert RELAXATION["SHAPING"]  == "POLICING"
    assert RELAXATION["POLICING"] is None       # suelo: restricción eliminada


def test_relajacion_es_inversa_de_escalado():
    """Subir un nivel y luego relajarlo debe devolver al nivel original."""
    assert RELAXATION[ESCALATION["POLICING"]] == "POLICING"
    assert RELAXATION[ESCALATION["SHAPING"]]  == "SHAPING"


def test_escalado_desde_block_no_cambia():
    """BLOCK es el nivel máximo; escalar desde él no modifica el estado."""
    assert ESCALATION["BLOCK"] == "BLOCK"


def test_relajacion_desde_policing_libera_puerto():
    """Relajar desde el nivel más bajo elimina la restricción (devuelve None)."""
    assert RELAXATION["POLICING"] is None
