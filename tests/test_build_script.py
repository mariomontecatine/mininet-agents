"""Tests unitarios para build_python_script(): verifica que genera código correcto
para cada topología estándar de Mininet y para topologías custom."""

import ast
import pytest
from agents.deploy_agent import build_python_script


TOPOLOGIAS_ESTANDAR = ["tree", "linear", "single", "minimal", "torus"]


class TestTopologiasEstandar:
    def test_tree(self):
        script = build_python_script(
            {"tipo": "estandar", "topologia": "tree", "depth": 2, "fanout": 3}
        )
        assert "TreeTopo" in script
        assert "depth=2" in script
        assert "fanout=3" in script

    def test_linear(self):
        script = build_python_script(
            {"tipo": "estandar", "topologia": "linear", "k": 5, "n": 2}
        )
        assert "LinearTopo" in script
        assert "k=5" in script
        assert "n=2" in script

    def test_single(self):
        script = build_python_script(
            {"tipo": "estandar", "topologia": "single", "k": 6}
        )
        assert "SingleSwitchTopo" in script
        assert "k=6" in script

    def test_minimal(self):
        script = build_python_script({"tipo": "estandar", "topologia": "minimal"})
        assert "MinimalTopo" in script

    def test_torus(self):
        script = build_python_script(
            {"tipo": "estandar", "topologia": "torus", "x": 3, "y": 4}
        )
        assert "Torus2D" in script
        assert "x=3" in script
        assert "y=4" in script

    def test_topologia_desconocida_usa_tree(self):
        script = build_python_script({"tipo": "estandar", "topologia": "inventada"})
        assert "TreeTopo" in script

    @pytest.mark.parametrize("topo", TOPOLOGIAS_ESTANDAR)
    def test_script_es_python_valido(self, topo):
        """El script generado para cada topología debe ser Python sintácticamente correcto."""
        script = build_python_script({"tipo": "estandar", "topologia": topo})
        ast.parse(script)  # lanza SyntaxError si el script es inválido

    @pytest.mark.parametrize("topo", TOPOLOGIAS_ESTANDAR)
    def test_script_incluye_net_start_stop(self, topo):
        script = build_python_script({"tipo": "estandar", "topologia": topo})
        assert "net.start()" in script
        assert "net.stop()" in script


class TestTopologiaCustom:
    def test_custom_hosts_y_switches(self):
        intent = {
            "tipo": "custom",
            "switches": ["s1"],
            "hosts": ["h1", "h2"],
            "routers": [],
            "servers": [],
            "links": [["s1", "h1"], ["s1", "h2"]],
        }
        script = build_python_script(intent)
        assert "addSwitch('s1')" in script
        assert "addHost('h1'" in script
        assert "addHost('h2'" in script
        assert "addLink('s1', 'h1')" in script

    def test_custom_script_es_python_valido(self):
        intent = {
            "tipo": "custom",
            "switches": ["s1", "s2"],
            "hosts": ["h1", "h2"],
            "routers": [],
            "servers": [],
            "links": [["s1", "h1"], ["s2", "h2"], ["s1", "s2"]],
        }
        ast.parse(build_python_script(intent))
