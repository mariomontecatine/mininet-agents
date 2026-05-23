"""Tests del catálogo, validación de plan y endpoints QoS intent.

No requieren VM Mininet ni Ollama: stubbeamos host_port_map, get_ssh_connection
y send_tmux_command. apply_qos_plan se prueba inspeccionando los comandos
generados.
"""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents import apps_catalog
from agents import qos_intent


# ─── Catálogo ───────────────────────────────────────────────────────────────

def test_catalog_has_expected_apps():
    apps = apps_catalog.list_apps()
    assert "voip" in apps
    assert "youtube" in apps
    assert "linux_iso" in apps
    assert "dns" in apps


def test_catalog_entries_reference_known_service():
    from utils import config
    for app_id, meta in apps_catalog.APPLICATIONS.items():
        svc = meta["service"]
        assert svc in config.SERVICE_DEFS, f"{app_id} apunta a service desconocido {svc}"


def test_catalog_tier_classid_consistent():
    for tier in apps_catalog.TIER_CLASSID:
        assert tier in apps_catalog.TIER_PRIORITY


def test_resolve_service_returns_service_def():
    svc = apps_catalog.resolve_service("voip")
    assert svc is not None
    assert svc["transport"] == "udp"
    assert svc["dport"] == 5060


def test_describe_catalog_lists_all_apps():
    text = apps_catalog.describe_catalog()
    for app_id in apps_catalog.list_apps():
        assert app_id in text


# ─── build_qos_plan ──────────────────────────────────────────────────────────

@pytest.fixture
def host_port_map(tmp_path, monkeypatch):
    """Crea un host_port_map.json temporal y apunta qos_intent a él."""
    fake_map = {"h1": "s1-eth2", "h2": "s1-eth3", "srv1": "s2-eth1"}
    p = tmp_path / "host_port_map.json"
    p.write_text(json.dumps(fake_map), encoding="utf-8")
    monkeypatch.setattr(qos_intent, "HOST_PORT_FILE", str(p))
    return fake_map


def test_build_plan_simple(host_port_map):
    plan = qos_intent.build_qos_plan(
        "h1",
        [{"app": "voip"}, {"app": "youtube"}, {"app": "linux_iso"}],
        total_mbps=50,
    )
    assert plan["target_host"] == "h1"
    assert plan["target_port"] == "s1-eth2"
    assert plan["total_mbps"] == 50.0
    assert len(plan["apps"]) == 3
    apps_by_id = {a["app"]: a for a in plan["apps"]}
    assert apps_by_id["voip"]["tier"]    == "interactive"
    assert apps_by_id["voip"]["classid"] == "1:10"
    assert apps_by_id["voip"]["dport"]   == 5060
    assert apps_by_id["youtube"]["classid"]   == "1:20"
    assert apps_by_id["linux_iso"]["classid"] == "1:30"


def test_build_plan_unknown_host_raises(host_port_map):
    with pytest.raises(ValueError, match="no está en host_port_map"):
        qos_intent.build_qos_plan("h99", [{"app": "voip"}], 50)


def test_build_plan_unknown_app_raises(host_port_map):
    with pytest.raises(ValueError, match="no está en el catálogo"):
        qos_intent.build_qos_plan("h1", [{"app": "spotify"}], 50)


def test_build_plan_empty_apps_raises(host_port_map):
    with pytest.raises(ValueError, match="vacía"):
        qos_intent.build_qos_plan("h1", [], 50)


def test_build_plan_accepts_app_as_string(host_port_map):
    plan = qos_intent.build_qos_plan("h1", ["voip"], 20)
    assert plan["apps"][0]["app"] == "voip"


def test_build_plan_conflict_same_service_raises(host_port_map, monkeypatch):
    monkeypatch.setitem(apps_catalog.APPLICATIONS, "youtube_clone", {
        "description": "duplicado intencional",
        "service": "https",
        "tier": "streaming",
        "priority": 1,
        "min_mbps": 2.0,
        "max_mbps": 10.0,
    })
    with pytest.raises(ValueError, match="Conflicto"):
        qos_intent.build_qos_plan(
            "h1", [{"app": "youtube"}, {"app": "youtube_clone"}], 50,
        )


def test_build_plan_caps_minimums_when_oversubscribed(host_port_map):
    plan = qos_intent.build_qos_plan(
        "h1",
        [
            {"app": "youtube",   "min_mbps": 40, "max_mbps": 100},
            {"app": "linux_iso", "min_mbps": 40, "max_mbps": 100},
        ],
        total_mbps=20,
    )
    assert plan["capped"] is True
    suma = sum(a["min_mbps"] for a in plan["apps"])
    assert abs(suma - 20.0) < 0.01


def test_build_plan_overrides_min_max(host_port_map):
    plan = qos_intent.build_qos_plan(
        "h1",
        [{"app": "voip", "min_mbps": 3, "max_mbps": 8}],
        20,
    )
    a = plan["apps"][0]
    assert a["min_mbps"] == 3.0
    assert a["max_mbps"] == 8.0


# ─── apply_qos_plan: comandos tc generados ──────────────────────────────────

class _FakeSSH:
    def close(self): pass


def _patch_ssh(monkeypatch):
    sent = []
    monkeypatch.setattr(qos_intent, "get_ssh_connection", lambda: _FakeSSH())
    monkeypatch.setattr(qos_intent, "send_tmux_command",
                        lambda ssh, cmd: sent.append(cmd))
    return sent


def test_apply_emits_htb_root_and_classes(host_port_map, tmp_path, monkeypatch):
    monkeypatch.setattr(qos_intent, "STATE_FILE",  str(tmp_path / "state.json"))
    monkeypatch.setattr(qos_intent, "QOS_HISTORY", str(tmp_path / "qos.json"))
    sent = _patch_ssh(monkeypatch)

    plan = qos_intent.build_qos_plan(
        "h1",
        [{"app": "voip"}, {"app": "youtube"}, {"app": "linux_iso"}],
        50,
    )
    qos_intent.apply_qos_plan(plan)

    joined = "\n".join(sent)
    # Limpieza idempotente.
    assert "tc qdisc del dev s1-eth2 root" in joined
    # Raíz HTB con default 40.
    assert "tc qdisc add dev s1-eth2 root handle 1: htb default 40" in joined
    # Una class por tier presente (3 explícitos + best_effort por defecto).
    class_count = sum(1 for c in sent if "tc class add" in c)
    assert class_count >= 4
    # Filtros u32 con dport del servicio (sip 5060, https 443, http_alt 8080).
    assert "match ip dport 5060 0xffff" in joined
    assert "match ip dport 443 0xffff" in joined
    assert "match ip dport 8080 0xffff" in joined
    # flowid apuntando a las clases correctas.
    assert "flowid 1:10" in joined  # voip
    assert "flowid 1:20" in joined  # youtube
    assert "flowid 1:30" in joined  # linux_iso

    # Estado persistido.
    assert os.path.exists(qos_intent.STATE_FILE)
    saved = json.load(open(qos_intent.STATE_FILE))
    assert saved["target_host"] == "h1"
    assert len(saved["apps"]) == 3


def test_apply_is_idempotent_clears_root_first(host_port_map, tmp_path, monkeypatch):
    monkeypatch.setattr(qos_intent, "STATE_FILE",  str(tmp_path / "state.json"))
    monkeypatch.setattr(qos_intent, "QOS_HISTORY", str(tmp_path / "qos.json"))
    sent = _patch_ssh(monkeypatch)
    plan = qos_intent.build_qos_plan("h1", [{"app": "voip"}], 20)
    qos_intent.apply_qos_plan(plan)
    qos_intent.apply_qos_plan(plan)
    # Cada apply emite UN "tc qdisc del" (idempotencia).
    dels = [c for c in sent if "tc qdisc del dev s1-eth2 root" in c]
    assert len(dels) == 2


def test_clear_qos_intent_removes_state(host_port_map, tmp_path, monkeypatch):
    monkeypatch.setattr(qos_intent, "STATE_FILE",  str(tmp_path / "state.json"))
    monkeypatch.setattr(qos_intent, "QOS_HISTORY", str(tmp_path / "qos.json"))
    _patch_ssh(monkeypatch)
    plan = qos_intent.build_qos_plan("h1", [{"app": "voip"}], 20)
    qos_intent.apply_qos_plan(plan)
    assert os.path.exists(qos_intent.STATE_FILE)
    qos_intent.clear_qos_intent()
    assert not os.path.exists(qos_intent.STATE_FILE)


# ─── Endpoints Flask (smoke) ─────────────────────────────────────────────────

def test_heuristic_parser_detects_apps():
    apps = qos_intent.parse_qos_intent_heuristic(
        "Voy a ver YouTube en 4K, hacer una llamada VoIP y descargar una distribución de Linux."
    )
    keys = {a["app"] for a in apps}
    assert "voip" in keys
    assert "youtube" in keys
    assert "linux_iso" in keys


def test_heuristic_parser_empty_when_nothing_matches():
    apps = qos_intent.parse_qos_intent_heuristic("hola, qué tal")
    assert apps == []


def test_heuristic_parser_word_boundaries():
    """videollamada y video llamada → voip, no youtube (regresión)."""
    for text in ("hacer una videollamada", "video llamada con familia"):
        keys = {a["app"] for a in qos_intent.parse_qos_intent_heuristic(text)}
        assert "voip" in keys
        assert "youtube" not in keys, f"FP video→youtube en {text!r}: {keys}"


def test_heuristic_parser_handles_uppercase_and_accents():
    keys = {a["app"] for a in qos_intent.parse_qos_intent_heuristic(
        "Necesito ver VÍDEO en alta definición")}
    assert "youtube" in keys


def test_llm_falls_back_on_timeout(host_port_map, tmp_path, monkeypatch):
    """Si Ollama lanza una excepción (p. ej. ReadTimeout), el parser cae al
    heurístico y devuelve un plan válido marcado como 'heuristic'.
    """
    monkeypatch.setattr(qos_intent, "STATE_FILE",  str(tmp_path / "state.json"))
    monkeypatch.setattr(qos_intent, "QOS_HISTORY", str(tmp_path / "qos.json"))

    class _BoomClient:
        def chat(self, *a, **kw):
            raise TimeoutError("read timed out")
    monkeypatch.setattr(qos_intent, "_ollama_client", _BoomClient())

    plan = qos_intent.parse_qos_intent_llm(
        "Quiero hacer una llamada VoIP y descargar Linux",
        default_total_mbps=50,
    )
    assert plan["parsed_by"] == "heuristic"
    assert "TimeoutError" in (plan.get("fallback_reason") or "")
    keys = {a["app"] for a in plan["apps"]}
    assert "voip" in keys and "linux_iso" in keys


def test_endpoints_register(host_port_map, tmp_path, monkeypatch):
    """Comprueba que la app Flask expone los nuevos endpoints sin ejecutar SSH."""
    monkeypatch.setattr(qos_intent, "STATE_FILE",  str(tmp_path / "state.json"))
    monkeypatch.setattr(qos_intent, "QOS_HISTORY", str(tmp_path / "qos.json"))
    _patch_ssh(monkeypatch)

    from dashboard import app as dash_app
    # Apuntamos el dashboard a un tmp/ temporal con el host_port_map fake.
    monkeypatch.setattr(dash_app, "_TMP_DIR", os.path.dirname(host_port_map and
                                                              qos_intent.HOST_PORT_FILE))

    client = dash_app.app.test_client()
    r = client.get("/api/qos-intent/catalog")
    assert r.status_code == 200
    payload = r.get_json()
    assert "voip" in payload["apps"]
    assert "h1" in payload["hosts"]

    # Apply con plan estructurado (sin LLM)
    plan_body = {
        "plan": {
            "target_host": "h1",
            "total_mbps":  20,
            "apps":        [{"app": "voip"}, {"app": "linux_iso"}],
        }
    }
    r = client.post("/api/qos-intent/apply", json=plan_body)
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d["ok"] is True
    assert d["plan"]["target_port"] == "s1-eth2"

    # State refleja lo aplicado
    r = client.get("/api/qos-intent/state")
    assert r.status_code == 200
    st = r.get_json()["state"]
    assert st["target_host"] == "h1"

    # Clear
    r = client.post("/api/qos-intent/clear")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
