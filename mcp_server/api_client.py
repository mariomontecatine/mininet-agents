"""Cliente HTTP mínimo contra la API del dashboard (dashboard/app.py).

Por qué existe: las tools MCP que ESCRIBEN no llaman a qos_intent.apply_qos_plan()
directamente. Esa función abre su propia sesión SSH contra la VM y reescribe
tmp/qos_intent_state.json. Si el proceso del servidor MCP la invocase mientras el
supervisor está corriendo tendríamos DOS escritores concurrentes sobre la misma
sesión tmux y sobre el mismo fichero de estado: comandos `tc` intercalados y
estado corrupto.

Enrutando por la API del dashboard, que vive dentro del proceso del supervisor,
se conserva un único escritor — y de regalo el dashboard refleja los cambios sin
trabajo extra.

Las tools de LECTURA sí importan los módulos directamente: son funciones puras
sobre ficheros, sin SSH ni estado compartido.
"""

import os
import sys

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config


DEFAULT_TIMEOUT = 120.0  # aplicar un plan implica varios `tc` por tmux


class NocApiUnavailable(RuntimeError):
    """El dashboard no responde: casi siempre el supervisor no está arrancado."""


def base_url() -> str:
    return f"http://127.0.0.1:{config.DASHBOARD_PORT}"


def _request(method: str, path: str, payload=None, timeout=DEFAULT_TIMEOUT):
    url = f"{base_url()}{path}"
    try:
        resp = httpx.request(method, url, json=payload, timeout=timeout)
    except httpx.ConnectError as e:
        raise NocApiUnavailable(
            f"No hay respuesta en {base_url()}. Arranca el NOC con "
            f"`python supervisor.py` antes de aplicar cambios de QoS."
        ) from e
    except httpx.TimeoutException as e:
        raise NocApiUnavailable(
            f"El dashboard no contestó a {path} en {timeout:.0f}s."
        ) from e

    # Los endpoints de QoS devuelven {"ok": false, "error": "..."} con 4xx/5xx.
    # Preferimos ese mensaje al genérico del status HTTP.
    try:
        data = resp.json()
    except ValueError:
        resp.raise_for_status()
        raise NocApiUnavailable(f"Respuesta no-JSON de {path}: {resp.text[:200]}")

    if isinstance(data, dict) and data.get("ok") is False:
        raise RuntimeError(data.get("error") or f"Error en {path}")
    if resp.status_code >= 400:
        raise RuntimeError(f"HTTP {resp.status_code} en {path}")
    return data


def get(path: str, timeout: float = 15.0):
    return _request("GET", path, timeout=timeout)


def post(path: str, payload=None, timeout: float = DEFAULT_TIMEOUT):
    return _request("POST", path, payload=payload, timeout=timeout)


def is_available() -> bool:
    """True si el dashboard responde. No lanza."""
    try:
        httpx.get(f"{base_url()}/api/topology-ready", timeout=2.0)
        return True
    except httpx.HTTPError:
        return False
