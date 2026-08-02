"""Analista NOC: informes y preguntas sobre el estado de la red en lenguaje natural.

Se diferencia de monitor_agent.generate_network_report() en tres cosas. Aquel
recibe un string de telemetría ya formateado, no puede consultar nada más y
devuelve como mucho cinco líneas por ciclo. Este:

  1. Construye su propio contexto agregando TODA la telemetría disponible
     (agents/telemetry_digest.py): tráfico por puerto, flujos, detecciones,
     historial de QoS, ataques inyectados, servicios y failover.
  2. Puede profundizar llamando a las herramientas del servidor MCP cuando la
     pregunta lo requiere.
  3. Mantiene conversación: se le pueden hacer preguntas de seguimiento.

Es de SOLO LECTURA por diseño: diagnostica y explica, pero no toca la red. Quien
actúa es el resolver. Así no compiten dos actuadores por el mismo puerto y el
analista no puede romper una demo en directo.

Puede analizar tanto la sesión viva (tmp/) como un run archivado
(saved_runs/<nombre>/) pasando `source_dir`, lo que permite informes post-mortem
de una ejecución pasada.
"""

import json
import os
import sys
import time
from datetime import datetime

import ollama

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config
from agents import telemetry_digest


# Subconjunto de herramientas MCP que el analista puede usar: solo consulta.
#
# Son pocas a propósito. El servidor publica más, pero cada esquema que se le
# ofrece al modelo ocupa sitio en la ventana de contexto, y qwen2.5:3b trabaja
# con 4096 tokens: ofrecerle las nueve tools de lectura junto al digest hacía
# que la telemetría se truncara y el modelo se inventara los datos. Aquí se
# dejan solo las que aportan algo que el digest NO trae ya — una ventana de
# tiempo distinta, más flujos, el catálogo de apps.
READ_ONLY_TOOLS = frozenset({
    "get_traffic_summary",
    "get_top_flows",
    "get_recent_alerts",
    "list_qos_catalog",
})

_GROUNDING = (
    "REGLAS ESTRICTAS:\n"
    "1. Usa ÚNICAMENTE los datos del contexto o los que devuelvan las "
    "herramientas. No inventes cifras, puertos ni hosts.\n"
    "2. Nombra puertos y hosts exactamente como aparecen (s3-eth2, h7, srv1).\n"
    "3. Si un dato no está disponible, di literalmente: 'No tengo ese dato en "
    "la telemetría'. No especules.\n"
    "4. Cuando cites un evento, incluye su marca de tiempo o su ciclo.\n"
    "5. Escribe en español, en prosa clara y sin markdown.\n"
    "6. No propongas comandos concretos de tc ni de OpenFlow: tu papel es "
    "diagnosticar y explicar, no actuar."
)

_SUMMARY_SYSTEM = (
    "Eres un analista senior de un centro de operaciones de red (NOC) que "
    "vigila una red Mininet con routers, switches, hosts y servidores.\n\n"
    "Redacta un informe breve del estado de la red: entre cinco y ocho frases, "
    "en un solo párrafo o dos. Cubre, si hay datos: qué está pasando "
    "(normalidad o incidente y de qué tipo), qué puertos y hosts están "
    "implicados, y qué mitigaciones de QoS hay activas y desde cuándo.\n\n"
    "Ojo con dos listas que NO son lo mismo: 'anomalías que el sistema detectó' "
    "es lo que el NOC vio, y 'ataques que se lanzaron de verdad' es lo que "
    "realmente ocurrió. Si un ataque aparece en la segunda y no en la primera, "
    "pasó desapercibido; no digas que no hubo ataques solo porque no haya "
    "detecciones.\n\n"
    "Escribe para un operador humano que quiere entender la situación de un "
    "vistazo, no para una máquina.\n\n" + _GROUNDING
)

_ANSWER_SYSTEM = (
    "Eres un analista senior de un centro de operaciones de red (NOC) que "
    "vigila una red Mininet. Respondes preguntas del operador sobre el estado "
    "de la red.\n\n"
    "Tienes un resumen de la telemetría en el contexto. Cubre casi todas las "
    "preguntas: respóndelas directamente sin llamar a ninguna herramienta. "
    "Recurre a las herramientas solo si necesitas un detalle que no esté en el "
    "contexto (por ejemplo el catálogo de aplicaciones o una ventana de tráfico "
    "distinta).\n\n"
    "Responde de forma directa y concreta, en pocas frases. Si la pregunta no "
    "tiene que ver con la red, dilo y ofrece ayudar con la red.\n\n" + _GROUNDING
)


def _client():
    return ollama.Client(
        host="http://localhost:11434",
        timeout=getattr(config, "ANALYST_LLM_TIMEOUT", 300),
    )


def _context_block(window_min=None, source_dir=None, compact=False):
    window_min = window_min or getattr(config, "ANALYST_WINDOW_MIN", 5)
    ctx = telemetry_digest.build_network_context(window_min=window_min,
                                                 source_dir=source_dir,
                                                 compact=compact)
    return ctx, telemetry_digest.render_context_text(ctx)


# ─── Registro auditable ──────────────────────────────────────────────────────
# Cada consulta se archiva junto al digest EXACTO que recibió el modelo. Sin
# esto no se puede juzgar una respuesta a posteriori: si el analista dice "no se
# detectó ningún ataque" hay que poder distinguir si mintió o si, en el instante
# de la pregunta, todavía no había ocurrido nada. El digest es la prueba.

HISTORY_FILE = "analyst_history.jsonl"
HISTORY_MAX = 50  # cada entrada lleva ~3 KB de digest; se acota el fichero


def _history_path(source_dir=None) -> str:
    return os.path.join(source_dir or telemetry_digest.TMP_DIR, HISTORY_FILE)


def _record_history(kind, question, answer_text, context_text, meta,
                    source_dir=None):
    """Añade una consulta al registro. Nunca interrumpe la respuesta al usuario."""
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "kind": kind,                     # "ask" | "summary"
        "question": question,
        "answer": answer_text,
        "context": context_text,          # el digest literal que vio el modelo
        "cycle": meta.get("cycle"),
        "model": meta.get("model"),
        "elapsed_ms": meta.get("elapsed_ms"),
        "sources": meta.get("sources") or [],
        "tool_calls": meta.get("tool_calls") or [],
    }
    path = _history_path(source_dir)
    try:
        rows = load_history(source_dir=source_dir)
        rows.append(entry)
        rows = rows[-HISTORY_MAX:]
        # Reescritura completa (no append) para poder aplicar el recorte.
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        os.replace(tmp_path, path)
    except (IOError, OSError) as e:
        print(f"[ANALISTA] WARN no se pudo archivar la consulta: {e}")
    return entry


def load_history(limit=None, source_dir=None) -> list:
    """Consultas archivadas, de la más antigua a la más reciente."""
    rows = telemetry_digest.read_jsonl(HISTORY_FILE, limit=limit,
                                       source_dir=source_dir)
    return rows


def _has_data(ctx) -> bool:
    """¿Hay algo que analizar? Evita gastar una llamada al LLM en un tmp/ vacío."""
    return bool(
        ctx.get("cycle")
        or (ctx.get("traffic") or {}).get("ports")
        or (ctx.get("flows") or {}).get("flows")
        or ctx.get("alerts")
    )


def summarize(window_min=None, source_dir=None) -> dict:
    """Informe narrativo del estado de la red. Sin herramientas, un disparo.

    Devuelve {report, elapsed_ms, model, context_chars, sources}.
    """
    started = time.time()
    # Perfil compacto: el informe narrativo no necesita el detalle completo y en
    # inferencia por CPU el prompt es lo que cuesta.
    ctx, text = _context_block(window_min, source_dir, compact=True)

    if not _has_data(ctx):
        return {
            "report": "Todavía no hay telemetría suficiente para un informe. "
                      "Arranca el supervisor y espera a que complete algún ciclo.",
            "elapsed_ms": 0,
            "model": None,
            "context_chars": len(text),
            "sources": [],
        }

    response = _client().chat(
        model=getattr(config, "MODEL_ANALYST", "qwen2.5:7b"),
        messages=[
            {"role": "system", "content": _SUMMARY_SYSTEM},
            {"role": "user", "content": f"TELEMETRÍA DE LA RED:\n\n{text}"},
        ],
        # num_predict acota la generación: el informe pedido son 5-8 frases, y
        # sin tope los modelos pequeños siguen escribiendo y duplican la espera.
        options={"temperature": 0.2, "num_predict": 400},
    )
    report = ((response.get("message", {}) or {}).get("content") or "").strip()

    result = {
        "report": report,
        "elapsed_ms": int((time.time() - started) * 1000),
        "model": getattr(config, "MODEL_ANALYST", "qwen2.5:7b"),
        "context_chars": len(text),
        "sources": _sources_for(ctx),
        "cycle": ctx.get("cycle"),
        "context": text,
    }
    _record_history("summary", None, report, text, result, source_dir=source_dir)
    return result


def answer(question, history=None, window_min=None, source_dir=None) -> dict:
    """Responde una pregunta sobre la red, con herramientas MCP si hace falta.

    history: lista de {role, content} de turnos anteriores (se recortan a los
    últimos 6 para no inflar el contexto de un modelo local).

    Devuelve {answer, tool_calls, elapsed_ms, model, sources}.
    """
    started = time.time()
    question = (question or "").strip()
    if not question:
        raise ValueError("La pregunta está vacía.")

    # Compacto también aquí: al digest hay que sumarle el prompt de sistema, el
    # historial y los esquemas de las herramientas, y todo junto debe caber en
    # la ventana del modelo. Si se desborda, Ollama trunca por silencio y el
    # modelo responde inventándose los datos que le faltan.
    ctx, text = _context_block(window_min, source_dir, compact=True)

    messages = [{"role": "system", "content": _ANSWER_SYSTEM},
                {"role": "user", "content": f"TELEMETRÍA DE LA RED:\n\n{text}"}]
    for turn in (history or [])[-6:]:
        role = turn.get("role")
        content = (turn.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": question})

    # Import tardío: mcp_server importa este paquete indirectamente y así se
    # evita una dependencia circular en tiempo de carga.
    from agents import mcp_ollama_bridge
    from mcp_server.server import mcp as mcp_server_instance

    try:
        reply, trace = mcp_ollama_bridge.chat_with_tools(
            mcp_server_instance,
            messages,
            allowed_tools=READ_ONLY_TOOLS,
        )
    except Exception as e:
        # Si el puente falla (Ollama caído, servidor MCP roto), seguimos
        # respondiendo con el contexto ya calculado: el analista nunca se queda
        # mudo, porque lo esencial ya está en el prompt.
        reply, trace = _answer_without_tools(messages), []
        reply = f"{reply}\n\n(Sin herramientas: {type(e).__name__}.)"

    result = {
        "answer": reply or "No he podido generar una respuesta.",
        "tool_calls": trace,
        "elapsed_ms": int((time.time() - started) * 1000),
        "model": getattr(config, "MODEL_ANALYST", "qwen2.5:7b"),
        "sources": _sources_for(ctx),
        "cycle": ctx.get("cycle"),
        "context": text,
        "context_chars": len(text),
    }
    _record_history("ask", question, result["answer"], text, result,
                    source_dir=source_dir)
    return result


def _answer_without_tools(messages) -> str:
    response = _client().chat(
        model=getattr(config, "MODEL_ANALYST", "qwen2.5:7b"),
        messages=messages,
        options={"temperature": 0.2, "num_predict": 400},
    )
    return ((response.get("message", {}) or {}).get("content") or "").strip()


def _sources_for(ctx) -> list:
    """Qué ficheros de telemetría alimentaron la respuesta. Para trazabilidad:
    el operador puede contrastar lo que dice el modelo con el dato crudo."""
    found = []
    if ctx.get("cycle") is not None:
        found.append("state.json")
    if (ctx.get("traffic") or {}).get("ports"):
        found.append("live_metrics.json")
    if (ctx.get("flows") or {}).get("flows"):
        found.append("flows.json")
    if ctx.get("alerts"):
        found.append("flow_alerts.jsonl")
    if ctx.get("injections"):
        found.append("anomaly_injections.jsonl")
    if ctx.get("qos_events"):
        found.append("qos_history.json")
    if ctx.get("qos_intent_plans"):
        found.append("qos_intent_state.json")
    return found


def write_report(path=None, window_min=None, source_dir=None) -> str:
    """Genera el informe y lo deja en tmp/analyst_report.md. Devuelve la ruta.

    Pensado para el cierre de una ejecución, junto al attack_report.md que ya
    produce agents/attack_report.py.
    """
    path = path or os.path.join(telemetry_digest.TMP_DIR, "analyst_report.md")
    result = summarize(window_min=window_min, source_dir=source_dir)
    lines = [
        "# Informe del analista NOC",
        "",
        f"- Modelo: `{result.get('model')}`",
        f"- Generado en: {result.get('elapsed_ms')} ms",
        f"- Fuentes: {', '.join(result.get('sources') or []) or 'ninguna'}",
        "",
        result.get("report") or "",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


if __name__ == "__main__":
    out = summarize()
    print(f"=== INFORME DEL ANALISTA ({out['model']}, {out['elapsed_ms']} ms) ===")
    print(out["report"])
    print(f"\nFuentes: {', '.join(out['sources'])}")
