"""Adaptador entre un servidor MCP y el tool-calling de Ollama.

Ollama no habla MCP: espera las herramientas en el formato de OpenAI
({"type":"function","function":{...,"parameters":<json-schema>}}) y devuelve las
llamadas en `message.tool_calls`. MCP, por su parte, publica cada herramienta
como {name, description, input_schema}. La traducción es casi directa — de hecho
el resultado es prácticamente el mismo dict que agents/qos_intent.py construye a
mano en _TOOL_SCHEMA — y es lo único que separa a un modelo local de poder usar
un servidor MCP estándar.

Se conecta al servidor EN EL MISMO PROCESO (`Client(servidor)`): el SDK levanta
un transporte en memoria y hace el handshake MCP completo, sin sockets ni
subprocesos. Es protocolo real, no un atajo, y evita tener que arrancar un
proceso aparte solo para que el dashboard pueda preguntar por la red. Pasando
una URL en vez del objeto servidor, el mismo código habla con un servidor MCP
remoto por HTTP.
"""

import json
import os
import sys

import anyio
import ollama
from mcp import Client

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config


def mcp_tools_to_ollama(tools) -> list:
    """Traduce una lista de Tool de MCP al esquema de tools de Ollama."""
    out = []
    for t in tools:
        out.append({
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema or {"type": "object", "properties": {}},
            },
        })
    return out


def _result_to_text(result) -> str:
    """Aplana un CallToolResult al texto que se le devuelve al modelo."""
    if getattr(result, "structured_content", None):
        return json.dumps(result.structured_content, ensure_ascii=False, default=str)
    parts = []
    for block in result.content or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts) if parts else "(sin contenido)"


async def _chat_loop(server, model, messages, allowed_tools, max_rounds,
                     timeout, temperature):
    client = ollama.Client(host="http://localhost:11434", timeout=timeout)
    trace = []

    async with Client(server) as session:
        listed = await session.list_tools()
        tools = list(listed.tools)
        if allowed_tools is not None:
            tools = [t for t in tools if t.name in allowed_tools]
        ollama_tools = mcp_tools_to_ollama(tools)
        valid_names = {t.name for t in tools}

        convo = list(messages)
        for _round in range(max_rounds):
            response = await anyio.to_thread.run_sync(
                lambda: client.chat(model=model, messages=convo,
                                    tools=ollama_tools,
                                    options={"temperature": temperature,
                                             "num_predict": 400})
            )
            msg = response.get("message", {}) or {}
            calls = msg.get("tool_calls") or []
            if not calls:
                return (msg.get("content") or "").strip(), trace

            # Ollama no siempre devuelve el mensaje del asistente completo; lo
            # reconstruimos para que el modelo vea su propia llamada al releer
            # la conversación en la siguiente vuelta.
            convo.append({"role": "assistant",
                          "content": msg.get("content") or "",
                          "tool_calls": calls})

            for call in calls:
                fn = call.get("function", {}) or {}
                name = fn.get("name")
                args = fn.get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}

                if name not in valid_names:
                    # Los modelos pequeños se inventan nombres de herramienta.
                    # Se lo decimos en vez de romper: suele reintentar bien.
                    output = (f"ERROR: la herramienta '{name}' no existe. "
                              f"Disponibles: {sorted(valid_names)}")
                else:
                    try:
                        result = await session.call_tool(name, args)
                        output = _result_to_text(result)
                        if result.is_error:
                            output = f"ERROR: {output}"
                    except Exception as e:
                        output = f"ERROR ejecutando '{name}': {type(e).__name__}: {e}"

                trace.append({"tool": name, "arguments": args,
                              "ok": not output.startswith("ERROR")})
                convo.append({"role": "tool", "name": name, "content": output})

        # Agotadas las vueltas: pedimos el cierre sin herramientas para que
        # redacte con lo que ya ha recogido en vez de quedarse en bucle.
        response = await anyio.to_thread.run_sync(
            lambda: client.chat(model=model, messages=convo,
                                options={"temperature": temperature})
        )
        content = (response.get("message", {}) or {}).get("content") or ""
        return content.strip(), trace


def chat_with_tools(server, messages, model=None, allowed_tools=None,
                    max_rounds=None, timeout=None, temperature=0.2):
    """Ejecuta un bucle de tool-calling contra `server` y devuelve (texto, traza).

    server:        instancia de MCPServer (en proceso) o URL de un servidor MCP.
    allowed_tools: si se pasa, solo se ofrecen esas herramientas — así el
                   analista queda limitado a las de lectura.

    Función síncrona a propósito: la llaman endpoints Flask y el supervisor,
    que no son async.
    """
    model = model or getattr(config, "MODEL_ANALYST", "qwen2.5:7b")
    max_rounds = max_rounds or getattr(config, "ANALYST_MAX_TOOL_ROUNDS", 4)
    timeout = timeout or getattr(config, "ANALYST_LLM_TIMEOUT", 300)
    return anyio.run(_chat_loop, server, model, messages, allowed_tools,
                     max_rounds, timeout, temperature)
