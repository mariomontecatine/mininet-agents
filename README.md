
```bash
curl -fsSL https://ollama.com/install.sh | sh

pip install -r requirements.txt

source venv/bin/activate

ollama run qwen

ssh mininet@192.168.173.6

tmux attach -t sesion_mininet
```

## Servidor MCP

Expone la QoS y la telemetría como herramientas MCP, consumibles por cualquier
cliente compatible. El analista del dashboard es uno de esos clientes.

```bash
mcp dev mcp_server/server.py                       # Inspector web, sin LLM

python -m mcp_server.server                        # stdio (editores)
python -m mcp_server.server --transport streamable-http   # en red, puerto 5001

MCP_READ_ONLY=1 python -m mcp_server.server        # sin herramientas de escritura
```

Aplicar QoS requiere el NOC arrancado (`python supervisor.py`): las escrituras
van por su API para no competir con el supervisor por la sesión tmux de la VM.

