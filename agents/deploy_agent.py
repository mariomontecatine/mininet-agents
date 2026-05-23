import sys
import os
import re
import time
import json
import ollama

# Parche para rutas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config
from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)
from agents.topology import run_visualizer

VM_PASSWORD = "mininet"
MODEL_NAME = config.MODEL_DEPLOY

TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)
SERVER_SERVICES_FILE = os.path.join(TMP_DIR, "server_services.json")

# ── Lanzadores de servicio embebidos ────────────────────────────────────────
# Se vuelcan en /tmp/service_launchers.py dentro de la VM al iniciarse la
# topología. Cada servidor srv* invoca uno de ellos según su tipo asignado.
# Sin dependencias externas: Python 3 estándar.
_SERVICE_LAUNCHERS_PY = r'''"""Lanzadores de servicio para los servidores Mininet (sin dependencias externas)."""
import sys, socket, struct, threading


def serve_http():
    import http.server, socketserver, os, secrets
    # Servimos desde /tmp/web/ con un fichero de contenido para que el tráfico
    # HTTP del simulador tenga volumen visible. Sin esto los wget reciben sólo
    # el listado de directorio (~200 B) y el panel de protocolos no ve HTTP.
    os.makedirs("/tmp/web", exist_ok=True)
    page = "/tmp/web/page.bin"
    if not os.path.exists(page):
        with open(page, "wb") as f:
            f.write(secrets.token_bytes(200 * 1024))   # 200 KB pseudo-random
    os.chdir("/tmp/web")
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", 80), http.server.SimpleHTTPRequestHandler) as srv:
        srv.serve_forever()


def serve_dns():
    """Servidor DNS minimalista. Responde 1.2.3.4 a cualquier consulta tipo A."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 53))
    while True:
        try:
            data, addr = s.recvfrom(512)
            if len(data) < 12:
                continue
            txid = data[:2]
            flags = b"\x81\x80"
            qd = data[4:6]
            an = b"\x00\x01"
            ns = b"\x00\x00"
            ar = b"\x00\x00"
            header = txid + flags + qd + an + ns + ar
            q_end = 12
            while q_end < len(data) and data[q_end] != 0:
                q_end += data[q_end] + 1
            q_end += 5
            question = data[12:q_end] if q_end <= len(data) else data[12:]
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"
            s.sendto(header + question + answer, addr)
        except Exception:
            pass


def serve_sip():
    """Servidor SIP minimalista. Responde 200 OK a OPTIONS/INVITE/REGISTER."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 5060))
    while True:
        try:
            data, addr = s.recvfrom(4096)
            head = data[:9].upper()
            if (head.startswith(b"OPTIONS ") or head.startswith(b"INVITE ")
                    or head.startswith(b"REGISTER")):
                s.sendto(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n", addr)
            else:
                s.sendto(b"SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n", addr)
        except Exception:
            pass


def _ssh_handle(c):
    try:
        c.sendall(b"SSH-2.0-OpenSSH_8.0p1 MininetSim\r\n")
        c.settimeout(3)
        try:
            c.recv(4096)
        except Exception:
            pass
    finally:
        try:
            c.close()
        except Exception:
            pass


def serve_ssh():
    """Listener SSH simulado. Emite banner válido y cierra la conexión."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 22))
    s.listen(8)
    while True:
        try:
            c, _ = s.accept()
            threading.Thread(target=_ssh_handle, args=(c,), daemon=True).start()
        except Exception:
            pass


if __name__ == "__main__":
    handlers = {"http": serve_http, "dns": serve_dns, "sip": serve_sip, "ssh": serve_ssh}
    fn = handlers.get(sys.argv[1] if len(sys.argv) > 1 else "http")
    if fn is None:
        sys.exit(1)
    fn()
'''


def assign_server_types(intent):
    """
    Devuelve {srv_name: service_type} para el intent dado.

    Prioridad: intent.server_types (si el LLM lo emitió) > rotación por defecto
    (DEFAULT_SERVER_TYPE_ROTATION). En topologías estándar no hay srv* → {}.
    """
    if intent.get("tipo") != "custom":
        return {}

    servers = [s for s in intent.get("servers", []) if s.strip()]
    if not servers:
        return {}

    user_assigned = intent.get("server_types") or {}
    rotation = config.DEFAULT_SERVER_TYPE_ROTATION

    def _srv_idx(name):
        m = re.search(r"(\d+)", name)
        return int(m.group(1)) if m else 0

    ordered = sorted(servers, key=_srv_idx)
    out = {}
    auto_i = 0
    for srv in ordered:
        explicit = user_assigned.get(srv)
        if explicit in config.SERVICE_DEFS:
            out[srv] = explicit
        else:
            out[srv] = rotation[auto_i % len(rotation)]
            auto_i += 1
    return out


def _persist_server_services(server_types, host_ips):
    """Guarda tmp/server_services.json para traffic y dashboard.

    Estructura: {srv_name: {type, ip, port, transport}}.
    """
    services = {}
    for srv, stype in server_types.items():
        svc = config.SERVICE_DEFS.get(stype, config.SERVICE_DEFS["http"])
        services[srv] = {
            "type":      stype,
            "ip":        host_ips.get(srv),
            "port":      svc["dport"],
            "transport": svc["transport"],
        }
    try:
        with open(SERVER_SERVICES_FILE, "w", encoding="utf-8") as f:
            json.dump(services, f, ensure_ascii=False, indent=2)
    except IOError:
        pass
    return services

_ollama_deploy_client = ollama.Client(host="http://localhost:11434")


def generate_network_intent(user_prompt):
    """Convierte lenguaje natural en un JSON estructurado (Arquitectura Unificada)."""
    print("\n[IA] Evaluando intención del usuario y generando diseño...")

    system_prompt = (
        "Eres un arquitecto de red para Mininet. Devuelve un JSON válido.\n\n"
        "REGLA DE DECISIÓN:\n"
        "1. MODO ESTÁNDAR: Si piden una red clásica de Mininet, elige la topología más adecuada:\n"
        "   - 'tree'    → árbol jerárquico. Params: depth (profundidad), fanout (hijos por nodo).\n"
        '     Ejemplo: {"tipo": "estandar", "topologia": "tree", "depth": 3, "fanout": 4}\n'
        "   - 'linear'  → cadena de switches en línea. Params: k (nº switches), n (hosts/switch, defecto 1).\n"
        '     Ejemplo: {"tipo": "estandar", "topologia": "linear", "k": 4, "n": 1}\n'
        "   - 'single'  → un único switch con múltiples hosts. Params: k (nº hosts).\n"
        '     Ejemplo: {"tipo": "estandar", "topologia": "single", "k": 6}\n'
        "   - 'minimal' → topología mínima (1 switch, 2 hosts). Sin parámetros adicionales.\n"
        '     Ejemplo: {"tipo": "estandar", "topologia": "minimal"}\n'
        "   - 'torus'   → malla toroidal 2D. Params: x (ancho), y (alto).\n"
        '     Ejemplo: {"tipo": "estandar", "topologia": "torus", "x": 3, "y": 3}\n'
        "2. MODO CUSTOM: Si piden servidores, routers, o diseños a medida.\n"
        "   REGLAS DE CABLEADO (estrictas):\n"
        "   - Hosts (h*) y servidores (srv*) SIEMPRE se conectan a un SWITCH (s*). NUNCA entre sí.\n"
        "   - Switches (s*) se conectan a routers (r*) u otros switches (s*).\n"
        "   - Routers (r*) se conectan a switches (s*) u otros routers (r*).\n"
        "   - PROHIBIDO: [h1,srv1], [h1,h2], [srv1,srv2]. CORRECTO: [s1,h1], [s1,srv1].\n"
        "   OBLIGATORIO: el campo 'links' debe contener TODOS los enlaces. "
        "Sin links los nodos quedan aislados.\n"
        "   OBLIGATORIO si el usuario menciona el tipo de algún servidor: "
        "incluye el campo 'server_types' con el mapping srv_name → tipo.\n"
        "   Valores soportados: http, dns, ssh, sip. Sinónimos a reconocer:\n"
        "     - 'web', 'http', 'apache', 'nginx', 'página', 'servidor web'      → http\n"
        "     - 'dns', 'resolución', 'nameserver', 'bind'                       → dns\n"
        "     - 'ssh', 'shell', 'terminal', 'acceso remoto'                     → ssh\n"
        "     - 'sip', 'voip', 'voz', 'teléfono', 'llamadas'                    → sip\n"
        "   Si el usuario no menciona el tipo de un srv*, omítelo y se rotará por defecto.\n"
        '   Ejemplo: {"tipo": "custom", "routers": ["r1"], "switches": ["s1", "s2"], '
        '"servers": ["srv1", "srv2", "srv3", "srv4"], "hosts": ["h1", "h2"], '
        '"server_types": {"srv1": "http", "srv2": "dns", "srv3": "sip", "srv4": "ssh"}, '
        '"links": [["r1", "s1"], ["r1", "s2"], ["s1", "h1"], ["s1", "h2"], '
        '["s2", "srv1"], ["s2", "srv2"], ["s2", "srv3"], ["s2", "srv4"]]}\n'
        "   Enumera TODOS los pares de conexión, uno por línea del array."
    )

    tools = [
        {
            "type": "function",
            "function": {
                "name": "build_network_json",
                "description": "Construye la estructura de la red",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tipo": {
                            "type": "string",
                            "description": "'estandar' o 'custom'",
                        },
                        "topologia": {
                            "type": "string",
                            "enum": ["tree", "linear", "single", "minimal", "torus"],
                            "description": "Topología estándar de Mininet",
                        },
                        "depth": {"type": "integer", "description": "Profundidad del árbol (tree)"},
                        "fanout": {"type": "integer", "description": "Hijos por nodo (tree)"},
                        "k": {"type": "integer", "description": "Nº de switches (linear) o hosts (single)"},
                        "n": {"type": "integer", "description": "Hosts por switch (linear, defecto 1)"},
                        "x": {"type": "integer", "description": "Dimensión X de la malla (torus)"},
                        "y": {"type": "integer", "description": "Dimensión Y de la malla (torus)"},
                        "routers": {"type": "array", "items": {"type": "string"}},
                        "servers": {"type": "array", "items": {"type": "string"}},
                        "switches": {"type": "array", "items": {"type": "string"}},
                        "hosts": {"type": "array", "items": {"type": "string"}},
                        "links": {
                            "type": "array",
                            "description": "OBLIGATORIO en modo custom. Lista de todos los enlaces [[nodo1, nodo2], ...].",
                            "items": {"type": "array", "items": {"type": "string"}},
                        },
                        "server_types": {
                            "type": "object",
                            "description": (
                                "Opcional. Mapeo srv_name → tipo de servicio "
                                "(http, dns, ssh, sip). Si se omite se asigna por rotación."
                            ),
                            "additionalProperties": {"type": "string"},
                        },
                    },
                    "required": ["tipo"],
                },
            },
        }
    ]

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    best_args = None  # mejor intento parcial guardado como fallback

    for intento in range(1, 4):
        try:
            print(f"[IA] Intento {intento}/3 con {MODEL_NAME} "
                  f"(mensajes={len(messages)})...")
            t0 = time.time()
            response = _ollama_deploy_client.chat(
                model=MODEL_NAME,
                messages=messages,
                tools=tools,
                options={"temperature": 0},
            )
            dt = time.time() - t0
            print(f"[IA] Respuesta recibida en {dt:.1f}s.")

            if response.get("message", {}).get("tool_calls"):
                args = response["message"]["tool_calls"][0]["function"]["arguments"]

                if args.get("tipo") != "custom":
                    return args

                if not args.get("links"):
                    print(f"[WARN] Intento {intento}: la IA no incluyó enlaces. Reintentando...")
                    messages.append(response["message"])
                    messages.append({
                        "role": "user",
                        "content": (
                            "INCOMPLETO: falta el campo 'links'. "
                            "Llama de nuevo a build_network_json incluyendo TODOS los enlaces "
                            "entre los nodos que ya definiste."
                        ),
                    })
                    continue

                args = _fix_invalid_links(args)
                isolated = _find_isolated_nodes(args)
                disconnected = _find_disconnected_switches(args)
                empty_leaves = _find_empty_leaf_switches(args)
                problems = isolated | disconnected | empty_leaves
                if problems:
                    best_args = args
                    parts = []
                    if isolated:
                        parts.append(f"Nodos sin ningún enlace: {sorted(isolated)}.")
                    if disconnected - isolated:
                        parts.append(f"Switches sin ruta a router: {sorted(disconnected - isolated)}.")
                    if empty_leaves:
                        parts.append(
                            f"Switches hoja sin endpoints directos: {sorted(empty_leaves)}. "
                            "Cada switch hoja DEBE tener al menos un host (h*) o servidor (srv*) "
                            "conectado directamente a él."
                        )
                    label = "; ".join(p.rstrip(".") for p in parts)
                    print(f"[WARN] Intento {intento}: {label}. Reintentando...")
                    messages.append(response["message"])
                    messages.append({
                        "role": "user",
                        "content": (
                            f"TOPOLOGÍA INCOMPLETA. {'  '.join(parts)} "
                            "Llama de nuevo a build_network_json corrigiendo todos estos problemas."
                        ),
                    })
                    continue

                return args

            print(f"[WARN] Intento {intento}: la IA no invocó la herramienta. Reintentando con instrucción explícita...")
            # Reintentamos pidiendo expresamente la llamada a la herramienta —
            # los modelos pequeños a veces responden en texto plano y abandonar
            # tras el primer intento perdía el resto de la cuota de reintentos.
            messages.append(response.get("message") or {"role": "assistant", "content": ""})
            messages.append({
                "role": "user",
                "content": (
                    "DEBES llamar a la herramienta `build_network_json` con la "
                    "topología en formato estructurado. NO respondas en texto plano. "
                    "Invoca la herramienta ahora con todos los campos: tipo='custom', "
                    "routers, switches, servers, hosts y links."
                ),
            })
            continue

        except Exception as e:
            # Timeout o error de red: NO abandonamos al primer fallo, reintentamos
            # con contexto fresco — un Ctrl+C explícito sigue rompiendo el bucle.
            print(f"[WARN] Intento {intento} falló ({type(e).__name__}: {e}). Reintentando con contexto reducido...")
            # Reset de mensajes: descartamos el historial acumulado (que crece y
            # ralentiza cada llamada) y reintentamos con solo system + user.
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
            continue

    # Último recurso: inferir enlaces faltantes desde el texto del prompt
    if best_args is not None:
        print("[INFER] Infiriendo enlaces faltantes desde el prompt...")
        best_args = _infer_missing_links(best_args, user_prompt)
        still_missing = _find_isolated_nodes(best_args)
        if still_missing:
            print(f"[WARN] Topología parcial: {sorted(still_missing)} siguen sin enlazar.")
        else:
            print("[INFER] Topología completada por inferencia del prompt.")
        return best_args

    print("[ERROR] La IA no completó la topología tras 3 intentos.")
    return None


def _find_empty_leaf_switches(intent):
    """Devuelve switches hoja (1 solo vecino infra) sin ningún endpoint conectado.

    Los switches de tránsito con múltiples uplinks son legítimamente vacíos de
    endpoints (p.ej. s2 en una DMZ que conecta r1↔r2).  Solo los switches hoja
    deben tener endpoints directos.
    """
    switches = set(intent.get("switches", []))
    endpoints = set(intent.get("hosts", [])) | set(intent.get("servers", []))
    infra = set(intent.get("routers", [])) | switches

    sw_has_ep = {sw: False for sw in switches}
    for link in intent.get("links", []):
        n1, n2 = link[0], link[1]
        if n1 in switches and n2 in endpoints:
            sw_has_ep[n1] = True
        elif n2 in switches and n1 in endpoints:
            sw_has_ep[n2] = True

    linked = {n for lnk in intent.get("links", []) for n in lnk}

    def infra_neighbor_count(sw):
        return sum(1 for lnk in intent.get("links", [])
                   if sw in lnk and lnk[0] in infra and lnk[1] in infra)

    return {sw for sw in switches
            if sw in linked and not sw_has_ep[sw] and infra_neighbor_count(sw) == 1}


def _find_disconnected_switches(intent):
    """Devuelve switches que no tienen ningún camino (BFS) hacia ningún router."""
    routers = set(intent.get("routers", []))
    switches = set(intent.get("switches", []))
    infra = routers | switches

    # Grafo de adyacencia solo entre nodos de infraestructura
    adj = {}
    for link in intent.get("links", []):
        n1, n2 = link[0], link[1]
        if n1 in infra and n2 in infra:
            adj.setdefault(n1, set()).add(n2)
            adj.setdefault(n2, set()).add(n1)

    def reaches_router(start):
        visited, queue = set(), [start]
        while queue:
            node = queue.pop()
            if node in routers:
                return True
            if node in visited:
                continue
            visited.add(node)
            queue.extend(adj.get(node, set()))
        return False

    return {sw for sw in switches if not reaches_router(sw)}


def _infer_missing_links(intent, user_prompt):
    """Infiere enlaces para nodos aislados y switches desconectados del prompt.

    1. Nodos sin ningún enlace (isolated).
    2. Switches con enlaces a endpoints pero sin camino a ningún router (disconnected).
    Busca co-ocurrencias en el texto del prompt (~200 chars de contexto por nodo).
    Solo genera enlaces topológicamente válidos.
    """
    isolated = _find_isolated_nodes(intent)
    disconnected = _find_disconnected_switches(intent)
    targets = isolated | disconnected
    if not targets:
        return intent

    all_nodes = set()
    for key in ("routers", "switches", "hosts", "servers"):
        all_nodes.update(intent.get(key, []))
    for link in intent.get("links", []):
        all_nodes.update(link)

    new_links = list(intent.get("links", []))
    seen = {tuple(sorted(lnk)) for lnk in new_links}

    is_infra = lambda n: n.startswith("r") or (n.startswith("s") and not n.startswith("srv"))

    if disconnected - isolated:
        print(f"  [INFER] Switches sin ruta a router: {sorted(disconnected - isolated)}")

    for node in targets:
        # Contexto amplio alrededor del nodo en el prompt
        contexts = re.findall(
            rf".{{0,200}}\b{re.escape(node)}\b.{{0,200}}", user_prompt, re.IGNORECASE
        )
        context = " ".join(contexts)

        # Nodos con los que puede conectarse según topología
        if is_infra(node):
            candidates = {n for n in all_nodes if is_infra(n) and n != node}
        else:  # host o servidor: solo conecta a switches
            candidates = {n for n in all_nodes if n.startswith("s") and not n.startswith("srv")}

        for other in candidates:
            if re.search(rf"\b{re.escape(other)}\b", context, re.IGNORECASE):
                key = tuple(sorted([node, other]))
                if key not in seen:
                    print(f"  [INFER] [{node}, {other}]")
                    new_links.append([node, other])
                    seen.add(key)

    intent["links"] = new_links
    return intent


def _find_isolated_nodes(intent):
    """Devuelve el conjunto de nodos declarados que no aparecen en ningún enlace."""
    all_nodes = set()
    for key in ("routers", "switches", "hosts", "servers"):
        all_nodes.update(intent.get(key, []))
    linked = {n for link in intent.get("links", []) for n in link}
    return all_nodes - linked


def _fix_invalid_links(intent):
    """Repara enlaces endpoint↔endpoint generados erróneamente por la IA.

    Heurística: si un servidor está enlazado a un host y ese host tiene un switch
    conocido, reconecta el servidor a ese switch. Los enlaces host↔host se descartan.
    """
    if intent.get("tipo") != "custom":
        return intent

    links = intent.get("links", [])
    switches = set(intent.get("switches", []))
    routers = set(intent.get("routers", []))
    infra = switches | routers

    # Mapa nodo → switch/router a partir de los enlaces válidos
    node_to_infra = {}
    for link in links:
        n1, n2 = link[0], link[1]
        if n1 in infra:
            node_to_infra[n2] = n1
        elif n2 in infra:
            node_to_infra[n1] = n2

    fixed = []
    seen = set()

    for link in links:
        n1, n2 = link[0], link[1]
        ep1 = n1.startswith("h") or n1.startswith("srv")
        ep2 = n2.startswith("h") or n2.startswith("srv")

        if ep1 and ep2:
            # Enlace inválido: intentar reparar reconectando el servidor al switch del host
            srv = n1 if n1.startswith("srv") else (n2 if n2.startswith("srv") else None)
            host = n2 if n1.startswith("srv") else (n1 if n2.startswith("srv") else None)
            if srv and host and host in node_to_infra:
                sw = node_to_infra[host]
                key = tuple(sorted([sw, srv]))
                if key not in seen:
                    print(f"[AUTO-FIX] [{n1},{n2}] → [{sw},{srv}]")
                    fixed.append([sw, srv])
                    seen.add(key)
            else:
                print(f"[AUTO-FIX] Enlace inválido [{n1},{n2}] descartado (no reparable).")
        else:
            key = tuple(sorted([n1, n2]))
            if key not in seen:
                fixed.append(link)
                seen.add(key)

    intent["links"] = fixed
    return intent


def build_python_script(intent_json):
    """Fábrica de Scripts Unificada: Patrón LinuxRouter con Asignación de IP Blindada."""
    tipo_red = intent_json.get("tipo", "custom")

    script = [
        "from mininet.topo import Topo",
        "from mininet.net import Mininet",
        "from mininet.node import Controller, Node",
        "from mininet.cli import CLI",
        "from mininet.log import setLogLevel",
        "from mininet.clean import cleanup",
        "",
    ]

    if tipo_red == "estandar":
        topologia = intent_json.get("topologia", "tree").lower()

        if topologia == "tree":
            depth = intent_json.get("depth", 2)
            fanout = intent_json.get("fanout", 2)
            script.insert(0, "from mininet.topolib import TreeTopo")
            topo_init = f"    topo = TreeTopo(depth={depth}, fanout={fanout})"

        elif topologia == "linear":
            k = intent_json.get("k", 4)
            n = intent_json.get("n", 1)
            script.insert(0, "from mininet.topo import LinearTopo")
            topo_init = f"    topo = LinearTopo(k={k}, n={n})"

        elif topologia == "single":
            k = intent_json.get("k", 4)
            script.insert(0, "from mininet.topo import SingleSwitchTopo")
            topo_init = f"    topo = SingleSwitchTopo(k={k})"

        elif topologia == "minimal":
            script.insert(0, "from mininet.topo import MinimalTopo")
            topo_init = "    topo = MinimalTopo()"

        elif topologia == "torus":
            x = intent_json.get("x", 3)
            y = intent_json.get("y", 3)
            script.insert(0, "from mininet.topolib import Torus2D")
            topo_init = f"    topo = Torus2D(x={x}, y={y})"

        else:
            # Fallback a tree si la IA devuelve una topología desconocida
            depth = intent_json.get("depth", 2)
            fanout = intent_json.get("fanout", 2)
            script.insert(0, "from mininet.topolib import TreeTopo")
            topo_init = f"    topo = TreeTopo(depth={depth}, fanout={fanout})"

        script.extend(
            [
                "if __name__ == '__main__':",
                "    setLogLevel('info')",
                "    cleanup()",
                topo_init,
                "    net = Mininet(topo=topo, controller=Controller)",
                "    net.start()",
                "    CLI(net)",
                "    net.stop()",
            ]
        )
    else:
        routers = [x for x in intent_json.get("routers", []) if x.strip()]
        servers = [x for x in intent_json.get("servers", []) if x.strip()]
        switches = [x for x in intent_json.get("switches", []) if x.strip()]
        hosts = [x for x in intent_json.get("hosts", []) if x.strip()]
        links = [l for l in intent_json.get("links", []) if len(l) == 2]

        hosts = [h for h in hosts if h not in servers and h not in routers]

        # AUTO-REPARACIÓN BLINDADA (Lógica anidada para evitar fall-through)
        nodos_en_enlaces = set([n for e in links for n in e])
        for nodo in nodos_en_enlaces:
            if nodo.startswith("srv"):
                if nodo not in servers:
                    servers.append(nodo)
            elif nodo.startswith("s"):
                if nodo not in switches:
                    switches.append(nodo)
            elif nodo.startswith("r"):
                if nodo not in routers:
                    routers.append(nodo)
            elif nodo.startswith("h"):
                if nodo not in hosts:
                    hosts.append(nodo)

        # 1. MOTOR IPAM
        # Cada switch s_i define una subred 192.168.(i+1).0/24.
        # Los routers conectados a un mismo switch reciben IPs únicas:
        # el primero se queda con .254 (gateway de los hosts), el siguiente
        # .253, .252, ... — esto evita colisiones en topologías con dos
        # routers compartiendo subred (p.ej. zona DMZ con r1↔s2↔r2).
        host_ips = {}
        host_gws = {}
        router_ips = {}                # router → [(switch, ip), ...]
        router_ip_per_switch = {}      # (router, switch) → ip — para el BFS de rutas
        switch_idx = {sw: i for i, sw in enumerate(switches)}

        for i, sw in enumerate(switches):
            prefix = f"192.168.{i+1}"
            host_counter = 1

            # PRIMERA PASADA: enumerar routers de esta subred y asignarles
            # IPs distintas. El orden viene de la lista `links` (estable).
            sw_routers = []
            for link in links:
                n1, n2 = link[0], link[1]
                target = n2 if n1 == sw else (n1 if n2 == sw else None)
                if target and target.startswith("r") and target not in sw_routers:
                    sw_routers.append(target)
            for j, r in enumerate(sw_routers):
                ip = f"{prefix}.{254 - j}"
                router_ip_per_switch[(r, sw)] = ip
                router_ips.setdefault(r, []).append((sw, ip))

            # Gateway por defecto de los hosts/servers de esta subred:
            # el PRIMER router (.254). Si no hay router, no hay gateway.
            primary_gw = f"{prefix}.254" if sw_routers else None

            # SEGUNDA PASADA: asignar IPs a hosts y servidores.
            for link in links:
                n1, n2 = link[0], link[1]
                target = n2 if n1 == sw else (n1 if n2 == sw else None)
                if target and (target.startswith("h") or target.startswith("srv")):
                    host_ips[target] = f"{prefix}.{host_counter}"
                    if primary_gw:
                        host_gws[target] = primary_gw
                    host_counter += 1

        # 1.b RUTAS ESTÁTICAS — solo necesarias cuando hay ≥2 routers
        # interconectados (en single-router todas las subredes son vecinas
        # directas y la ruta por defecto basta).
        static_routes = []   # lista de tuplas (router, dest_subnet, via_ip)
        if len(routers) >= 2:
            # Grafo de routing: routers y switches como nodos, links como aristas.
            adj = {n: [] for n in set(routers) | set(switches)}
            for a, b in links:
                if a in adj and b in adj:
                    adj[a].append(b)
                    adj[b].append(a)

            for r in routers:
                # BFS desde r — `prev[n]` = nodo anterior en el camino más corto.
                prev = {r: None}
                queue = [r]
                while queue:
                    cur = queue.pop(0)
                    for nb in adj.get(cur, []):
                        if nb not in prev:
                            prev[nb] = cur
                            queue.append(nb)

                direct_switches = {n for n in adj[r] if n in switch_idx}
                for s in switches:
                    if s == r or s not in prev or s in direct_switches:
                        continue
                    # Reconstruir camino r → ... → s
                    path = []
                    cur = s
                    while cur is not None:
                        path.append(cur)
                        cur = prev[cur]
                    path.reverse()
                    # path[0] = r ; path[1] = switch compartido ; path[2] = next-hop router
                    if len(path) < 3 or path[2] not in routers:
                        continue
                    shared_sw = path[1]
                    next_hop  = path[2]
                    via_ip = router_ip_per_switch.get((next_hop, shared_sw))
                    if not via_ip:
                        continue
                    dest_subnet = f"192.168.{switch_idx[s] + 1}.0/24"
                    static_routes.append((r, dest_subnet, via_ip))

        # 2. CLASE LINUXROUTER
        script.extend(
            [
                "class LinuxRouter(Node):",
                '    """Nodo configurado para actuar como router en Capa 3."""',
                "    def config(self, **params):",
                "        super(LinuxRouter, self).config(**params)",
                "        self.cmd('sysctl net.ipv4.ip_forward=1')",
                "",
                "    def terminate(self):",
                "        self.cmd('sysctl net.ipv4.ip_forward=0')",
                "        super(LinuxRouter, self).terminate()",
                "",
            ]
        )

        # 3. GENERACIÓN DE TOPOLOGÍA FÍSICA
        script.extend(["class SmartTopo(Topo):", "    def build(self):"])
        for s in switches:
            script.append(f"        self.addSwitch('{s}')")
        for r in routers:
            script.append(f"        self.addNode('{r}', cls=LinuxRouter)")

        for srv in servers:
            ip, gw = host_ips.get(srv), host_gws.get(srv)
            script.append(
                f"        self.addHost('{srv}', ip='{ip}/24', defaultRoute='via {gw}')"
                if ip
                else f"        self.addHost('{srv}')"
            )

        for h in hosts:
            ip, gw = host_ips.get(h), host_gws.get(h)
            script.append(
                f"        self.addHost('{h}', ip='{ip}/24', defaultRoute='via {gw}')"
                if ip
                else f"        self.addHost('{h}')"
            )

        for l in links:
            script.append(f"        self.addLink('{l[0]}', '{l[1]}')")

        # 4. INICIALIZACIÓN
        script.extend(
            [
                "",
                "if __name__ == '__main__':",
                "    setLogLevel('info')",
                "    cleanup()",
                "    topo = SmartTopo()",
                "    net = Mininet(topo=topo, controller=Controller)",
                "    net.start()",
            ]
        )

        # 5. ASIGNACIÓN BLINDADA DE IPs A LOS ROUTERS
        if router_ips:
            for r, connections in router_ips.items():
                for sw, ip in connections:
                    script.append(
                        f"    net.get('{r}').setIP('{ip}/24', intf=net.get('{r}').connectionsTo(net.get('{sw}'))[0][0])"
                    )

        # 5.b RUTAS ESTÁTICAS — inter-router (solo si hay ≥2 routers).
        # Cada router aprende a alcanzar subredes "lejanas" vía el router
        # contiguo. Sin esto, las topologías con r1↔s↔r2 quedan partidas a L3.
        if static_routes:
            for r, subnet, via in static_routes:
                script.append(
                    f"    net.get('{r}').cmd('ip route add {subnet} via {via}')"
                )

        if servers:
            # Asignación tipo de servicio por servidor + persistencia local.
            server_types = assign_server_types(intent_json)
            _persist_server_services(server_types, host_ips)

            # Embebemos el script de lanzadores Python como literal repr() y lo
            # escribimos en la VM antes de arrancar cada servicio. Sin ficheros
            # adicionales por SFTP — todo viaja dentro de smart_topo.py.
            script.append("    _LAUNCHERS = " + repr(_SERVICE_LAUNCHERS_PY))
            script.append(
                "    with open('/tmp/service_launchers.py', 'w', encoding='utf-8') as _lf:"
            )
            script.append("        _lf.write(_LAUNCHERS)")

            for srv in servers:
                stype = server_types.get(srv, "http")
                script.append(
                    f"    net.get('{srv}').cmd("
                    f"'python3 /tmp/service_launchers.py {stype} "
                    f"> /tmp/svc_{srv}.log 2>&1 &')"
                )

        script.extend(["    CLI(net)", "    net.stop()"])

    return "\n".join(script)


def _wait_for_sudo_prompt(ssh, timeout=15):
    """Espera a que tmux muestre el prompt de contraseña de sudo o desaparezca."""
    start = time.time()
    while time.time() - start < timeout:
        out = capture_tmux_output(ssh).strip()
        if "[sudo]" in out or "password" in out.lower() or "mininet>" in out:
            return
        time.sleep(0.2)


def deploy_unified_in_vm(python_code, run_pingall=False):
    """Una única función blindada para desplegar cualquier red."""
    print("\nConectando a la VM para despliegue...")
    try:
        ssh = get_ssh_connection()

        # Limpieza síncrona real
        print("Limpiando entorno anterior...")
        stdout = ssh.exec_command(f"echo {VM_PASSWORD} | sudo -S mn -c")[1]
        stdout.channel.recv_exit_status()
        kill_out = ssh.exec_command("tmux kill-session -t sesion_mininet")[1]
        kill_out.channel.recv_exit_status()

        # Escribir script vía SFTP (síncrono, sin race condition)
        sftp = ssh.open_sftp()
        with sftp.file("/tmp/smart_topo.py", "w") as f:
            f.write(python_code)
        sftp.close()

        # Crear sesión tmux y esperar a que exista antes de enviar comandos
        print("Lanzando red a través de Python...")
        new_sess = ssh.exec_command("tmux new-session -d -s sesion_mininet")[1]
        new_sess.channel.recv_exit_status()

        send_tmux_command(ssh, "sudo python3 /tmp/smart_topo.py")
        _wait_for_sudo_prompt(ssh, timeout=15)
        send_tmux_command(ssh, VM_PASSWORD)

        print("Esperando inicialización de la red...")
        if not wait_for_mininet_prompt(ssh, timeout=120):
            tail = capture_tmux_output(ssh).strip().split("\n")
            print("[DEBUG] Últimas líneas del panel tmux:")
            print("\n".join(tail[-10:]))

        if run_pingall:
            print("Activando Pings de prueba (puede tardar minutos en redes masivas)...")
            send_tmux_command(ssh, "pingall")
            wait_for_mininet_prompt(ssh, timeout=300)

        run_visualizer()

        print("\n[ÉXITO] Red desplegada correctamente.")
        ssh.close()
    except Exception as e:
        print(f"Error en despliegue: {e}")


if __name__ == "__main__":
    print("=== AGENTE IA DE DESPLIEGUE (Arquitectura Unificada) ===")
    req = input("Describe la red que deseas crear:\n> ")

    intent = generate_network_intent(req)

    if intent:
        print("\n--- INTENCIÓN EXTRAÍDA POR IA ---")
        print(json.dumps(intent, indent=2))

        # Un solo camino para construir
        code = build_python_script(intent)
        print("\n--- CÓDIGO PYTHON AUTO-GENERADO ---")
        print(code)

        # Un solo camino para desplegar
        if input("\n¿Desplegar este script en la VM? (s/n): ").lower() == "s":
            deploy_unified_in_vm(code)
    else:
        print("[ERROR] Falló la extracción.")
