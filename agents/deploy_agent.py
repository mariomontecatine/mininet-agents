import sys
import os
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
        "2. MODO CUSTOM: Si piden servidores, routers, o diseños a medida. "
        'Rellena las listas: {"tipo": "custom", "routers": ["r1"], "switches": ["s1"], "servers": ["srv1"], "hosts": ["h1"], "links": [["r1", "s1"], ["s1", "srv1"]]}'
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
                            "items": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                    "required": ["tipo"],
                },
            },
        }
    ]

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            tools=tools,
        )

        if response.get("message", {}).get("tool_calls"):
            tool_call = response["message"]["tool_calls"][0]
            args = tool_call["function"]["arguments"]
            return args
        return None
    except Exception as e:
        print(f"[ERROR CRÍTICO] Ollama falló: {e}")
        return None


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
        host_ips = {}
        host_gws = {}
        router_ips = {}

        for i, sw in enumerate(switches):
            prefix = f"192.168.{i+1}"
            host_counter = 1
            router_gw = f"{prefix}.254"
            for link in links:
                n1, n2 = link[0], link[1]
                target = n2 if n1 == sw else (n1 if n2 == sw else None)
                if target:
                    if target.startswith("h") or target.startswith("srv"):
                        host_ips[target] = f"{prefix}.{host_counter}"
                        host_gws[target] = router_gw
                        host_counter += 1
                    elif target.startswith("r"):
                        if target not in router_ips:
                            router_ips[target] = []
                        router_ips[target].append((sw, router_gw))

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

        if servers:
            for srv in servers:
                script.append(
                    f"    net.get('{srv}').cmd('python3 -m http.server 80 > /dev/null 2>&1 &')"
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
