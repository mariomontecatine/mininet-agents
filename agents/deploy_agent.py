import sys
import os
import time
import json
import ollama

# Parche para rutas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)
from agents.topology import run_visualizer

VM_PASSWORD = "mininet"
MODEL_NAME = "qwen2.5:7b"  # O el modelo que prefieras


def generate_network_intent(user_prompt):
    """Convierte lenguaje natural en un JSON estructurado (Arquitectura Unificada)."""
    print("\n[IA] Evaluando intención del usuario y generando diseño...")

    system_prompt = (
        "Eres un arquitecto de red para Mininet. Devuelve un JSON válido.\n\n"
        "REGLA DE DECISIÓN:\n"
        "1. MODO ESTÁNDAR: Si piden una red clásica de Mininet (árbol/tree). "
        'Usa el formato exacto: {"tipo": "estandar", "topologia": "tree", "depth": 3, "fanout": 4}\n'
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
                            "description": "'tree' u otra estándar",
                        },
                        "depth": {"type": "integer"},
                        "fanout": {"type": "integer"},
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
    """Fábrica de Scripts Unificada: Crea Python nativo para cualquier tipo de red."""
    tipo_red = intent_json.get("tipo", "custom")

    # Cabecera común obligatoria
    script = [
        "from mininet.net import Mininet",
        "from mininet.node import Controller",
        "from mininet.cli import CLI",
        "from mininet.log import setLogLevel",
        "from mininet.clean import cleanup",
        "",
    ]

    if tipo_red == "estandar":
        depth = intent_json.get("depth", 2)
        fanout = intent_json.get("fanout", 2)
        script.insert(0, "from mininet.topolib import TreeTopo")
        script.extend(
            [
                "if __name__ == '__main__':",
                "    setLogLevel('info')",
                "    cleanup()",
                f"    topo = TreeTopo(depth={depth}, fanout={fanout})",
                "    net = Mininet(topo=topo, controller=Controller)",
                "    net.start()",
                "    print('\\n*** Red estándar nativa iniciada ***')",
                "    print('\\n*** Entrando en CLI ***')",
                "    CLI(net)",
                "    net.stop()",
            ]
        )
    else:
        # Modo Custom (El código de tu DMZ empresarial que ya funcionaba)
        script.insert(0, "from mininet.topo import Topo")
        script.extend(["class SmartTopo(Topo):", "    def build(self):"])

        routers = [x for x in intent_json.get("routers", []) if x.strip()]
        servers = [x for x in intent_json.get("servers", []) if x.strip()]
        switches = [x for x in intent_json.get("switches", []) if x.strip()]
        hosts = [x for x in intent_json.get("hosts", []) if x.strip()]
        links = [l for l in intent_json.get("links", []) if len(l) == 2]

        # 1. PARCHE ANTI-DUPLICADOS (Si la IA mete los servidores/routers en hosts, los quitamos)
        hosts = [h for h in hosts if h not in servers and h not in routers]

        # 2. AUTO-REPARACIÓN CORREGIDA (Miramos el prefijo PRIMERO, luego si falta)
        nodos_en_enlaces = set([n for e in links for n in e])
        for nodo in nodos_en_enlaces:
            if nodo.startswith("srv"):
                if nodo not in servers:
                    servers.append(nodo)
            elif nodo.startswith("s"):
                if nodo not in switches:
                    switches.append(nodo)
            elif nodo.startswith("h"):
                if nodo not in hosts:
                    hosts.append(nodo)
            elif nodo.startswith("r"):
                if nodo not in routers:
                    routers.append(nodo)

        for s in switches:
            script.append(f"        self.addSwitch('{s}')")
        for r in routers:
            script.append(
                f"        self.addHost('{r}', sysctls={{'net.ipv4.ip_forward': 1}})"
            )
        for srv in servers:
            script.append(f"        self.addHost('{srv}')")
        for h in hosts:
            script.append(f"        self.addHost('{h}')")
        for l in links:
            script.append(f"        self.addLink('{l[0]}', '{l[1]}')")

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

        if servers:
            script.append("    print('\\n*** Iniciando Servidores Web ***')")
            for srv in servers:
                script.append(
                    f"    net.get('{srv}').cmd('python3 -m http.server 80 > /dev/null 2>&1 &')"
                )

        script.extend(
            [
                "    print('\\n*** Entrando en CLI ***')",
                "    CLI(net)",
                "    net.stop()",
            ]
        )

    return "\n".join(script)


def deploy_unified_in_vm(python_code):
    """Una única función blindada para desplegar cualquier red."""
    print("\nConectando a la VM para despliegue...")
    try:
        ssh = get_ssh_connection()

        # Limpieza síncrona real
        print("Limpiando entorno anterior...")
        stdout = ssh.exec_command(f"echo {VM_PASSWORD} | sudo -S mn -c")[1]
        stdout.channel.recv_exit_status()
        ssh.exec_command("tmux kill-session -t sesion_mininet")
        time.sleep(1)

        # Inyectar código
        ssh.exec_command(f"cat << 'EOF' > /tmp/smart_topo.py\n{python_code}\nEOF")

        # Ejecutar Python (No volvemos a usar 'mn' directo nunca más)
        print("Lanzando red a través de Python...")
        ssh.exec_command("tmux new-session -d -s sesion_mininet")
        send_tmux_command(ssh, "sudo python3 /tmp/smart_topo.py")
        time.sleep(1)
        send_tmux_command(ssh, VM_PASSWORD)

        print("Esperando inicialización de la red...")
        wait_for_mininet_prompt(ssh, timeout=90)

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
