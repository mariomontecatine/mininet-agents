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
MODEL_NAME = "qwen2.5:3b"


def clear_agent_memory():
    """Borra los archivos de estado de los agentes."""
    print("Limpiando memoria de los agentes (JSON/TXT)...")
    files_to_delete = ["network_history.json", "ultima_rafaga.txt"]
    for filename in files_to_delete:
        if os.path.exists(filename):
            os.remove(filename)
            print(f" -> Archivo borrado: {filename}")


def generate_network_intent(user_prompt):
    """Convierte lenguaje natural en un JSON estructurado de la red."""
    print("\n[IA] Traduciendo intención del usuario a estructura JSON...")

    system_prompt = (
        "Eres un diseñador de topologías de red. Tu única tarea es extraer "
        "los nodos y enlaces que el usuario pide y devolverlos usando la herramienta.\n"
        "Reglas de nombres:\n"
        "- Routers: r1, r2...\n"
        "- Servidores: srv1, srv2...\n"
        "- Switches: s1, s2...\n"
        "- PCs: h1, h2...\n\n"
        "¡REGLA CRÍTICA PARA LOS ENLACES (links)!\n"
        "Debes deducir las conexiones. Si el usuario dice 'conecta 1 router a 1 switch y 2 PCs al switch':\n"
        'Los enlaces (links) DEBEN SER: [["r1", "s1"], ["s1", "h1"], ["s1", "h2"]]'
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
                        "routers": {"type": "array", "items": {"type": "string"}},
                        "servers": {"type": "array", "items": {"type": "string"}},
                        "switches": {"type": "array", "items": {"type": "string"}},
                        "hosts": {"type": "array", "items": {"type": "string"}},
                        "links": {
                            "type": "array",
                            "items": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": 'Ejemplo: ["r1", "s1"]',
                            },
                        },
                    },
                    "required": ["routers", "servers", "switches", "hosts", "links"],
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

        print("[ERROR] La IA no usó la herramienta correctamente.")
        return None

    except Exception as e:
        print(f"[ERROR CRÍTICO] Ollama falló: {e}")
        return None


def build_python_script(intent_json):
    """Genera el código de Mininet usando una plantilla segura y el JSON de la IA."""

    routers = intent_json.get("routers", [])
    servers = intent_json.get("servers", [])
    switches = intent_json.get("switches", [])
    hosts = intent_json.get("hosts", [])
    links = intent_json.get("links", [])

    # === PLANTILLA SEGURA DE MININET (CON CONTROLADOR) ===
    script = [
        "from mininet.topo import Topo",
        "from mininet.net import Mininet",
        "from mininet.node import Controller",  # IMPORTANTE: Importamos el controlador local
        "from mininet.cli import CLI",
        "from mininet.log import setLogLevel",
        "",
        "class SmartTopo(Topo):",
        "    def build(self):",
    ]

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

    for link in links:
        if len(link) == 2:
            script.append(f"        self.addLink('{link[0]}', '{link[1]}')")

    # === BLOQUE MAIN (CON CONTROLADOR Y LIMPIEZA INYECTADOS) ===
    script.extend(
        [
            "",
            "if __name__ == '__main__':",
            "    setLogLevel('info')",
            "    # Limpieza agresiva de procesos zombies de Mininet",
            "    from mininet.clean import cleanup",  # <-- AQUÍ ESTÁ EL CAMBIO
            "    cleanup()",  # <-- Y AQUÍ
            "    ",
            "    topo = SmartTopo()",
            "    # Forzamos el controlador local para evitar crasheos",
            "    net = Mininet(topo=topo, controller=Controller)",
            "    net.start()",
            "    ",
        ]
    )

    if servers:
        script.append("    print('\\n*** Iniciando Servidores Web ***')")
        for srv in servers:
            # Redirigimos la salida a /dev/null para evitar que bloquee el hilo de Python
            script.append(
                f"    net.get('{srv}').cmd('python3 -m http.server 80 > /dev/null 2>&1 &')"
            )
            script.append(f"    print('-> Servidor HTTP lanzado en {srv}')")

    script.extend(
        ["    print('\\n*** Entrando en CLI ***')", "    CLI(net)", "    net.stop()"]
    )

    return "\n".join(script)


def deploy_advanced_in_vm(python_code):
    """Despliega el código generado en la Máquina Virtual."""
    print("\nConectando a la VM para despliegue avanzado...")
    try:
        ssh = get_ssh_connection()

        # Limpiar entorno
        ssh.exec_command(f"echo {VM_PASSWORD} | sudo -S mn -c")
        ssh.exec_command("tmux kill-session -t sesion_mininet")
        time.sleep(1)

        # Transferir código seguro a la VM
        cmd_write = f"cat << 'EOF' > /tmp/smart_topo.py\n{python_code}\nEOF"
        ssh.exec_command(cmd_write)

        # Iniciar tmux y ejecutar
        print("Lanzando red inteligente desde script Python...")
        ssh.exec_command("tmux new-session -d -s sesion_mininet")
        send_tmux_command(ssh, f"sudo python3 /tmp/smart_topo.py")
        time.sleep(1)
        send_tmux_command(ssh, VM_PASSWORD)

        print("Esperando inicialización de la red (8 segundos)...")
        time.sleep(8)

        # Verificación
        print("Activando Pings de prueba...")
        send_tmux_command(ssh, "pingall")
        wait_for_mininet_prompt(ssh, timeout=30)

        # Visualización
        run_visualizer()

        print("\n[ÉXITO] Red inteligente desplegada y servidores activos.")
        ssh.close()

    except Exception as e:
        print(f"Error en despliegue: {e}")


if __name__ == "__main__":
    print("=== AGENTE IA DE DESPLIEGUE AVANZADO (Plantilla JSON) ===")
    req = input(
        "Describe tu red avanzada: Crea una red con 1 router central. Conecta un switch al router. A ese switch, conecta 2 PCs de usuario y 1 servidor web.\n> "
    )

    # 1. IA extrae JSON
    intent = generate_network_intent(req)

    if intent:
        print("\n--- INTENCIÓN EXTRAÍDA POR IA ---")
        print(json.dumps(intent, indent=2))

        # 2. Python construye script (solo si hay enlaces)
        if not intent.get("links"):
            print("\n[ERROR DE IA] La IA no ha generado enlaces. Red inválida.")
        else:
            code = build_python_script(intent)
            print("\n--- CÓDIGO PYTHON AUTO-GENERADO ---")
            print(code)

            # 3. Despliegue
            if input("\n¿Desplegar este script en la VM? (s/n): ").lower() == "s":
                deploy_advanced_in_vm(code)
    else:
        print("[ERROR] Falló la extracción.")
