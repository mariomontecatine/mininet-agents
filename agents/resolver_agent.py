import sys
import os
import ollama
import time

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import get_ssh_connection, send_tmux_command

MODEL_NAME = "qwen2.5:3b"


def analyze_and_decide(report_text):
    print("\n[IA] Evaluando el informe con Tool Calling para aplicar QoS...")

    system_prompt = (
        "Eres un Orquestador Automático de Redes (SDN/QoS).\n"
        "Tu trabajo es leer el informe del Monitor y decidir si es necesario aplicar "
        "control de tráfico (Rate Limiting) en el puerto FÍSICO más saturado.\n"
        "REGLAS CRÍTICAS:\n"
        "1. IGNORA EL PUERTO 'LOCAL'. Nunca apliques QoS al puerto LOCAL.\n"
        "2. Identifica el puerto físico (ej. s3-eth2, s4-eth4) con peor congestión (mayor rx_delta).\n"
        "3. Si hay congestión, DEBES usar la herramienta 'apply_qos'. Si la red está sana, no hagas nada."
    )

    # AQUÍ ESTÁ LA MAGIA: Definimos la "Herramienta" (Tool)
    tools = [
        {
            "type": "function",
            "function": {
                "name": "apply_qos",
                "description": "Aplica límite de ancho de banda (QoS) a un puerto físico congestionado.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_port": {
                            "type": "string",
                            "description": "El identificador exacto del puerto FÍSICO a limitar (ej. s5-eth3). NUNCA usar LOCAL.",
                        },
                        "rate_limit": {
                            "type": "string",
                            "description": 'El límite de ancho de banda a aplicar. DEBE ser siempre "20mbit".',
                            "enum": ["20mbit"],
                        },
                        "reason": {
                            "type": "string",
                            "description": "Breve explicación técnica de por qué se eligió este puerto exacto.",
                        },
                    },
                    "required": ["target_port", "rate_limit", "reason"],
                },
            },
        }
    ]

    try:
        # Llamada a la IA pasándole nuestras herramientas
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"INFORME DEL MONITOR:\n{report_text}"},
            ],
            tools=tools,  # <--- Activamos el Tool Calling
        )

        # Comprobamos si la IA ha decidido usar la herramienta
        if response.get("message", {}).get("tool_calls"):
            # Cogemos la primera herramienta que ha decidido usar
            tool_call = response["message"]["tool_calls"][0]

            if tool_call["function"]["name"] == "apply_qos":
                argumentos = tool_call["function"]["arguments"]

                # Construimos el diccionario que espera nuestra función de ejecución
                decision = {
                    "action": "apply_qos",
                    "target_port": argumentos.get("target_port"),
                    "rate_limit": argumentos.get("rate_limit", "20mbit"),
                    "reason": argumentos.get("reason"),
                }
                return decision

        # Si no usó la herramienta, es que decidió que no hace falta QoS
        print("[IA] La red parece estable. No se invocaron herramientas de mitigación.")
        return {"action": "none"}

    except Exception as e:
        print(f"[ERROR CRÍTICO] Fallo en la comunicación con Ollama: {e}")
        return None


def execute_resolution(decision):
    if not decision:
        return

    accion = decision.get("action", "none")
    puerto = decision.get("target_port")
    limite = decision.get("rate_limit", "20mbit")
    motivo = decision.get("reason", "Mantenimiento preventivo")

    print(f"\n--- DECISIÓN DEL NOC AUTOMATIZADO ---")
    print(f" > Acción:  {accion.upper()}")
    print(f" > Puerto:  {puerto}")
    print(f" > Límite:  {limite}")
    print(f" > Motivo:  {motivo}")
    print("-------------------------------------")

    if accion == "apply_qos" and puerto and puerto.lower() != "null":
        print(f"\n[EJECUCIÓN] Inyectando reglas Open vSwitch (OVS) en {puerto}...")
        try:
            ssh = get_ssh_connection()

            # En Open vSwitch, 20mbit se escriben como 20000 kbps.
            cmd_qos_rate = (
                f"sh ovs-vsctl set interface {puerto} ingress_policing_rate=20000"
            )
            cmd_qos_burst = (
                f"sh ovs-vsctl set interface {puerto} ingress_policing_burst=2000"
            )

            send_tmux_command(ssh, cmd_qos_rate)
            time.sleep(0.5)
            send_tmux_command(ssh, cmd_qos_burst)

            print(f"[COMANDO] {cmd_qos_rate}")
            print(
                f"[OK] Límite de hardware OVS (20mbit) aplicado con éxito en {puerto}."
            )
            ssh.close()
        except Exception as e:
            print(f"Error al aplicar la regla OVS: {e}")
    else:
        print("\n[EJECUCIÓN] No se requiere modificación en la infraestructura.")


def run_resolver_agent():
    print("=== AGENTE RESOLUTOR (Gestión de QoS) ===")

    archivo_informe = "ultimo_informe.txt"

    if not os.path.exists(archivo_informe):
        print(
            f"[ERROR] No se encontró '{archivo_informe}'. Ejecuta el Agente Monitor primero."
        )
        return

    with open(archivo_informe, "r", encoding="utf-8") as f:
        reporte = f.read()

    decision_ia = analyze_and_decide(reporte)

    if decision_ia:
        execute_resolution(decision_ia)


if __name__ == "__main__":
    run_resolver_agent()
