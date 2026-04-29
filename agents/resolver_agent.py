import sys
import os
import json
import ollama

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import get_ssh_connection, send_tmux_command

MODEL_NAME = "qwen2.5:3b"


def analyze_and_decide(report_text):
    print(
        "\n[IA] Evaluando el informe para aplicar políticas de Calidad de Servicio (QoS)..."
    )

    system_prompt = (
        "Eres un Orquestador Automático de Redes (SDN/QoS).\n"
        "Tu trabajo es leer el informe del Monitor y aplicar control de tráfico (Rate Limiting) en el puerto FÍSICO más saturado.\n\n"
        "REGLAS CRÍTICAS (¡OBLIGATORIAS!):\n"
        "1. IGNORA EL PUERTO 'LOCAL'. Nunca apliques QoS al puerto LOCAL. Es una interfaz interna.\n"
        "2. Identifica el puerto físico (ej. s3-eth2, s4-eth4) con peor congestión o más [TRÁFICO EXTREMO].\n"
        "3. Si hay congestión, el 'rate_limit' DEBE ser exactamente '20mbit'. NUNCA uses 'null' o 'None' si aplicas QoS.\n"
        "4. DEBES devolver ÚNICAMENTE un JSON válido, sin texto extra.\n\n"
        "FORMATO DE SALIDA (ESTRICTO JSON):\n"
        "{\n"
        '  "action": "apply_qos" o "none",\n'
        '  "target_port": "nombre del puerto FÍSICO o null",\n'
        '  "rate_limit": "20mbit",\n'
        '  "reason": "Explicación técnica de la decisión"\n'
        "}"
    )

    response = ollama.chat(
        model=MODEL_NAME,
        format="json",  # Obligamos a la IA a no divagar
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"INFORME DEL MONITOR:\n{report_text}"},
        ],
    )

    try:
        decision = json.loads(response["message"]["content"])
        return decision
    except json.JSONDecodeError:
        print("[ERROR CRÍTICO] La IA no devolvió un JSON válido.")
        return None


def execute_resolution(decision):
    if not decision:
        return

    accion = decision.get("action", "none")
    puerto = decision.get("target_port")
    limite = decision.get("rate_limit", "10mbit")
    motivo = decision.get("reason", "Mantenimiento preventivo")

    print(f"\n--- DECISIÓN DEL NOC AUTOMATIZADO ---")
    print(f" > Acción:  {accion.upper()}")
    print(f" > Puerto:  {puerto}")
    print(f" > Límite:  {limite}")
    print(f" > Motivo:  {motivo}")
    print("-------------------------------------")

    if accion == "apply_qos" and puerto and puerto != "null":
        print(f"\n[EJECUCIÓN] Inyectando reglas de Traffic Control (tc) en {puerto}...")
        try:
            ssh = get_ssh_connection()

            # Comando de Linux/Mininet para aplicar QoS (Rate Limiting)
            # Primero borramos cualquier regla previa por si acaso, y luego aplicamos la nueva
            cmd_clear = f"sh tc qdisc del dev {puerto} root 2>/dev/null"
            cmd_qos = f"sh tc qdisc add dev {puerto} root tbf rate {limite} burst 32kbit latency 400ms"

            send_tmux_command(ssh, cmd_clear)
            send_tmux_command(ssh, cmd_qos)

            print(f"[COMANDO] {cmd_qos}")
            print(
                f"[OK] Límite de ancho de banda ({limite}) aplicado con éxito en {puerto}. Tráfico estabilizado."
            )
            ssh.close()
        except Exception as e:
            print(f"Error al aplicar la regla QoS: {e}")
    else:
        print("\n[EJECUCIÓN] No se requiere modificación en la infraestructura.")


def run_resolver_agent():
    print("=== AGENTE RESOLUTOR (Gestión de QoS) ===")

    archivo_informe = "ultimo_informe.txt"

    if not os.path.exists(archivo_informe):
        print(
            f"[ERROR] No se encontró '{archivo_informe}'. Debes ejecutar el Agente Monitor (o Tráfico) primero."
        )
        return

    with open(archivo_informe, "r", encoding="utf-8") as f:
        reporte = f.read()

    decision_ia = analyze_and_decide(reporte)

    if decision_ia:
        execute_resolution(decision_ia)


if __name__ == "__main__":
    run_resolver_agent()
