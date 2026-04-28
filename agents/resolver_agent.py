import sys
import os
import json
import ollama

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import get_ssh_connection, send_tmux_command

MODEL_NAME = "qwen2.5:3b"


def analyze_and_decide(report_text):
    print("\n[IA] Leyendo el informe de red y tomando decisiones críticas...")

    system_prompt = (
        "Eres un Agente Resolutor de Redes (NOC Automático).\n"
        "Tu trabajo es leer el informe del Monitor y tomar UNA decisión táctica para salvar la red.\n\n"
        "REGLAS CRÍTICAS:\n"
        "1. Si el informe indica [ALERTA ROJA] o [TRÁFICO EXTREMO] en algún puerto (ej. s2-eth4), debes APAGAR ese puerto para cortar la congestión.\n"
        "2. Si el informe dice que la red está sana, no hagas nada.\n"
        "3. DEBES devolver ÚNICAMENTE un JSON válido, sin texto extra, sin markdown.\n\n"
        "FORMATO DE SALIDA (ESTRICTO JSON):\n"
        "{\n"
        '  "action": "disable_port" o "none",\n'
        '  "target_port": "nombre del puerto (ej. s2-eth4) o null",\n'
        '  "reason": "Explicación breve de por qué tomas esta decisión"\n'
        "}"
    )

    response = ollama.chat(
        model=MODEL_NAME,
        format="json",  # Forzamos la salida en JSON seguro
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"INFORME DEL MONITOR:\n{report_text}"},
        ],
    )

    try:
        decision = json.loads(response["message"]["content"])
        return decision
    except json.JSONDecodeError:
        print("[ERROR] La IA no devolvió un JSON válido.")
        return None


def execute_resolution(decision):
    if not decision:
        return

    accion = decision.get("action", "none")
    puerto = decision.get("target_port")
    motivo = decision.get("reason", "Sin motivo especificado")

    print(f"\n[RESOLUTOR] Decisión tomada: {accion.upper()}")
    print(f"[RESOLUTOR] Motivo: {motivo}")

    if accion == "disable_port" and puerto and puerto != "null":
        print(f"\n[EJECUCIÓN] ¡Apagando la interfaz {puerto} para aislar el problema!")
        try:
            ssh = get_ssh_connection()
            # En Mininet, podemos apagar una interfaz usando sh ifconfig <interfaz> down
            comando_mitigacion = f"sh ifconfig {puerto} down"
            send_tmux_command(ssh, comando_mitigacion)
            print(f"[EJECUCIÓN] Comando enviado: {comando_mitigacion}")
            ssh.close()
        except Exception as e:
            print(f"Error al intentar mitigar el problema: {e}")
    else:
        print("\n[EJECUCIÓN] No se requiere acción en la infraestructura.")


def run_resolver_agent():
    print("=== AGENTE RESOLUTOR (Mitigación Automática) ===")

    archivo_informe = "ultimo_informe.txt"

    if not os.path.exists(archivo_informe):
        print(
            f"No se encontró el archivo '{archivo_informe}'. Ejecuta el Agente Monitor primero."
        )
        return

    with open(archivo_informe, "r", encoding="utf-8") as f:
        reporte = f.read()

    decision_ia = analyze_and_decide(reporte)

    if decision_ia:
        execute_resolution(decision_ia)


if __name__ == "__main__":
    run_resolver_agent()
