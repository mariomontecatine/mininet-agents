import sys
import os
import re
import ollama
import time

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import get_ssh_connection, send_tmux_command

MODEL_NAME = "qwen2.5:7b"
TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)

# Escala de severidad: cada nivel sólo puede subir, nunca bajar
ESCALATION = {"POLICING": "SHAPING", "SHAPING": "BLOCK", "BLOCK": "BLOCK"}


# =============================================================
# === PRIMITIVAS DE EJECUCIÓN (operan sobre una SSH abierta) ==
# =============================================================

def apply_policing(ssh, port, rate_mbps=20):
    """
    Limita ingress con tc ingress police.
    Los paquetes excedentes se dropean ANTES de que entren al datapath OVS,
    por lo que no se contabilizan en rx_bytes de dpctl dump-ports.
    """
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} ingress 2>/dev/null; true")
    time.sleep(0.2)
    send_tmux_command(ssh, f"sh tc qdisc add dev {port} handle ffff: ingress")
    time.sleep(0.1)
    send_tmux_command(
        ssh,
        f"sh tc filter add dev {port} parent ffff: protocol all u32 match u32 0 0 "
        f"police rate {rate_mbps}mbit burst 64k drop flowid :1",
    )
    print(f"  [OK] POLICING → {port}: {rate_mbps} Mbps ingress (tc police, pre-OVS)")


def apply_shaping(ssh, port, rate_mbps=20):
    """Limita egress con tc TBF (Token Bucket Filter). burst=64kb para tolerar ráfagas legítimas."""
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
    time.sleep(0.2)
    send_tmux_command(
        ssh,
        f"sh tc qdisc add dev {port} root tbf rate {rate_mbps}mbit burst 64kb latency 200ms",
    )
    print(f"  [OK] SHAPING → {port}: {rate_mbps} Mbps egress (tc tbf)")


def block_port(ssh, port):
    """
    Bloqueo de seguridad en dos capas:
    1. OpenFlow DROP de alta prioridad (SDN nativo, el tráfico no se reenvía).
    2. tc ingress total block (rate=1kbit) para que los bytes no lleguen al contador OVS.
    El bridge se deriva del nombre del puerto: s1-eth2 → s1.
    """
    bridge = port.split("-")[0]

    send_tmux_command(
        ssh,
        f"sh ovs-ofctl add-flow {bridge} priority=200,in_port={port},actions=drop",
    )
    time.sleep(0.2)

    send_tmux_command(ssh, f"sh tc qdisc del dev {port} ingress 2>/dev/null; true")
    time.sleep(0.1)
    send_tmux_command(ssh, f"sh tc qdisc add dev {port} handle ffff: ingress")
    time.sleep(0.1)
    send_tmux_command(
        ssh,
        f"sh tc filter add dev {port} parent ffff: protocol all u32 match u32 0 0 "
        f"police rate 1kbit burst 1k drop flowid :1",
    )
    print(f"  [OK] BLOCK → {port}: OpenFlow DROP (prio=200) + tc total block en {bridge}")


# =============================================================
# === ORQUESTADOR MULTI-ACCIÓN ================================
# =============================================================

def resolve_multiple(actions_list):
    """
    Recibe la lista de acciones devuelta por el LLM y las ejecuta todas
    en una sola conexión SSH.
    """
    if not actions_list:
        print("\n[EJECUCIÓN] Lista de acciones vacía. Sin intervenciones.")
        return

    real_actions = [a for a in actions_list if a.get("action") != "NO_ACTION"]
    if not real_actions:
        print("\n[EJECUCIÓN] Red estable. Sin intervenciones requeridas.")
        return

    print(f"\n[EJECUCIÓN] Aplicando {len(real_actions)} acción(es) de red...")
    try:
        ssh = get_ssh_connection()

        for item in real_actions:
            action = item.get("action", "")
            port = item.get("target_port", "")
            rate = int(item.get("rate_mbps", 20))
            reason = item.get("reason", "Automático")

            print(f"\n  --- {action} | puerto: {port} | motivo: {reason} ---")

            if not port or port.upper() == "LOCAL":
                print("  [SKIP] Puerto inválido o LOCAL, ignorado.")
                continue

            if action == "POLICING":
                apply_policing(ssh, port, rate)
            elif action == "SHAPING":
                apply_shaping(ssh, port, rate)
            elif action == "BLOCK":
                block_port(ssh, port)
            else:
                print(f"  [WARN] Acción desconocida '{action}', ignorada.")

        ssh.close()

    except Exception as e:
        print(f"[ERROR] Fallo en resolve_multiple: {e}")


# =============================================================
# === AGENTE DE DECISIÓN (LLM con Tool Calling multi-acción) ==
# =============================================================

def analyze_and_decide(report_text, raw_telemetry=None, reglas_activas=None):
    """
    Analiza el informe y devuelve una lista de acciones.
    - raw_telemetry: texto crudo de collect_telemetry() para extraer puertos alertados con regex.
    - reglas_activas: dict {puerto → {"action": str, "ciclo": int}} para inyectar contexto de estado.
    """
    print("\n[IA] Evaluando el informe con Tool Calling (multi-acción)...")

    # --- 1. Extraer puertos alertados de la telemetría cruda (no del informe LLM) ---
    alerted_ports = []
    if raw_telemetry:
        found = re.findall(
            r"(?:\[ALERTA ROJA\]|\[TRÁFICO INTENSO\]).*?Port\s+(s\d+-eth\d+):",
            raw_telemetry,
        )
        alerted_ports = list(dict.fromkeys(found))  # deduplicar, preservar orden

    # --- 2. Bloque de enumeración 1:1 para el LLM ---
    if alerted_ports:
        enum_lines = "\n".join(f"  {i+1}. {p}" for i, p in enumerate(alerted_ports))
        enum_ctx = (
            f"PUERTOS EN ALERTA (MAPEO 1:1 OBLIGATORIO):\n{enum_lines}\n"
            f"TOTAL: {len(alerted_ports)} puertos. "
            f"El array DEBE contener EXACTAMENTE {len(alerted_ports)} entradas, una por puerto."
        )
    else:
        enum_ctx = "PUERTOS EN ALERTA: ninguno detectado en este ciclo."

    # --- 3. Bloque de estado/escalado ---
    if reglas_activas:
        estado_lineas = [
            f"  - {p}: {info['action']} (ciclo {info['ciclo']}) "
            f"→ escalar a {ESCALATION.get(info['action'], 'BLOCK')} si persiste"
            for p, info in reglas_activas.items()
        ]
        estado_ctx = "MITIGACIONES YA ACTIVAS:\n" + "\n".join(estado_lineas)
    else:
        estado_ctx = "MITIGACIONES YA ACTIVAS: ninguna (primer ciclo)."

    system_prompt = (
        "Eres un Orquestador Automático de Redes (SDN/QoS). "
        "Analiza el informe y usa 'apply_network_actions' para resolver TODAS las alertas en un solo ciclo.\n"
        "REGLAS DE DECISIÓN:\n"
        "1. REGLA CRÍTICA DE CARDINALIDAD: el array de acciones debe tener EXACTAMENTE tantas entradas "
        "como el TOTAL indicado en 'PUERTOS EN ALERTA'. Ni una más, ni una menos.\n"
        "2. REGLA DE ESCALADO: si un puerto ya tiene una mitigación activa y sigue en alerta, "
        "DEBES escalar según la cadena POLICING → SHAPING → BLOCK. "
        "Nunca repitas la misma acción que ya falló en un ciclo anterior.\n"
        "3. Usa POLICING para [TRÁFICO INTENSO] sin mitigación previa (limita ingress a 20 Mbps).\n"
        "4. Usa SHAPING para congestión de egress o como escalado tras POLICING fallido.\n"
        "5. Usa BLOCK para drop_delta muy alto (DDoS) o como escalado tras SHAPING fallido.\n"
        "6. Si no hay puertos en alerta, devuelve una única acción NO_ACTION.\n"
        "7. NUNCA actúes sobre puertos 'LOCAL'. Formato obligatorio: sX-ethY (ej: s1-eth2).\n"
        "Siempre invoca la herramienta. Nunca respondas con texto plano."
    )

    tools = [
        {
            "type": "function",
            "function": {
                "name": "apply_network_actions",
                "description": (
                    "Aplica una lista de acciones de red (QoS/seguridad) sobre todos los puertos "
                    "afectados simultáneamente en un solo ciclo."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "actions": {
                            "type": "array",
                            "description": (
                                "Lista de acciones. Una entrada por cada puerto en alerta. "
                                "Longitud debe coincidir exactamente con el TOTAL indicado."
                            ),
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "action": {
                                        "type": "string",
                                        "enum": ["NO_ACTION", "POLICING", "SHAPING", "BLOCK"],
                                        "description": (
                                            "NO_ACTION: red estable. "
                                            "POLICING: tc ingress police (limita y dropea pre-OVS). "
                                            "SHAPING: tc tbf egress (moldea salida). "
                                            "BLOCK: OpenFlow DROP + tc total block."
                                        ),
                                    },
                                    "target_port": {
                                        "type": "string",
                                        "description": "Puerto físico sX-ethY (ej: s1-eth2). Obligatorio para POLICING, SHAPING y BLOCK.",
                                    },
                                    "rate_mbps": {
                                        "type": "integer",
                                        "description": "Límite en Mbps para POLICING/SHAPING. Por defecto 20.",
                                    },
                                    "reason": {
                                        "type": "string",
                                        "description": "Justificación breve de la acción.",
                                    },
                                },
                                "required": ["action"],
                            },
                        }
                    },
                    "required": ["actions"],
                },
            },
        }
    ]

    user_message = (
        f"{enum_ctx}\n\n"
        f"{estado_ctx}\n\n"
        f"INFORME DEL MONITOR:\n{report_text}"
    )

    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            tools=tools,
            options={"temperature": 0},
        )

        if response.get("message", {}).get("tool_calls"):
            tool_call = response["message"]["tool_calls"][0]
            if tool_call["function"]["name"] == "apply_network_actions":
                actions = tool_call["function"]["arguments"].get("actions", [])
                resumen = [f"{a.get('action')}@{a.get('target_port', '-')}" for a in actions]
                print(f"[IA] {len(actions)} acción(es): {resumen}")
                return actions

        print("[IA] Red estable. No se invocaron acciones de mitigación.")
        return [{"action": "NO_ACTION"}]

    except Exception as e:
        print(f"[ERROR CRÍTICO] Fallo en la comunicación con Ollama: {e}")
        return None


def execute_resolution(decision):
    """Shim de compatibilidad para llamadas con el formato dict antiguo."""
    if not decision:
        return
    if isinstance(decision, dict):
        resolve_multiple([decision] if decision.get("action") not in ("none", "NO_ACTION") else [])
    else:
        resolve_multiple(decision)


def run_resolver_agent():
    print("=== AGENTE RESOLUTOR (Gestión de QoS Multi-Acción) ===")

    archivo_informe = os.path.join(TMP_DIR, "ultimo_informe.txt")

    if not os.path.exists(archivo_informe):
        print(
            f"[ERROR] No se encontró '{archivo_informe}'. Ejecuta el Agente Monitor primero."
        )
        return

    with open(archivo_informe, "r", encoding="utf-8") as f:
        reporte = f.read()

    actions = analyze_and_decide(reporte)

    if actions:
        resolve_multiple(actions)


if __name__ == "__main__":
    run_resolver_agent()
