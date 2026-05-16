import sys
import os
import re
import ollama
import time

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import config
from utils.ssh_client import get_ssh_connection, send_tmux_command

MODEL_NAME = config.MODEL_RESOLVER
TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)

# Cliente Ollama con timeout — evita que un ciclo cuelgue indefinidamente si el modelo se atasca.
_ollama_client = ollama.Client(host="http://localhost:11434", timeout=config.RESOLVER_LLM_TIMEOUT)

# Escala de severidad: cada nivel sólo puede subir, nunca bajar
ESCALATION = {"POLICING": "SHAPING", "SHAPING": "BLOCK", "BLOCK": "BLOCK"}

# Relajación: camino inverso cuando el tráfico vuelve a la normalidad
RELAXATION = {"BLOCK": "SHAPING", "SHAPING": "POLICING", "POLICING": None}

# Política por defecto para alertas de baja prioridad (las que no llegan al LLM).
# Determinista, replica las reglas del system prompt — el LLM "delega" en esta tabla.
DEFAULT_POLICY = {
    "ALERTA ROJA": "POLICING",  # pérdidas de paquetes: limitar ingress
    "ESCANEO":     "BLOCK",     # port scan: bloquear el origen
    "FAN-IN":      "BLOCK",     # DDoS fan-in: bloquear el puerto víctima
    "DoS":         "SHAPING",   # flujo volumétrico: moldear egress
}

# Pesos de severidad por categoría — definen el orden de prioridad para el top-K.
_CATEGORY_WEIGHT = {
    "ALERTA ROJA": 1000,  # pérdidas reales: siempre lo más urgente
    "ESCANEO":      800,  # seguridad: amenaza activa
    "FAN-IN":       600,  # DDoS coordinado
    "DoS":          400,  # volumétrico unitario
}


# =============================================================
# === PRIMITIVAS DE EJECUCIÓN (operan sobre una SSH abierta) ==
# =============================================================

def remove_policing(ssh, port):
    """Elimina el policing de ingress, devolviendo el puerto a estado libre."""
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} ingress 2>/dev/null; true")
    time.sleep(0.2)
    print(f"  [OK] RELAJACIÓN POLICING → {port}: restricción de ingress eliminada")


def remove_shaping(ssh, port):
    """Elimina el shaping de egress, devolviendo el puerto a estado libre."""
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
    time.sleep(0.2)
    print(f"  [OK] RELAJACIÓN SHAPING → {port}: restricción de egress eliminada")


def remove_block(ssh, port):
    """
    Elimina el bloqueo OpenFlow de alta prioridad y el tc ingress block.
    Permite que el controlador re-instale las reglas de reenvío normales.
    """
    bridge = port.split("-")[0]
    send_tmux_command(
        ssh,
        f"sh ovs-ofctl del-flows {bridge} in_port={port} 2>/dev/null; true",
    )
    time.sleep(0.2)
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} ingress 2>/dev/null; true")
    time.sleep(0.2)
    print(f"  [OK] RELAJACIÓN BLOCK → {port}: flujo OpenFlow DROP eliminado + tc block eliminado")


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
# === RELAJACIÓN DE REGLAS ====================================
# =============================================================

def run_relaxation(ports_to_relax):
    """
    Relaja las restricciones de los puertos cuyo tráfico ha vuelto a la normalidad.

    ports_to_relax: dict {port → current_action_str}
    Devuelve: dict {port → new_action_or_None}
      None  → sin restricción activa
      str   → nuevo nivel aplicado (SHAPING o POLICING)
    """
    if not ports_to_relax:
        return {}

    print(f"\n[RELAJACIÓN] Reduciendo restricciones en {len(ports_to_relax)} puerto(s)...")
    resultado = {}

    try:
        ssh = get_ssh_connection()

        for port, current_action in ports_to_relax.items():
            nuevo_nivel = RELAXATION.get(current_action)
            print(
                f"\n  --- RELAJAR {port}: {current_action} → "
                f"{nuevo_nivel if nuevo_nivel else 'SIN RESTRICCIÓN'} ---"
            )

            # Eliminar la restricción actual
            if current_action == "BLOCK":
                remove_block(ssh, port)
            elif current_action == "SHAPING":
                remove_shaping(ssh, port)
            elif current_action == "POLICING":
                remove_policing(ssh, port)

            # Aplicar el nivel inferior si corresponde
            if nuevo_nivel == "SHAPING":
                apply_shaping(ssh, port, rate_mbps=config.TASA_POLICING_MBPS)
            elif nuevo_nivel == "POLICING":
                apply_policing(ssh, port, rate_mbps=config.TASA_POLICING_MBPS)

            resultado[port] = nuevo_nivel

        ssh.close()

    except Exception as e:
        print(f"[ERROR] Fallo en run_relaxation: {e}")

    return resultado


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

def _parse_alerts(raw_telemetry):
    """
    Extrae alertas estructuradas (puerto, categoría, severidad) del texto crudo de telemetría.
    Devuelve lista ordenada por severidad descendente, sin duplicados por puerto.
    """
    if not raw_telemetry:
        return []

    alerts = []

    # [ALERTA ROJA]: pérdidas. El drop_delta da el peso fino.
    for m in re.finditer(
        r"\[ALERTA ROJA\].*?Port\s+(s\d+-eth\d+):.*?drop_delta=(\d+)",
        raw_telemetry,
    ):
        alerts.append({
            "port":     m.group(1),
            "category": "ALERTA ROJA",
            "metric":   int(m.group(2)),
            "severity": _CATEGORY_WEIGHT["ALERTA ROJA"] + int(m.group(2)),
        })

    # [ESCANEO]: port scan. Peso fijo (la severidad real está en el nº de destinos).
    for m in re.finditer(r"\[ESCANEO\].*?Port\s+(s\d+-eth\d+):", raw_telemetry):
        alerts.append({
            "port":     m.group(1),
            "category": "ESCANEO",
            "metric":   0,
            "severity": _CATEGORY_WEIGHT["ESCANEO"],
        })

    # [FAN-IN]: DDoS coordinado. Peso = MB combinados.
    for m in re.finditer(
        r"\[FAN-IN\].*?Port\s+(s\d+-eth\d+):.*?([\d.]+)\s*MB\s*combinados",
        raw_telemetry,
    ):
        mb = float(m.group(2))
        alerts.append({
            "port":     m.group(1),
            "category": "FAN-IN",
            "metric":   mb,
            "severity": _CATEGORY_WEIGHT["FAN-IN"] + mb,
        })

    # [DoS]: flujo volumétrico unitario. Peso = MB del flujo.
    for m in re.finditer(
        r"\[DoS\].*?Port\s+(s\d+-eth\d+):.*?\(([\d.]+)\s*MB\)",
        raw_telemetry,
    ):
        mb = float(m.group(2))
        alerts.append({
            "port":     m.group(1),
            "category": "DoS",
            "metric":   mb,
            "severity": _CATEGORY_WEIGHT["DoS"] + mb,
        })

    # Deduplicar por puerto, conservando la categoría de mayor severidad.
    by_port = {}
    for a in alerts:
        if a["port"] not in by_port or a["severity"] > by_port[a["port"]]["severity"]:
            by_port[a["port"]] = a

    return sorted(by_port.values(), key=lambda x: x["severity"], reverse=True)


def _default_action(alert, reglas_activas):
    """
    Decisión determinista para una alerta delegada (fuera del top-K del LLM).
    Aplica la política base y escala si el puerto ya tenía mitigación activa.
    """
    cat  = alert["category"]
    port = alert["port"]
    base = DEFAULT_POLICY.get(cat, "POLICING")

    # Si la acción propuesta coincide con la ya activa, hay que escalar.
    if reglas_activas and port in reglas_activas:
        previa = reglas_activas[port]["action"]
        if base == previa:
            base = ESCALATION.get(previa, "BLOCK")

    return {
        "action":      base,
        "target_port": port,
        "rate_mbps":   config.TASA_POLICING_MBPS,
        "reason":      f"Política por defecto ({cat} → {base}, severidad {alert['metric']:.1f})",
    }


def analyze_and_decide(report_text, raw_telemetry=None, reglas_activas=None):
    """
    Híbrido LLM + política determinista.
    - Las top-K alertas más críticas se envían al LLM (decisión informada).
    - El resto se resuelve con DEFAULT_POLICY (decisión inmediata, sin Ollama).
    Devuelve la lista combinada de acciones.
    """
    print("\n[IA] Evaluando el informe (top-K LLM + política por defecto)...")

    alerts = _parse_alerts(raw_telemetry)

    # Fast-path: sin alertas ni reglas activas → NO_ACTION inmediato.
    if not alerts and not reglas_activas:
        print("[IA] Red limpia. Sin acción necesaria.")
        return [{"action": "NO_ACTION"}]

    # Split top-K (LLM) vs resto (política por defecto).
    top_k = alerts[: config.RESOLVER_LLM_TOPK]
    rest  = alerts[config.RESOLVER_LLM_TOPK:]

    # Acciones deterministas para las alertas delegadas.
    default_actions = [_default_action(a, reglas_activas) for a in rest]
    if default_actions:
        resumen_default = [(a["target_port"], a["action"]) for a in default_actions]
        print(f"[IA] {len(default_actions)} alerta(s) delegadas a política por defecto: {resumen_default}")

    # Si no quedan alertas para el LLM (porque K cubre todo o porque hay 0 alertas
    # pero sí reglas_activas), devolvemos lo que tengamos. Las reglas_activas se
    # gestionan en el supervisor (escalado forzado + relajación).
    if not top_k:
        return default_actions or [{"action": "NO_ACTION"}]

    # --- Enumeración 1:1 para el LLM, ahora solo sobre top-K ---
    enum_lines = "\n".join(
        f"  {i+1}. {a['port']} [{a['category']}, severidad {a['metric']:.1f}]"
        for i, a in enumerate(top_k)
    )
    enum_ctx = (
        f"PUERTOS EN ALERTA (TOP-{len(top_k)} más críticos, MAPEO 1:1 OBLIGATORIO):\n{enum_lines}\n"
        f"TOTAL: {len(top_k)} puertos. "
        f"El array DEBE contener EXACTAMENTE {len(top_k)} entradas, una por puerto."
    )
    alerted_ports = [a["port"] for a in top_k]

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
        "Decides sobre las alertas más críticas del ciclo (top-K). "
        "Las alertas secundarias se resuelven con política por defecto antes de llegar a ti.\n"
        "REGLAS DE DECISIÓN:\n"
        "1. REGLA CRÍTICA DE CARDINALIDAD: el array de acciones debe tener EXACTAMENTE tantas entradas "
        "como el TOTAL indicado en 'PUERTOS EN ALERTA'. Ni una más, ni una menos.\n"
        "2. REGLA DE ESCALADO: si un puerto ya tiene una mitigación activa y sigue en alerta, "
        "DEBES escalar según la cadena POLICING → SHAPING → BLOCK. "
        "Nunca repitas la misma acción que ya falló en un ciclo anterior.\n"
        "3. Usa SHAPING para [DoS] (flujo volumétrico anómalo) — mitiga sin cortar la conectividad.\n"
        "4. Usa BLOCK para [ESCANEO] (port scan: bloquear origen) y [FAN-IN] (DDoS: bloquear la víctima). "
        "También como escalado final tras SHAPING.\n"
        "5. Usa POLICING para [ALERTA ROJA] (pérdidas) sin mitigación previa.\n"
        "6. NUNCA actúes sobre puertos 'LOCAL'. Formato obligatorio: sX-ethY (ej: s1-eth2).\n"
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
        t0 = time.time()
        response = _ollama_client.chat(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            tools=tools,
            options={"temperature": 0},
        )
        dt = time.time() - t0

        llm_actions = None
        if response.get("message", {}).get("tool_calls"):
            tool_call = response["message"]["tool_calls"][0]
            if tool_call["function"]["name"] == "apply_network_actions":
                llm_actions = tool_call["function"]["arguments"].get("actions", [])

        if llm_actions:
            resumen = [f"{a.get('action')}@{a.get('target_port', '-')}" for a in llm_actions]
            print(f"[IA] LLM resolvió {len(llm_actions)} acción(es) en {dt:.1f}s: {resumen}")
            return llm_actions + default_actions

        print(f"[IA] LLM no invocó la herramienta ({dt:.1f}s). Fallback a política por defecto para top-K.")
        fallback = [_default_action(a, reglas_activas) for a in top_k]
        return fallback + default_actions

    except Exception as e:
        print(f"[ERROR] Fallo en la llamada al LLM ({e}). Fallback a política por defecto para top-K.")
        fallback = [_default_action(a, reglas_activas) for a in top_k]
        return fallback + default_actions


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
