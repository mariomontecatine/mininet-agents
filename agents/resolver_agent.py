import sys
import os
import re
import json
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

# Cadena de mitigación, de gentil a brutal:
#   SHAPING  → encola en egress (TBF, atrasa pero no rompe TCP)
#   POLICING → dropea en ingress (más agresivo: causa retransmisiones)
#   BLOCK    → corte total (OpenFlow DROP)
ESCALATION = {"SHAPING": "POLICING", "POLICING": "BLOCK", "BLOCK": "BLOCK"}

# Desescalado: camino inverso cuando el tráfico vuelve a la normalidad
RELAXATION = {"BLOCK": "POLICING", "POLICING": "SHAPING", "SHAPING": None}

# Política por defecto para alertas de baja prioridad (las que no llegan al LLM).
# Determinista, replica las reglas del system prompt — el LLM "delega" en esta tabla.
DEFAULT_POLICY = {
    "ALERTA ROJA": "SHAPING",  # pérdidas: empezar gentil, encolar antes de dropear
    "ESCANEO":     "BLOCK",    # port scan: no hay nivel intermedio razonable, bloquear
    "DDoS":        "SHAPING",  # DDoS fan-in: encolar hacia la víctima antes de cortar
    "DoS":         "SHAPING",  # flujo volumétrico: encolar primero, escalar si persiste
}


# ─── Helpers de QoS por protocolo ────────────────────────────────────────────
def _tc_proto_match(protocol):
    """Devuelve la cláusula tc u32 que matchea (ip_proto, dport) del servicio.

    None si el protocolo no está en SERVICE_DEFS.
    """
    if not protocol or protocol not in config.SERVICE_DEFS:
        return None
    d = config.SERVICE_DEFS[protocol]
    parts = [f"match ip protocol {d['ip_proto']} 0xff"]
    if d.get("dport"):
        parts.append(f"match ip dport {d['dport']} 0xffff")
    return " ".join(parts)


def _of_proto_match(protocol):
    """Devuelve la cláusula OpenFlow para el protocolo (ej. 'udp,tp_dst=53')."""
    if not protocol or protocol not in config.SERVICE_DEFS:
        return None
    d = config.SERVICE_DEFS[protocol]
    transport = d.get("transport", "ip")
    if transport == "icmp":
        return "icmp"
    if d.get("dport"):
        return f"{transport},tp_dst={d['dport']}"
    return transport

# Niveles de agresividad para comparaciones de escalado/downgrade.
_LEVELS = {"SHAPING": 1, "POLICING": 2, "BLOCK": 3}

# ─── Rol de puerto (compartido con monitor_agent) ────────────────────────────
_HOST_PORT_FILE = os.path.join(TMP_DIR, "host_port_map.json")
_PORT_ROLE_CACHE: dict = {"data": None, "mtime": 0}


def _get_port_role(port: str) -> str:
    """Devuelve 'host', 'server' o 'trunk' para un puerto OVS. Cacheado por mtime."""
    if not os.path.exists(_HOST_PORT_FILE):
        return "trunk"
    mtime = os.path.getmtime(_HOST_PORT_FILE)
    if _PORT_ROLE_CACHE["data"] is None or mtime > _PORT_ROLE_CACHE["mtime"]:
        try:
            with open(_HOST_PORT_FILE, encoding="utf-8") as f:
                hp = json.load(f)
            port_to_host = {v: k for k, v in hp.items()}
            roles = {}
            for p, host in port_to_host.items():
                if host.startswith("srv"):
                    roles[p] = "server"
                elif host.startswith("h"):
                    roles[p] = "host"
                else:
                    roles[p] = "trunk"
            _PORT_ROLE_CACHE["data"]  = roles
            _PORT_ROLE_CACHE["mtime"] = mtime
        except (json.JSONDecodeError, IOError):
            return "trunk"
    return _PORT_ROLE_CACHE["data"].get(port, "trunk")

# Pesos de severidad por categoría — definen el orden de prioridad para el top-K.
_CATEGORY_WEIGHT = {
    "ALERTA ROJA": 1000,  # pérdidas reales: siempre lo más urgente
    "ESCANEO":      800,  # seguridad: amenaza activa
    "DDoS":       600,  # DDoS coordinado
    "DoS":          400,  # volumétrico unitario
}


# =============================================================
# === PRIMITIVAS DE EJECUCIÓN (operan sobre una SSH abierta) ==
# =============================================================

def remove_policing(ssh, port, protocol=None):
    """Elimina el policing de ingress (port-wide o por protocolo)."""
    # `tc qdisc del ... ingress` borra todos los filtros u32 colgados de él, así
    # que el caso protocol-aware y el port-wide convergen aquí.
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} ingress 2>/dev/null; true")
    time.sleep(0.2)
    scope = f"({protocol})" if protocol else ""
    print(f"  [OK] DESESCALADO POLICING {scope} → {port}: restricción de ingress eliminada")


def remove_shaping(ssh, port, protocol=None):
    """Elimina el shaping de egress (port-wide o por protocolo)."""
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
    time.sleep(0.2)
    scope = f"({protocol})" if protocol else ""
    print(f"  [OK] DESESCALADO SHAPING {scope} → {port}: restricción de egress eliminada")


def remove_block(ssh, port, protocol=None):
    """
    Elimina el bloqueo OpenFlow + tc ingress block.

    Si `protocol` está presente sólo elimina el flow que matchea ese protocolo
    en ese puerto (deja intactos otros bloqueos); en port-wide barre todo el
    in_port + tc ingress.
    """
    bridge = port.split("-")[0]
    if protocol:
        of_match = _of_proto_match(protocol)
        if of_match:
            send_tmux_command(
                ssh,
                f"sh ovs-ofctl del-flows {bridge} 'in_port={port},{of_match}' 2>/dev/null; true",
            )
            time.sleep(0.2)
            print(f"  [OK] DESESCALADO BLOCK ({protocol}) → {port}: flow OpenFlow eliminado")
            return
    send_tmux_command(
        ssh,
        f"sh ovs-ofctl del-flows {bridge} in_port={port} 2>/dev/null; true",
    )
    time.sleep(0.2)
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} ingress 2>/dev/null; true")
    time.sleep(0.2)
    print(f"  [OK] DESESCALADO BLOCK → {port}: flujo OpenFlow DROP eliminado + tc block eliminado")


def apply_policing(ssh, port, rate_mbps=20, protocol=None):
    """Policing ingress (port-wide o limitado al protocolo indicado).

    Si protocol está presente usa un filtro u32 que matchea (ip_proto, dport) y
    deja el resto del tráfico sin tocar — limita solo a ese servicio.
    """
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} ingress 2>/dev/null; true")
    time.sleep(0.2)
    send_tmux_command(ssh, f"sh tc qdisc add dev {port} handle ffff: ingress")
    time.sleep(0.1)

    match = _tc_proto_match(protocol) if protocol else None
    if match:
        send_tmux_command(
            ssh,
            f"sh tc filter add dev {port} parent ffff: protocol ip prio 1 u32 "
            f"{match} police rate {rate_mbps}mbit burst 64k drop flowid :1",
        )
        print(f"  [OK] POLICING ({protocol}) → {port}: {rate_mbps} Mbps ingress")
    else:
        send_tmux_command(
            ssh,
            f"sh tc filter add dev {port} parent ffff: protocol all u32 match u32 0 0 "
            f"police rate {rate_mbps}mbit burst 64k drop flowid :1",
        )
        print(f"  [OK] POLICING → {port}: {rate_mbps} Mbps ingress (tc police, pre-OVS)")


def apply_shaping(ssh, port, rate_mbps=20, protocol=None):
    """Shaping egress.

    - Sin protocol → tc TBF clásico sobre todo el tráfico saliente.
    - Con protocol → HTB con dos clases: 1:10 limitada a rate_mbps (el filtro
      u32 envía ahí solo el tráfico del servicio) y 1:30 ilimitada (default).
    """
    send_tmux_command(ssh, f"sh tc qdisc del dev {port} root 2>/dev/null; true")
    time.sleep(0.2)

    match = _tc_proto_match(protocol) if protocol else None
    if match:
        send_tmux_command(
            ssh, f"sh tc qdisc add dev {port} root handle 1: htb default 30"
        )
        time.sleep(0.1)
        send_tmux_command(
            ssh,
            f"sh tc class add dev {port} parent 1: classid 1:10 htb "
            f"rate {rate_mbps}mbit ceil {rate_mbps}mbit",
        )
        time.sleep(0.1)
        send_tmux_command(
            ssh,
            f"sh tc class add dev {port} parent 1: classid 1:30 htb "
            f"rate 1000mbit ceil 1000mbit",
        )
        time.sleep(0.1)
        send_tmux_command(
            ssh,
            f"sh tc filter add dev {port} parent 1: protocol ip prio 1 u32 "
            f"{match} flowid 1:10",
        )
        print(f"  [OK] SHAPING ({protocol}) → {port}: {rate_mbps} Mbps egress (htb+u32)")
    else:
        send_tmux_command(
            ssh,
            f"sh tc qdisc add dev {port} root tbf rate {rate_mbps}mbit burst 64kb latency 200ms",
        )
        print(f"  [OK] SHAPING → {port}: {rate_mbps} Mbps egress (tc tbf)")


def block_port(ssh, port, protocol=None):
    """
    Bloqueo de seguridad.

    - Sin protocol → OpenFlow DROP all in_port + tc ingress total block (kbit).
    - Con protocol → un único flujo OpenFlow DROP scoped por (in_port, proto, dport);
      el resto del tráfico sigue circulando.
    """
    bridge = port.split("-")[0]

    of_match = _of_proto_match(protocol) if protocol else None
    if of_match:
        send_tmux_command(
            ssh,
            f"sh ovs-ofctl add-flow {bridge} priority=200,"
            f"in_port={port},{of_match},actions=drop",
        )
        time.sleep(0.2)
        print(f"  [OK] BLOCK ({protocol}) → {port}: OpenFlow DROP ({of_match})")
        return

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
# === DESESCALADO DE REGLAS ===================================
# =============================================================

def run_desescalado(ports_to_relax):
    """
    Desescala las restricciones de los puertos cuyo tráfico ha vuelto a la normalidad.

    ports_to_relax: dict {port → current_action_str | {"action": ..., "protocol": ...}}
    Devuelve: dict {port → new_action_or_None}
      None  → sin restricción activa
      str   → nuevo nivel aplicado (SHAPING o POLICING)

    Acepta tanto el formato antiguo (action str) como el nuevo (dict con
    protocolo) para no romper llamadas existentes.
    """
    if not ports_to_relax:
        return {}

    print(f"\n[DESESCALADO] Reduciendo restricciones en {len(ports_to_relax)} puerto(s)...")
    resultado = {}

    try:
        ssh = get_ssh_connection()

        for port, current in ports_to_relax.items():
            if isinstance(current, dict):
                current_action = current.get("action")
                protocol       = current.get("protocol")
            else:
                current_action = current
                protocol       = None
            nuevo_nivel = RELAXATION.get(current_action)
            scope = f" [proto={protocol}]" if protocol else ""
            print(
                f"\n  --- DESESCALAR {port}{scope}: {current_action} → "
                f"{nuevo_nivel if nuevo_nivel else 'SIN RESTRICCIÓN'} ---"
            )

            if current_action == "BLOCK":
                remove_block(ssh, port, protocol=protocol)
            elif current_action == "SHAPING":
                remove_shaping(ssh, port, protocol=protocol)
            elif current_action == "POLICING":
                remove_policing(ssh, port, protocol=protocol)

            if nuevo_nivel == "SHAPING":
                apply_shaping(ssh, port, rate_mbps=config.TASA_POLICING_MBPS, protocol=protocol)
            elif nuevo_nivel == "POLICING":
                apply_policing(ssh, port, rate_mbps=config.TASA_POLICING_MBPS, protocol=protocol)

            resultado[port] = nuevo_nivel

        ssh.close()

    except Exception as e:
        print(f"[ERROR] Fallo en run_desescalado: {e}")

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
            protocol = item.get("protocol")
            if protocol and protocol not in config.SERVICE_DEFS:
                # Protocolo desconocido → descartamos el scope (acción port-wide).
                print(f"  [WARN] protocolo '{protocol}' no reconocido — aplicando port-wide.")
                protocol = None

            scope = f" [proto={protocol}]" if protocol else ""
            print(f"\n  --- {action}{scope} | puerto: {port} | motivo: {reason} ---")

            if not port or port.upper() == "LOCAL":
                print("  [SKIP] Puerto inválido o LOCAL, ignorado.")
                continue

            if action == "POLICING":
                apply_policing(ssh, port, rate, protocol=protocol)
            elif action == "SHAPING":
                apply_shaping(ssh, port, rate, protocol=protocol)
            elif action == "BLOCK":
                block_port(ssh, port, protocol=protocol)
            else:
                print(f"  [WARN] Acción desconocida '{action}', ignorada.")

        ssh.close()

    except Exception as e:
        print(f"[ERROR] Fallo en resolve_multiple: {e}")


# =============================================================
# === AGENTE DE DECISIÓN (LLM con Tool Calling multi-acción) ==
# =============================================================

def _extract_proto(line):
    """Lee la cláusula '[proto=<svc>]' añadida por monitor_agent._format_anomaly_lines.

    Devuelve el nombre del servicio si está presente, None en caso contrario.
    """
    m = re.search(r"\[proto=([a-z_]+)\]", line)
    return m.group(1) if m else None


def _parse_alerts(raw_telemetry, reglas_activas=None, skip_alerta_roja_ports=None):
    """
    Extrae alertas estructuradas (puerto, categoría, severidad, protocolo) del texto
    crudo de telemetría. Devuelve lista ordenada por severidad desc, sin duplicados.

    reglas_activas: puertos con QoS activa — sus drops son del propio TBF/police,
        no de un ataque nuevo. Se excluyen de [ALERTA ROJA] para evitar el bucle
        drops→alerta→más QoS→más drops.
    skip_alerta_roja_ports: conjunto adicional de puertos a ignorar en [ALERTA ROJA]
        (p.ej. recientemente desescalados, con drops acumulados del ciclo anterior).
    """
    if not raw_telemetry:
        return []

    # Puertos cuya [ALERTA ROJA] debe silenciarse porque sus drops son propios de la QoS.
    _suppress = set()
    if reglas_activas:
        _suppress.update(reglas_activas.keys())
    if skip_alerta_roja_ports:
        _suppress.update(skip_alerta_roja_ports)

    alerts = []

    for line in raw_telemetry.split("\n"):
        proto = _extract_proto(line)

        m = re.search(r"\[ALERTA ROJA\].*?Port\s+(s\d+-eth\d+):.*?drop_delta=(\d+)", line)
        if m:
            port = m.group(1)
            if port in _suppress:
                # Drops causados por QoS propio (TBF overflow o tc police) — no actuar.
                continue
            if _get_port_role(port) == "trunk":
                # Congestión en enlace backbone durante DDoS → no aplicar QoS aquí (sería FP).
                continue
            alerts.append({
                "port":     port,
                "category": "ALERTA ROJA",
                "metric":   int(m.group(2)),
                "protocol": proto,
                "severity": _CATEGORY_WEIGHT["ALERTA ROJA"] + int(m.group(2)),
            })
            continue

        m = re.search(r"\[ESCANEO\].*?Port\s+(s\d+-eth\d+):", line)
        if m:
            # port_scan: protocolo no aplicable (muchos destinos heterogéneos)
            alerts.append({
                "port":     m.group(1),
                "category": "ESCANEO",
                "metric":   0,
                "protocol": None,
                "severity": _CATEGORY_WEIGHT["ESCANEO"],
            })
            continue

        m = re.search(r"\[DDoS\].*?Port\s+(s\d+-eth\d+):.*?([\d.]+)\s*MB\s*combinados", line)
        if m:
            mb = float(m.group(2))
            alerts.append({
                "port":     m.group(1),
                "category": "DDoS",
                "metric":   mb,
                "protocol": proto,
                "severity": _CATEGORY_WEIGHT["DDoS"] + mb,
            })
            continue

        m = re.search(r"\[DoS\].*?Port\s+(s\d+-eth\d+):.*?\(([\d.]+)\s*MB\)", line)
        if m:
            mb = float(m.group(2))
            alerts.append({
                "port":     m.group(1),
                "category": "DoS",
                "metric":   mb,
                "protocol": proto,
                "severity": _CATEGORY_WEIGHT["DoS"] + mb,
            })
            continue

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

    Si la alerta lleva 'protocol', la acción se scopa a ese servicio.
    """
    cat  = alert["category"]
    port = alert["port"]
    proto = alert.get("protocol")
    base = DEFAULT_POLICY.get(cat, "POLICING")

    # Comparar contra la restricción ya activa en este puerto.
    if reglas_activas and port in reglas_activas:
        previa = reglas_activas[port]["action"]
        if _LEVELS.get(base, 0) == _LEVELS.get(previa, 0):
            # Mismo nivel → no está funcionando, escalar al siguiente.
            base = ESCALATION.get(previa, "BLOCK")
        elif _LEVELS.get(base, 0) < _LEVELS.get(previa, 0):
            # Acción propuesta más débil → no degradar la restricción existente.
            return {"action": "NO_ACTION", "target_port": port,
                    "rate_mbps": config.TASA_POLICING_MBPS,
                    "reason": f"Restricción más agresiva ({previa}) ya activa"}

    reason = (
        f"Política por defecto ({cat}{' '+proto if proto else ''} → {base}, "
        f"severidad {alert['metric']:.1f})"
    )
    out = {
        "action":      base,
        "target_port": port,
        "rate_mbps":   config.TASA_POLICING_MBPS,
        "reason":      reason,
    }
    if proto:
        out["protocol"] = proto
    return out


def fast_decide(raw_telemetry, reglas_activas=None, skip_alerta_roja_ports=None):
    """
    Decisión puramente determinista (sin LLM) para TODAS las alertas activas.
    Solo actúa sobre puertos que aún no tienen una regla aplicada — los que ya
    la tienen se dejan al LLM para que decida si escalar.
    Devuelve lista de acciones (puede estar vacía).
    """
    alerts = _parse_alerts(raw_telemetry,
                           reglas_activas=reglas_activas,
                           skip_alerta_roja_ports=skip_alerta_roja_ports)
    if not alerts:
        return []
    return [_default_action(a, reglas_activas) for a in alerts]


def analyze_and_decide(report_text, raw_telemetry=None, reglas_activas=None,
                       skip_alerta_roja_ports=None):
    """
    Híbrido LLM + política determinista.
    - Las top-K alertas más críticas se envían al LLM (decisión informada).
    - El resto se resuelve con DEFAULT_POLICY (decisión inmediata, sin Ollama).
    Devuelve la lista combinada de acciones.
    """
    print("\n[IA] Evaluando el informe (top-K LLM + política por defecto)...")

    alerts = _parse_alerts(raw_telemetry,
                           reglas_activas=reglas_activas,
                           skip_alerta_roja_ports=skip_alerta_roja_ports)

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
    # gestionan en el supervisor (escalado forzado + desescalado).
    if not top_k:
        return default_actions or [{"action": "NO_ACTION"}]

    # --- Enumeración 1:1 para el LLM, ahora solo sobre top-K ---
    def _enum_line(i, a):
        scope = f", proto={a['protocol']}" if a.get("protocol") else ""
        return f"  {i+1}. {a['port']} [{a['category']}{scope}, severidad {a['metric']:.1f}]"

    enum_lines = "\n".join(_enum_line(i, a) for i, a in enumerate(top_k))
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
        "DEBES escalar según la cadena SHAPING → POLICING → BLOCK "
        "(de gentil a brutal: encolar → dropear excedente → corte total). "
        "Nunca repitas la misma acción que ya falló en un ciclo anterior.\n"
        "3. Usa SHAPING como primera respuesta para [DoS], [DDoS] y [ALERTA ROJA] — "
        "encola en egress y atrasa el exceso sin romper TCP.\n"
        "4. Usa POLICING como escalado intermedio cuando SHAPING no contiene el ataque — "
        "dropea en ingress, más agresivo pero más eficiente.\n"
        "5. Usa BLOCK para [ESCANEO] (port scan: cortar el origen) y como escalado final tras POLICING.\n"
        "6. NUNCA actúes sobre puertos 'LOCAL'. Formato obligatorio: sX-ethY (ej: s1-eth2).\n"
        "7. PROTOCOLO: si la alerta indica '[proto=<svc>]' (ej: [proto=dns]) propaga el campo "
        "'protocol' en tu acción para que la mitigación se limite a ese servicio en lugar de "
        "todo el puerto. Valores válidos: http, https, http_alt, dns, ssh, sip, ftp, smtp, icmp. "
        "Omite 'protocol' si la alerta no especifica uno.\n"
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
                                    "protocol": {
                                        "type": "string",
                                        "enum": [
                                            "http", "https", "http_alt",
                                            "dns", "ssh", "sip",
                                            "ftp", "smtp", "icmp",
                                        ],
                                        "description": (
                                            "Opcional. Limita la acción a un protocolo concreto "
                                            "(ej. 'dns' bloquea solo UDP/53). Omitir = todo el tráfico."
                                        ),
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
