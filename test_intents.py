"""
Script de validación de intents: prueba los 5 prompts complejos contra
generate_network_intent y valida completitud de nodos y enlaces.
No despliega nada en Mininet.
"""
import re
import sys
import json

sys.path.insert(0, "/home/mario/UGR/mininet-agents")

from agents.deploy_agent import (
    generate_network_intent,
    _find_isolated_nodes,
    _find_disconnected_switches,
    _find_empty_leaf_switches,
    _fix_invalid_links,
)

PROMPTS = {
    "Campus universitario": (
        "Crea una red de campus universitario. Hay un router central r1 conectado a tres switches "
        "de edificio: s1 (facultad de informática), s2 (biblioteca) y s3 (administración). "
        "Al s1 conecta 8 PCs de laboratorio (h1 a h8) y 2 servidores de cálculo (srv1, srv2). "
        "Al s2 conecta 4 PCs de consulta (h9 a h12) y 1 servidor de catálogo (srv3). "
        "Al s3 conecta 3 PCs administrativos (h13, h14, h15) y 1 servidor de gestión (srv4)."
    ),
    "Data center spine-leaf": (
        "Diseña un data center con arquitectura spine-leaf. Dos routers spine: r1 y r2. "
        "Cuatro switches leaf: s1, s2, s3 y s4. Cada spine conecta a todos los leaf. "
        "Al s1 y s2 conecta 3 servidores de aplicación cada uno (srv1-srv6). "
        "Al s3 conecta 2 servidores de base de datos (srv7, srv8). "
        "Al s4 conecta 2 servidores de almacenamiento (srv9, srv10) y 2 hosts de monitorización (h1, h2)."
    ),
    "Red corporativa DMZ": (
        "Red empresarial con tres zonas. Router perimetral r1 conectado a: switch s1 de zona DMZ pública "
        "con 3 servidores web (srv1, srv2, srv3); switch s2 de zona interna con router interno r2 que "
        "conecta al switch s3 de empleados con 10 PCs (h1 a h10) y al switch s4 de dirección con 4 PCs "
        "ejecutivos (h11, h12, h13, h14); y switch s5 de servidores internos con 2 servidores de ficheros "
        "(srv4, srv5) y 1 servidor de base de datos (srv6)."
    ),
    "ISP residencial/empresarial": (
        "Simula una red de ISP. Router backbone r1 conectado a dos routers de distribución r2 y r3. "
        "R2 conecta al switch s1 con 6 clientes residenciales (h1 a h6) y al switch s2 con 4 clientes "
        "residenciales más (h7 a h10). R3 conecta al switch s3 con 3 clientes empresariales con servidores "
        "propios (srv1, srv2, srv3) y al switch s4 con 5 hosts de oficina (h11 a h15). R1 también conecta "
        "directamente al switch s5 de servicios del ISP con 2 servidores DNS y caché (srv4, srv5)."
    ),
    "Red hospitalaria crítica": (
        "Red hospitalaria con alta disponibilidad. Router principal r1 y router de respaldo r2, ambos "
        "conectados al switch de core s1. S1 conecta a: switch s2 de urgencias con 4 terminales médicos "
        "(h1 a h4) y 1 servidor de imágenes (srv1); switch s3 de planta con 6 tablets de enfermería "
        "(h5 a h10); switch s4 de administración con 3 PCs (h11, h12, h13) y 1 servidor de gestión (srv2); "
        "switch s5 de servidores centrales con servidor de historia clínica (srv3), servidor de farmacia "
        "(srv4) y servidor de laboratorio (srv5)."
    ),
}


def _expand_nodes(text):
    """Extrae nodos individuales del texto, expandiendo rangos como 'h1 a h8' o 'srv1-srv6'."""
    nodes = set()

    # Rangos "prefijoa h1 a h8"
    for m in re.finditer(r'\b([a-z]+)(\d+)\s+a\s+\1(\d+)\b', text):
        prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        nodes.update(f"{prefix}{i}" for i in range(start, end + 1))

    # Rangos "srv1-srv6"
    for m in re.finditer(r'\b([a-z]+)(\d+)-([a-z]+)(\d+)\b', text):
        if m.group(1) == m.group(3):
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(4))
            nodes.update(f"{prefix}{i}" for i in range(start, end + 1))

    # Nodos individuales (r1, s1, h1, srv1…)
    for m in re.finditer(r'\b(srv\d+|[rsh]\d+)\b', text):
        nodes.add(m.group(1))

    return nodes


def validate(name, prompt, intent):
    errors = []

    if intent is None:
        return ["La IA devolvió None"]

    if intent.get("tipo") != "custom":
        return []  # estándar: no validamos

    isolated = _find_isolated_nodes(intent)
    if isolated:
        errors.append(f"Nodos aislados: {sorted(isolated)}")

    disconnected = _find_disconnected_switches(intent)
    if disconnected:
        errors.append(f"Switches sin ruta a router: {sorted(disconnected)}")

    empty_leaves = _find_empty_leaf_switches(intent)
    if empty_leaves:
        errors.append(f"Switches hoja sin endpoints: {sorted(empty_leaves)}")

    # Nodos esperados según el texto del prompt que no aparecen NI declarados NI en enlaces
    # (build_python_script auto-añade desde enlaces, así que basta con que estén en alguno)
    expected = _expand_nodes(prompt)
    declared = set()
    for key in ("routers", "switches", "hosts", "servers"):
        declared.update(intent.get(key, []))
    linked_nodes = {n for link in intent.get("links", []) for n in link}
    missing_everywhere = expected - declared - linked_nodes
    if missing_everywhere:
        errors.append(f"Nodos ausentes en todo el intent: {sorted(missing_everywhere)}")

    # Verificar enlaces inválidos (endpoint↔endpoint)
    bad = []
    for link in intent.get("links", []):
        n1, n2 = link[0], link[1]
        if (n1.startswith("h") or n1.startswith("srv")) and \
           (n2.startswith("h") or n2.startswith("srv")):
            bad.append(f"{n1}↔{n2}")
    if bad:
        errors.append(f"Enlaces inválidos: {bad}")

    return errors


def run_all():
    results = {}
    pending = dict(PROMPTS)

    while pending:
        still_pending = {}
        for name, prompt in pending.items():
            print(f"\n{'='*60}")
            print(f"  Probando: {name}")
            print(f"{'='*60}")

            intent = generate_network_intent(prompt)
            errors = validate(name, prompt, intent)

            if errors:
                print(f"  [FAIL] {name}")
                for e in errors:
                    print(f"    - {e}")
                print(f"  Intent recibido:")
                print(json.dumps(intent, indent=4, ensure_ascii=False))
                still_pending[name] = prompt
            else:
                print(f"  [OK] {name}")
                print(f"    Nodos: {sum(len(intent.get(k,[])) for k in ('routers','switches','hosts','servers'))}")
                print(f"    Enlaces: {len(intent.get('links', []))}")
                results[name] = intent

        pending = still_pending
        if pending:
            print(f"\n  → Reintentando {len(pending)} prompt(s) fallido(s)...\n")

    print(f"\n{'='*60}")
    print("  TODOS LOS PROMPTS PASARON")
    print(f"{'='*60}")
    return results


if __name__ == "__main__":
    run_all()
