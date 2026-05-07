import sys
import os
import re
import json
import time
import base64

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)


def _icon_b64(path):
    """Devuelve un data URI base64 del PNG, o cadena vacía si no existe."""
    try:
        with open(path, "rb") as f:
            return "data:image/png;base64," + base64.b64encode(f.read()).decode()
    except FileNotFoundError:
        return ""


# ---------------------------------------------------------------------------
# Plantilla HTML con Cytoscape.js (CDN). Marcadores sustituidos en ejecución:
#   __ELEMENTS__  → JSON de nodos y aristas
# ---------------------------------------------------------------------------
_HTML = """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Topología de Red — Mininet</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #f0f4f8; font-family: 'Segoe UI', system-ui, sans-serif; }
    #cy { width: 100vw; height: 100vh; }
    #fit-btn {
      position: fixed; top: 16px; right: 20px;
      background: rgba(255,255,255,0.97); border: 1px solid #ddd;
      border-radius: 8px; padding: 7px 14px; cursor: pointer;
      font-size: 13px; color: #2c3e50;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      transition: background 0.15s;
    }
    #fit-btn:hover { background: #e8edf2; }
    #legend {
      position: fixed; bottom: 20px; right: 20px;
      background: rgba(255,255,255,0.97);
      border-radius: 10px; padding: 14px 18px;
      box-shadow: 0 2px 16px rgba(0,0,0,0.15);
      font-size: 12px; min-width: 120px;
    }
    #legend h3 { font-size: 13px; margin-bottom: 10px; color: #2c3e50; }
    .li { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; color: #555; }
    .li img { width: 20px; height: 20px; object-fit: contain; }
  </style>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"
          crossorigin="anonymous"></script>
</head>
<body>
  <div id="cy"></div>
  <button id="fit-btn" onclick="cy.fit(undefined,60)" title="Restablecer vista">⊡ Restablecer vista</button>
  <div id="legend">
    <h3>Leyenda</h3>
    <div class="li"><img src="__ICON_ROUTER__" alt="">Router</div>
    <div class="li"><img src="__ICON_SWITCH__" alt="">Switch</div>
    <div class="li"><img src="__ICON_SERVER__" alt="">Servidor</div>
    <div class="li"><img src="__ICON_HOST__"   alt="">Host</div>
  </div>
  <script>
    var cy = cytoscape({
      container: document.getElementById('cy'),
      elements: __ELEMENTS__,
      minZoom: 0.15,
      maxZoom: 3,
      wheelSensitivity: 0.15,
      style: [
        /* ── Nodos base ── */
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'font-size': '12px',
            'font-weight': 'bold',
            'color': '#2c3e50',
            'text-margin-y': '6px',
            /* El nodo es solo el icono: sin fondo de color ni borde */
            'background-image': 'data(icon)',
            'background-fit': 'contain',
            'background-opacity': 0,
            'border-width': 0,
            'shape': 'rectangle',
          }
        },
        { selector: 'node[type="router"]', style: { 'width': 52, 'height': 52 } },
        { selector: 'node[type="switch"]', style: { 'width': 46, 'height': 46 } },
        { selector: 'node[type="server"]', style: { 'width': 46, 'height': 46 } },
        { selector: 'node[type="host"]',   style: { 'width': 40, 'height': 40 } },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#f39c12',
            'background-color': '#f39c12',
            'background-opacity': 0.18,
          }
        },
        /* ── Aristas ── */
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#aab7b8',
            'curve-style': 'bezier',
            /* Etiquetas nativas en los extremos del cable */
            'source-label': 'data(sourceLabel)',
            'target-label': 'data(targetLabel)',
            'source-text-offset': 32,
            'target-text-offset': 32,
            'font-size': '10px',
            'font-family': 'monospace, Courier New',
            'color': '#2c3e50',
            /* Fondo 100 % opaco: cuando dos etiquetas se acercan,
               una tapa a la otra en lugar de fundirse y confundirse */
            'text-background-color': '#ffffff',
            'text-background-opacity': 1,
            'text-background-padding': '3px',
            'text-border-color': '#aab7b8',
            'text-border-width': 1,
            'text-border-opacity': 1,
            /* Rotar la etiqueta con el cable ayuda a saber de qué extremo es */
            'text-rotation': 'autorotate',
          }
        },
        {
          selector: 'edge:selected',
          style: { 'line-color': '#f39c12', 'width': 3 }
        }
      ],
      layout: {
        name: 'cose',
        animate: false,
        padding: 60,
        nodeRepulsion: 25000,
        idealEdgeLength: 160,
        edgeElasticity: 100,
        gravity: 0.3,
        numIter: 1000,
        componentSpacing: 120,
        nodeDimensionsIncludeLabels: true,
      }
    });

    cy.fit(undefined, 60);
  </script>
</body>
</html>
"""


def get_topology_links():
    """Se conecta a Mininet, lanza 'links' y lee el historial completo de Tmux."""
    print("\n[VISUALIZADOR] Extrayendo topología física de Mininet...")
    try:
        ssh = get_ssh_connection()

        send_tmux_command(ssh, "")
        wait_for_mininet_prompt(ssh, timeout=20)

        send_tmux_command(ssh, "links")

        # Espera real para que Mininet vuelque todos los enlaces en Tmux
        time.sleep(2)

        wait_for_mininet_prompt(ssh, timeout=20)

        stdin, stdout, stderr = ssh.exec_command(
            "tmux capture-pane -p -t sesion_mininet -S -5000"
        )
        raw_output = stdout.read().decode("utf-8")
        ssh.close()

        matches = re.findall(
            r"([a-zA-Z0-9_]+)-(eth\d+)<->([a-zA-Z0-9_]+)-(eth\d+)", raw_output
        )

        links = list({(n1, i1, n2, i2) for n1, i1, n2, i2 in matches})
        return links
    except Exception as e:
        print(f"[ERROR] No se pudo extraer la topología: {e}")
        return []


def draw_topology(links, output_file="topologia_interactiva.html"):
    """Genera un HTML estático con Cytoscape.js a partir de los enlaces de Mininet.

    links: lista de tuplas (node1, intf1, node2, intf2)
    """
    if not links:
        print("[VISUALIZADOR] No hay enlaces para dibujar.")
        return

    print("[VISUALIZADOR] Generando mapa interactivo con Cytoscape.js...")

    icons_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "icons")
    icons = {
        "router": _icon_b64(os.path.join(icons_dir, "router.png")),
        "switch": _icon_b64(os.path.join(icons_dir, "switch.png")),
        "server": _icon_b64(os.path.join(icons_dir, "server.png")),
        "host":   _icon_b64(os.path.join(icons_dir, "pc.png")),
    }

    def _node_type(name):
        if name.startswith("r"):   return "router"
        if name.startswith("srv"): return "server"
        if name.startswith("s"):   return "switch"
        return "host"

    nodes_seen = set()
    elements = []

    for node1, intf1, node2, intf2 in links:
        for node in (node1, node2):
            if node not in nodes_seen:
                ntype = _node_type(node)
                elements.append({
                    "data": {
                        "id": node,
                        "label": node,
                        "type": ntype,
                        "icon": icons[ntype],
                    }
                })
                nodes_seen.add(node)
        elements.append({
            "data": {
                "source": node1,
                "target": node2,
                "sourceLabel": intf1,
                "targetLabel": intf2,
            }
        })

    html = (
        _HTML
        .replace("__ELEMENTS__", json.dumps(elements, ensure_ascii=False))
        .replace("__ICON_ROUTER__", icons["router"])
        .replace("__ICON_SWITCH__", icons["switch"])
        .replace("__ICON_SERVER__", icons["server"])
        .replace("__ICON_HOST__",   icons["host"])
    )

    ruta_guardado = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), output_file
    )
    with open(ruta_guardado, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[VISUALIZADOR] ✅ Mapa interactivo guardado en: {ruta_guardado}")


def run_visualizer():
    enlaces = get_topology_links()
    draw_topology(enlaces)


if __name__ == "__main__":
    run_visualizer()
