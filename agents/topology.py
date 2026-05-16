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
    body { background: #ffffff; color: #1a1c1f;
           font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; }
    #cy { width: 100vw; height: 100vh; }
    #fit-btn {
      position: fixed; top: 16px; right: 20px;
      background: #1c1f24; border: 1px solid #2d3035;
      border-radius: 3px; padding: 6px 12px; cursor: pointer;
      font-size: 11px; color: #d9d9d9;
      letter-spacing: .05em; text-transform: uppercase;
      transition: border-color 0.15s, color 0.15s;
    }
    #fit-btn:hover { border-color: #5794f2; color: #5794f2; }
    #legend {
      position: fixed; bottom: 20px; right: 20px;
      background: #1c1f24; border: 1px solid #2d3035;
      border-radius: 3px; padding: 12px 14px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.4);
      font-size: 11px; min-width: 130px; color: #d9d9d9;
    }
    #legend h3 { font-size: 10px; margin-bottom: 8px; color: #6e7177;
                 letter-spacing: .08em; text-transform: uppercase; font-weight: 600; }
    .li { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; color: #d9d9d9; }
    .li img { width: 18px; height: 18px; object-fit: contain; }
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
      wheelSensitivity: 0,
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
            'color': '#1a1c1f',
            'text-outline-color': '#ffffff',
            'text-outline-width': 2,
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
            'source-text-offset': 12,
            'target-text-offset': 12,
            'font-size': '10px',
            'font-family': 'monospace, Courier New',
            'color': '#1a1c1f',
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

    // Clave única por topología (nodos + aristas) para no mezclar layouts distintos
    var _key = 'cyto-' + cy.nodes().length + 'n-' + cy.edges().length + 'e';
    var _saved = JSON.parse(localStorage.getItem(_key) || 'null');

    if (_saved) {
      // Restaurar posiciones guardadas (evita que el usuario pierda su organización)
      cy.startBatch();
      cy.nodes().forEach(function(n) {
        if (_saved[n.id()]) n.position(_saved[n.id()]);
      });
      cy.endBatch();
    }

    cy.fit(undefined, 60);

    // Ctrl+rueda = zoom; rueda sola = scroll de la página padre
    document.getElementById('cy').addEventListener('wheel', function(e) {
      if (e.ctrlKey) {
        e.preventDefault();
        var factor = e.deltaY < 0 ? 1.15 : 0.87;
        cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: e.offsetX, y: e.offsetY } });
      } else {
        window.parent.postMessage({ noc_scroll: e.deltaY }, '*');
      }
    }, { passive: false });

    // Guardar posiciones cada vez que se mueve un nodo
    cy.on('dragfree', 'node', function() {
      var pos = {};
      cy.nodes().forEach(function(n) { pos[n.id()] = n.position(); });
      localStorage.setItem(_key, JSON.stringify(pos));
    });
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
        wait_for_mininet_prompt(ssh, timeout=20)
        # Pausa extra: wait_for_mininet_prompt puede volver al ver el prompt
        # antes de que mininet termine de imprimir todas las líneas de 'links'.
        time.sleep(1.5)

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


TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
os.makedirs(TMP_DIR, exist_ok=True)


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

    ruta_guardado = os.path.join(TMP_DIR, output_file)
    with open(ruta_guardado, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[VISUALIZADOR] ✅ Mapa interactivo guardado en: {ruta_guardado}")


def dump_host_interfaces():
    """
    Devuelve dict {host_name: [ip1, ip2, ...]} con TODAS las IPs activas de
    cada host/router de Mininet. Para hosts mono-homed devuelve [ip]; para
    routers multi-subnet devuelve todas las interfaces no-loopback.

    Implementación: ejecuta una sola línea 'py print(...)' en mininet> y
    parsea la lista de tuplas que imprime, con marcas BEGIN/END para
    aislarla del resto del buffer tmux.
    """
    import ast
    BEGIN, END = "__HOSTIP_BEGIN__", "__HOSTIP_END__"
    # OJO: send_tmux_command envuelve el comando en comillas simples, así que
    # NO podemos usar comillas simples dentro de la expresión. Filtramos
    # 127.0.0.1 en Python local tras parsear el output.
    expr = ('py print("' + BEGIN + '" + str([(h.name, '
            '[i.IP() for i in h.intfList() if i.IP()]'
            ') for h in net.hosts]) + "' + END + '")')
    try:
        ssh = get_ssh_connection()
        send_tmux_command(ssh, "")
        wait_for_mininet_prompt(ssh, timeout=15)
        send_tmux_command(ssh, expr)
        wait_for_mininet_prompt(ssh, timeout=20)
        time.sleep(1.0)  # margen anti-race (mismo motivo que en get_topology_links)
        # -J: une líneas envueltas por ancho de terminal. Sin esto, las
        # salidas largas se rompen a ~200 col y el regex no encuentra el END.
        _, o, _ = ssh.exec_command("tmux capture-pane -J -p -t sesion_mininet -S -5000")
        raw = o.read().decode("utf-8", errors="replace")
        ssh.close()
        m = re.search(re.escape(BEGIN) + r"(\[.*?\])" + re.escape(END), raw, re.DOTALL)
        if not m:
            return {}
        pairs = ast.literal_eval(m.group(1))
        # Filtramos loopback aquí (no en el comando enviado a tmux)
        return {name: [ip for ip in ips if ip != "127.0.0.1"]
                for name, ips in pairs if any(ip != "127.0.0.1" for ip in ips)}
    except Exception as e:
        print(f"[WARN] dump_host_interfaces falló: {e}")
        return {}


def persist_topology_json(host_ips, links, output_file="topology.json"):
    """
    Escribe tmp/topology.json con el formato que esperan los lectores
    (dashboard._build_host_map y monitor_agent.detect_flow_anomalies):
      {
        "nodes":     [name | ip, ...],
        "links":     [{"from": host, "to": ip}, ...],   # uno por (host, ip)
        "endpoints": {host: ip_principal, ...}
      }

    Soporta hosts multi-homed: emite tantos pseudo-links como IPs tenga el
    host. Eso permite resolver TODAS las IPs en el Sankey, incluidas las de
    routers con varias interfaces.
    """
    nodes = []
    nodes_seen = set()

    def _add(n):
        if n not in nodes_seen:
            nodes.append(n)
            nodes_seen.add(n)

    pseudo_links = []
    endpoints = {}
    for host, ips in host_ips.items():
        _add(host)
        for ip in ips:
            _add(ip)
            pseudo_links.append({"from": host, "to": ip})
        if ips:
            endpoints[host] = ips[0]

    # Enlaces físicos (host↔switch, switch↔switch) — sin la información de
    # interfaz, solo el grafo lógico. Útil para el visualizador.
    phys_links = []
    for n1, _i1, n2, _i2 in links:
        _add(n1); _add(n2)
        phys_links.append({"from": n1, "to": n2})

    payload = {
        "nodes":     nodes,
        "links":     pseudo_links + phys_links,
        "endpoints": endpoints,
    }
    try:
        path = os.path.join(TMP_DIR, output_file)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        return path
    except IOError as e:
        print(f"[WARN] No se pudo escribir topology.json: {e}")
        return None


def run_visualizer():
    enlaces = get_topology_links()
    draw_topology(enlaces)


if __name__ == "__main__":
    run_visualizer()
