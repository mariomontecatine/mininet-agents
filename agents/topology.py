import sys
import os
from pyvis.network import Network

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)


def get_topology_links():
    """Se conecta a Mininet, lanza 'links' y lee el historial completo de Tmux."""
    print("\n[VISUALIZADOR] Extrayendo topología física de Mininet...")
    try:
        ssh = get_ssh_connection()

        # 1. Aseguramos que la consola está limpia y lista
        send_tmux_command(ssh, "")
        wait_for_mininet_prompt(ssh, timeout=5)

        # 2. Lanzamos el comando normal de links
        send_tmux_command(ssh, "links")
        wait_for_mininet_prompt(ssh, timeout=10)

        # 3. EL TRUCO MAESTRO (Versión Definitiva):
        # Le pedimos a Tmux que nos escupa las últimas 1000 líneas de historial (scrollback).
        # Así no importa si la pantalla visible es pequeña, capturaremos el árbol entero.
        stdin, stdout, stderr = ssh.exec_command(
            "tmux capture-pane -p -t sesion_mininet -S -1000"
        )
        raw_output = stdout.read().decode("utf-8")

        ssh.close()

        links = []
        import re

        # Buscamos coincidencias tipo s1-eth1<->h1-eth0
        matches = re.findall(
            r"([a-zA-Z0-9_]+)-eth\d+<->([a-zA-Z0-9_]+)-eth\d+", raw_output
        )

        for node1, node2 in matches:
            links.append((node1, node2))

        # Eliminar duplicados
        links = list(set(links))

        return links
    except Exception as e:
        print(f"[ERROR] No se pudo extraer la topología: {e}")
        return []


def draw_topology(links, output_file="topologia_interactiva.html"):
    """Dibuja el grafo de la red con físicas e iconos locales y lo guarda como HTML."""
    if not links:
        print("[VISUALIZADOR] No hay enlaces para dibujar.")
        return

    print("[VISUALIZADOR] Generando Gemelo Digital interactivo...")

    # Crear la red con fondo blanco
    net = Network(height="800px", width="100%", bgcolor="#ffffff", font_color="black")

    # Motor de física Force Atlas (fíjate en el nombre exacto de la función)
    net.force_atlas_2based(
        gravity=-60, central_gravity=0.01, spring_length=120, spring_strength=0.05
    )

    # Rutas relativas a la carpeta 'iconos' que acabas de crear
    ICON_PC = "icons/pc.png"
    ICON_SWITCH = "icons/switch.png"

    nodes_added = set()

    for node1, node2 in links:
        # Añadir nodos con sus iconos locales
        for node in (node1, node2):
            if node not in nodes_added:
                if node.startswith("h"):
                    # Nodos Host: más pequeños, fuente ajustada abajo
                    net.add_node(
                        node,
                        label=node,
                        shape="image",
                        image=ICON_PC,
                        size=25,
                        font={"size": 14, "color": "#333333", "vadjust": 35},
                    )
                else:
                    # Nodos Switch/Router: más grandes, fuente en negrita
                    net.add_node(
                        node,
                        label=node,
                        shape="image",
                        image=ICON_SWITCH,
                        size=35,
                        font={
                            "size": 16,
                            "color": "black",
                            "vadjust": 45,
                            "face": "bold",
                        },
                    )
                nodes_added.add(node)

        # Añadir el cable (arista) un poco más sutil
        net.add_edge(node1, node2, color="#A0A0A0", width=1.5)

    # Guardar en la raíz del proyecto
    ruta_guardado = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), output_file
    )
    net.write_html(ruta_guardado)

    print(f"[VISUALIZADOR] ✅ Mapa interactivo guardado en: {ruta_guardado}")


def run_visualizer():
    enlaces = get_topology_links()
    draw_topology(enlaces)


if __name__ == "__main__":
    run_visualizer()
