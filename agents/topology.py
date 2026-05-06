import sys
import os
import re
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

        # 1. Aseguramos que la consola está limpia
        send_tmux_command(ssh, "")
        wait_for_mininet_prompt(ssh, timeout=20)

        # 2. Lanzamos el comando de links
        send_tmux_command(ssh, "links")

        # --- PARCHE DE SINCRONIZACIÓN ---
        # Obligamos a Python a esperar 2 segundos reales para que Mininet
        # tenga tiempo de volcar todos los enlaces en la pantalla de Tmux.
        import time

        time.sleep(2)
        # --------------------------------

        wait_for_mininet_prompt(ssh, timeout=20)

        # 3. Capturamos el historial del panel (ampliado a 5000 líneas para redes masivas)
        stdin, stdout, stderr = ssh.exec_command(
            "tmux capture-pane -p -t sesion_mininet -S -5000"
        )
        raw_output = stdout.read().decode("utf-8")

        ssh.close()

        links = []

        # Buscamos coincidencias tipo s1-eth1<->h1-eth0
        import re

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

    # Motor de física Force Atlas
    net.force_atlas_2based(
        gravity=-60, central_gravity=0.01, spring_length=120, spring_strength=0.05
    )

    # Rutas relativas a la carpeta 'icons'
    ICON_PC = "icons/pc.png"
    ICON_SWITCH = "icons/switch.png"
    ICON_ROUTER = "icons/router.png"
    ICON_SERVER = "icons/server.png"

    nodes_added = set()

    for node1, node2 in links:
        # Añadir nodos con sus iconos locales
        for node in (node1, node2):
            if node not in nodes_added:
                # 1. Es un ROUTER
                if node.startswith("r"):
                    net.add_node(
                        node,
                        label=node,
                        shape="image",
                        image=ICON_ROUTER,
                        size=45,  # Más grande para que destaque
                        font={
                            "size": 18,
                            "color": "black",
                            "vadjust": 50,
                            "face": "bold",
                        },
                    )
                # 2. Es un SERVIDOR
                elif node.startswith("srv"):
                    net.add_node(
                        node,
                        label=node,
                        shape="image",
                        image=ICON_SERVER,
                        size=35,
                        font={
                            "size": 16,
                            "color": "black",
                            "vadjust": 45,
                            "face": "bold",
                        },
                    )
                # 3. Es un SWITCH
                elif node.startswith("s"):
                    net.add_node(
                        node,
                        label=node,
                        shape="image",
                        image=ICON_SWITCH,
                        size=30,
                        font={
                            "size": 14,
                            "color": "#333333",
                            "vadjust": 40,
                            "face": "bold",
                        },
                    )
                # 4. Es un PC/HOST normal
                else:
                    net.add_node(
                        node,
                        label=node,
                        shape="image",
                        image=ICON_PC,
                        size=25,
                        font={"size": 14, "color": "#555555", "vadjust": 35},
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
