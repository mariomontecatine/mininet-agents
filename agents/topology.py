import sys
import os
import time
import networkx as nx
import matplotlib.pyplot as plt

# Parche de rutas para VS Code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ssh_client import (
    get_ssh_connection,
    send_tmux_command,
    capture_tmux_output,
    wait_for_mininet_prompt,
)


def get_topology_links():
    """Se conecta a Mininet y extrae los enlaces físicos activos."""
    print("\n[VISUALIZADOR] Extrayendo topología física de Mininet...")
    try:
        ssh = get_ssh_connection()

        # Limpiamos buffer y lanzamos el comando 'links'
        send_tmux_command(ssh, "")
        wait_for_mininet_prompt(ssh, timeout=2)

        send_tmux_command(ssh, "links")
        wait_for_mininet_prompt(ssh, timeout=5)

        raw_output = capture_tmux_output(ssh)
        ssh.close()

        # Parsear la salida. Las líneas de enlaces suelen ser: h1-eth0<->s1-eth1 (OK OK)
        links = []
        for line in raw_output.split("\n"):
            if "<->" in line:
                try:
                    # Separamos por la flecha doble
                    parts = line.split("<->")
                    # El nodo 1 es lo que hay antes de "-eth" en la parte izquierda
                    node1 = parts[0].split("-eth")[0].strip()
                    # El nodo 2 es lo que hay antes de "-eth" en la parte derecha (quitando lo de OK OK)
                    node2 = parts[1].split()[0].split("-eth")[0].strip()

                    # Evitamos meter basura
                    if node1 and node2:
                        links.append((node1, node2))
                except Exception:
                    continue

        return links
    except Exception as e:
        print(f"[ERROR] No se pudo extraer la topología: {e}")
        return []


def draw_topology(links, output_file="topologia_red.png"):
    """Dibuja el grafo de la red y lo guarda como imagen."""
    if not links:
        print("[VISUALIZADOR] No hay enlaces para dibujar.")
        return

    print("[VISUALIZADOR] Dibujando mapa de la red...")

    # Crear el grafo
    G = nx.Graph()
    G.add_edges_from(links)

    # Colorear nodos (Hosts en verde, Switches en azul)
    color_map = []
    for node in G:
        if node.startswith("h"):
            color_map.append("lightgreen")
        else:
            color_map.append("lightblue")

    # Configurar el lienzo
    plt.figure(figsize=(12, 8))

    # Algoritmo de posicionamiento (spring_layout simula muelles, queda muy natural)
    pos = nx.spring_layout(G, k=0.5, iterations=50)

    # Dibujar
    nx.draw(
        G,
        pos,
        node_color=color_map,
        with_labels=True,
        node_size=1500,
        font_weight="bold",
        font_size=10,
        edge_color="gray",
        width=2,
    )

    plt.title("Topología de Mininet", size=15)

    # Guardar en la raíz del proyecto
    ruta_guardado = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), output_file
    )
    plt.savefig(ruta_guardado, format="PNG")
    plt.close()

    print(f"[VISUALIZADOR] ✅ Topología guardada con éxito en: {ruta_guardado}")


def run_visualizer():
    enlaces = get_topology_links()
    draw_topology(enlaces)


if __name__ == "__main__":
    run_visualizer()
