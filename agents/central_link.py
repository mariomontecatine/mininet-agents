"""Detección del enlace/router central (cuello de botella) de la topología.

Se calcula UNA vez tras desplegar, cuando ya tenemos el grafo físico completo
(`get_topology_links` → tuplas (n1, i1, n2, i2) con nombres de interfaz reales).

Idea: en una red empresarial multi-sitio la saturación entre subredes ocurre en
el **troncal entre routers**, no en los switches de acceso. Por eso NO usamos
betweenness "a secas" (que premiaría al switch con más hosts colgando), sino la
betweenness restringida a pares de extremos servidos por routers DISTINTOS —
es decir, el tráfico que cruza de un sitio a otro. La arista que más caminos
inter-router concentra es el troncal; su switch es el "router central" lógico
donde aplicaremos QoS.

El puerto de shaping que devolvemos es SIEMPRE una interfaz de switch (puerto
OVS, vive en el root netns), alcanzable con `sh tc …` igual que el resto de la
QoS — así no hay que entrar al netns de un LinuxRouter.

Salida persistida en tmp/central_link.json:
  {
    "central_switch":  "s2",
    "trunk_link":      ["s2", "r2"],
    "shaping_port":    "s2-eth2",        # egress hacia el lado con más hosts
    "shaping_port_reverse": "s2-eth1",   # el otro extremo del troncal
    "ports":           ["s2-eth2", "s2-eth1"],
    "hosts_behind":    {"s2-eth2": 14, "s2-eth1": 0},
    "method":          "inter_router_betweenness" | "global_betweenness",
    "generated_at":    "..."
  }
"""

import os
import json
from collections import defaultdict, deque
from datetime import datetime

TMP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp")
CENTRAL_FILE = os.path.join(TMP_DIR, "central_link.json")


# ── Clasificación de nodos ───────────────────────────────────────────────────

def _is_router(n):  return n.startswith("r") and not n.startswith("srv")
def _is_server(n):  return n.startswith("srv")
def _is_switch(n):  return n.startswith("s") and not n.startswith("srv")
def _is_host(n):    return n.startswith("h")
def _is_endpoint(n): return _is_host(n) or _is_server(n)


# ── Grafo ─────────────────────────────────────────────────────────────────────

def _build_graph(phys_links):
    """phys_links: lista de (n1, i1, n2, i2). Devuelve adyacencia con interfaces.

    adj[node] = lista de (neighbor, my_intf, neighbor_intf)
    """
    adj = defaultdict(list)
    for n1, i1, n2, i2 in phys_links:
        adj[n1].append((n2, i1, i2))
        adj[n2].append((n1, i2, i1))
    return adj


def _bfs_path(adj, src, dst):
    """Camino más corto src→dst como lista de nodos (BFS, único en árboles)."""
    if src == dst:
        return [src]
    prev = {src: None}
    q = deque([src])
    while q:
        cur = q.popleft()
        if cur == dst:
            break
        for nb, _mi, _ni in adj[cur]:
            if nb not in prev:
                prev[nb] = cur
                q.append(nb)
    if dst not in prev:
        return []
    path = []
    cur = dst
    while cur is not None:
        path.append(cur)
        cur = prev[cur]
    return list(reversed(path))


def _nearest_router(adj, routers):
    """BFS multi-fuente desde los routers: asigna a cada nodo su router más cercano."""
    nearest = {}
    q = deque()
    for r in routers:
        nearest[r] = r
        q.append(r)
    while q:
        cur = q.popleft()
        for nb, _mi, _ni in adj[cur]:
            if nb not in nearest:
                nearest[nb] = nearest[cur]
                q.append(nb)
    return nearest


def _reachable_hosts(adj, start, blocked):
    """Cuenta nodos host (h*) alcanzables desde `start` sin cruzar `blocked`."""
    seen = {blocked, start}
    q = deque([start])
    count = 1 if _is_host(start) else 0
    while q:
        cur = q.popleft()
        for nb, _mi, _ni in adj[cur]:
            if nb in seen:
                continue
            seen.add(nb)
            if _is_host(nb):
                count += 1
            q.append(nb)
    return count


def _intf_between(adj, node, neighbor):
    """Interfaz de `node` que conecta con `neighbor` (p.ej. 's2' → 'eth2')."""
    for nb, my_intf, _ni in adj[node]:
        if nb == neighbor:
            return my_intf
    return None


# ── Cálculo principal ────────────────────────────────────────────────────────

def compute_central_link(phys_links, persist=True):
    """Calcula el troncal central y el puerto OVS de shaping.

    phys_links: lista de (n1, i1, n2, i2) — salida de get_topology_links().
    Devuelve el dict descrito en el módulo, o None si no se puede determinar.
    """
    if not phys_links:
        return None

    adj = _build_graph(phys_links)
    nodes = list(adj.keys())
    endpoints = [n for n in nodes if _is_endpoint(n)]
    routers = [n for n in nodes if _is_router(n)]
    if len(endpoints) < 2:
        return None

    # Pares de extremos a considerar: si hay ≥2 routers, solo el tráfico que
    # cruza de un router a otro (el que satura el troncal). Si no, todos.
    if len(routers) >= 2:
        nearest = _nearest_router(adj, routers)
        pairs = [(a, b) for i, a in enumerate(endpoints) for b in endpoints[i + 1:]
                 if nearest.get(a) != nearest.get(b)]
        method = "inter_router_betweenness"
    else:
        pairs = [(a, b) for i, a in enumerate(endpoints) for b in endpoints[i + 1:]]
        method = "global_betweenness"

    if not pairs:
        # Hay routers pero ningún par cruza (red de un solo sitio efectivo):
        # caemos a betweenness global.
        pairs = [(a, b) for i, a in enumerate(endpoints) for b in endpoints[i + 1:]]
        method = "global_betweenness"

    # Betweenness de aristas: cada par suma 1 a cada arista de su camino corto.
    edge_bet = defaultdict(float)
    for a, b in pairs:
        path = _bfs_path(adj, a, b)
        for u, v in zip(path, path[1:]):
            edge_bet[frozenset((u, v))] += 1.0

    if not edge_bet:
        return None

    # Arista central que TENGA un switch (para tener puerto OVS de shaping).
    def _edge_key(item):
        edge, score = item
        has_switch = any(_is_switch(n) for n in edge)
        return (score, has_switch)

    ranked = sorted(edge_bet.items(), key=_edge_key, reverse=True)
    central_edge = None
    for edge, _score in ranked:
        if any(_is_switch(n) for n in edge):
            central_edge = edge
            break
    if central_edge is None:
        central_edge = ranked[0][0]

    edge_nodes = list(central_edge)
    switches = [n for n in edge_nodes if _is_switch(n)]
    central_switch = switches[0] if switches else edge_nodes[0]

    # Puertos troncales del switch central: los que van a router u otro switch
    # (no a hosts/servidores). Para cada uno, cuántos hosts quedan "detrás".
    trunk_ports = []
    for nb, my_intf, _ni in adj[central_switch]:
        if _is_router(nb) or _is_switch(nb):
            hosts_behind = _reachable_hosts(adj, nb, blocked=central_switch)
            trunk_ports.append({
                "port": f"{central_switch}-{my_intf}",
                "neighbor": nb,
                "hosts_behind": hosts_behind,
            })

    if not trunk_ports:
        # El switch central solo toca hosts/servidores (topología degenerada):
        # usamos cualquier puerto hacia el otro extremo de la arista central.
        other = [n for n in edge_nodes if n != central_switch]
        nb = other[0] if other else None
        my_intf = _intf_between(adj, central_switch, nb) if nb else None
        if my_intf:
            trunk_ports = [{
                "port": f"{central_switch}-{my_intf}",
                "neighbor": nb,
                "hosts_behind": _reachable_hosts(adj, nb, blocked=central_switch),
            }]

    if not trunk_ports:
        return None

    # Primario = egress hacia el lado con MÁS hosts (donde se nota la saturación
    # de cara a los usuarios). El reverso = el otro extremo del troncal.
    trunk_ports.sort(key=lambda p: p["hosts_behind"], reverse=True)
    shaping_port = trunk_ports[0]["port"]
    shaping_port_reverse = trunk_ports[1]["port"] if len(trunk_ports) > 1 else None

    result = {
        "central_switch": central_switch,
        "trunk_link": sorted(edge_nodes),
        "shaping_port": shaping_port,
        "shaping_port_reverse": shaping_port_reverse,
        "ports": [p["port"] for p in trunk_ports],
        "hosts_behind": {p["port"]: p["hosts_behind"] for p in trunk_ports},
        "neighbors": {p["port"]: p["neighbor"] for p in trunk_ports},
        "method": method,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }

    if persist:
        try:
            os.makedirs(TMP_DIR, exist_ok=True)
            with open(CENTRAL_FILE, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
        except IOError:
            pass

    return result


def load_central_link():
    """Carga tmp/central_link.json, o None si no existe / es ilegible."""
    if not os.path.exists(CENTRAL_FILE):
        return None
    try:
        with open(CENTRAL_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None
