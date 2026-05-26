"""Tests de la detección del enlace/router central (agents.central_link)."""

from agents.central_link import compute_central_link


def _empresa_links():
    """Enlaces físicos (n1,i1,n2,i2) de una empresa de 2 sitios: r1↔s2↔r2.

    r1: s1 (srv1,srv2), s5 (srv3) | troncal s2 | r2: s3 (h1..h3), s4 (h4)
    """
    pairs = [
        ("r1", "s1"), ("s1", "srv1"), ("s1", "srv2"),
        ("r1", "s5"), ("s5", "srv3"),
        ("r1", "s2"), ("s2", "r2"),
        ("r2", "s3"), ("s3", "h1"), ("s3", "h2"), ("s3", "h3"),
        ("r2", "s4"), ("s4", "h4"),
    ]
    ctr = {}
    links = []
    for a, b in pairs:
        ctr[a] = ctr.get(a, 0) + 1
        ctr[b] = ctr.get(b, 0) + 1
        links.append((a, f"eth{ctr[a]}", b, f"eth{ctr[b]}"))
    return links


def test_central_is_inter_router_trunk():
    """En una red de 2 sitios, el central es el switch del troncal entre routers,
    NO el switch de acceso con más hosts."""
    res = compute_central_link(_empresa_links(), persist=False)
    assert res is not None
    assert res["central_switch"] == "s2"
    assert res["method"] == "inter_router_betweenness"
    assert set(res["trunk_link"]) <= {"s2", "r1", "r2"}


def test_shaping_port_points_to_hosts_side():
    """El puerto de shaping primario egresa hacia el lado con MÁS hosts (r2)."""
    res = compute_central_link(_empresa_links(), persist=False)
    sp = res["shaping_port"]
    assert sp.startswith("s2-")
    # 4 hosts detrás de r2, 0 detrás de r1.
    assert res["hosts_behind"][sp] == 4
    assert res["neighbors"][sp] == "r2"


def test_single_router_falls_back_to_global():
    """Con un solo router se usa betweenness global (sin troncal inter-router)."""
    links = [
        ("r1", "eth1", "s1", "eth1"),
        ("s1", "eth2", "h1", "eth1"),
        ("s1", "eth3", "h2", "eth1"),
        ("s1", "eth4", "srv1", "eth1"),
    ]
    res = compute_central_link(links, persist=False)
    assert res is not None
    assert res["method"] == "global_betweenness"
    assert res["central_switch"] == "s1"
