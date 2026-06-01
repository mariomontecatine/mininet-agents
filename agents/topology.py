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
#   __SERVICES__  → JSON {srv: {type, ip, port}} para el primer pintado
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
    #cy { width: 100vw; height: 100vh; position: relative; }
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
    #legend h3:not(:first-child) { margin-top: 10px; }
    .li { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; color: #d9d9d9; }
    .li img { width: 18px; height: 18px; object-fit: contain; }
    .sw { width: 14px; height: 4px; border-radius: 2px; flex: none; }
    .dot { width: 11px; height: 11px; border-radius: 50%; flex: none; }
    /* ── Panel vivo (arriba a la izquierda) ── */
    #live {
      position: fixed; top: 16px; left: 16px;
      background: #1c1f24; border: 1px solid #2d3035;
      border-radius: 3px; padding: 11px 13px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.4);
      font-size: 11px; color: #d9d9d9; min-width: 168px;
    }
    #live h3 { font-size: 10px; margin-bottom: 8px; color: #6e7177;
               letter-spacing: .08em; text-transform: uppercase; font-weight: 600;
               display: flex; align-items: center; gap: 6px; }
    #live .lv { display: flex; justify-content: space-between; gap: 14px;
                margin-bottom: 4px; }
    #live .lv b { font-variant-numeric: tabular-nums; }
    #live .pulse { width: 7px; height: 7px; border-radius: 50%; background: #3fb950;
                   box-shadow: 0 0 0 0 rgba(63,185,80,.6); animation: pl 1.8s infinite; }
    @keyframes pl { 0% { box-shadow: 0 0 0 0 rgba(63,185,80,.5); }
                    70% { box-shadow: 0 0 0 6px rgba(63,185,80,0); }
                    100% { box-shadow: 0 0 0 0 rgba(63,185,80,0); } }
    .fxbtn { background: #182a33; border: 1px solid #2d3035; color: #22d3ee;
             border-radius: 3px; font-size: 10px; padding: 1px 9px; cursor: pointer;
             letter-spacing: .06em; font-weight: 600; transition: color .15s, border-color .15s; }
    .fxbtn:hover { border-color: #22d3ee; }
    .fxbtn.off { color: #6e7177; }
  </style>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"
          crossorigin="anonymous"></script>
</head>
<body>
  <div id="cy"></div>
  <button id="fit-btn" onclick="cy.fit(undefined,60)" title="Restablecer vista">⊡ Restablecer vista</button>
  <div id="live">
    <h3><span class="pulse"></span>En vivo</h3>
    <div class="lv"><span>Flujos activos</span><b id="lv-flows">—</b></div>
    <div class="lv"><span>Restricciones QoS</span><b id="lv-qos">—</b></div>
    <div class="lv"><span>Troncal</span><b id="lv-trunk">—</b></div>
    <div class="lv" style="color:#6e7177"><span>Actualizado</span><b id="lv-ts">—</b></div>
    <div class="lv" style="margin-top:7px;border-top:1px solid #2d3035;padding-top:8px">
      <span>Animar flujos</span>
      <button id="fx-toggle" class="fxbtn" onclick="toggleFx()">ON</button>
    </div>
  </div>
  <div id="legend">
    <h3>Nodos</h3>
    <div class="li"><img src="__ICON_ROUTER__" alt="">Router</div>
    <div class="li"><img src="__ICON_SWITCH__" alt="">Switch</div>
    <div class="li"><img src="__ICON_SERVER__" alt="">Servidor</div>
    <div class="li"><img src="__ICON_HOST__"   alt="">Host</div>
    <h3>Estado vivo</h3>
    <div class="li"><span class="sw" style="background:linear-gradient(90deg,#aab7b8,#f0883e,#f85149)"></span>Carga del enlace</div>
    <div class="li"><span class="sw" style="background:#f85149"></span>Pérdidas (drops)</div>
    <div class="li"><span class="sw" style="background:#f0883e;background-image:repeating-linear-gradient(90deg,#f0883e 0 4px,transparent 4px 7px)"></span>QoS aplicada</div>
    <div class="li"><span class="sw" style="background:#e3b341;height:6px"></span>Troncal central</div>
    <div class="li"><span class="dot" style="background:rgba(63,185,80,.45)"></span>Host activo</div>
    <div class="li"><span class="dot" style="background:#22d3ee;width:8px;height:8px"></span>Flujo activo</div>
  </div>
  <script>
    var SERVICES = __SERVICES__;   // {srv1: {type, ip, port}, ...} — primer pintado

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
            'text-wrap': 'wrap',
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
        /* Anillo de color por tipo de servicio (Nivel 0) */
        {
          selector: 'node[svcColor]',
          style: {
            'border-width': 3,
            'border-color': 'data(svcColor)',
            'border-opacity': 1,
            'background-color': 'data(svcColor)',
            'background-opacity': 0.10,
            'shape': 'round-rectangle',
          }
        },
        /* Halo verde en extremos de flujos activos (Nivel 1) */
        {
          selector: 'node[flowAct > 0]',
          style: {
            'overlay-color': '#3fb950',
            'overlay-opacity': 'mapData(flowAct, 0, 1, 0.06, 0.34)',
            'overlay-padding': 'mapData(flowAct, 0, 1, 4, 13)',
          }
        },
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
        /* Carga del enlace: grosor + color gris→naranja→rojo (Nivel 1) */
        {
          selector: 'edge[load > 0]',
          style: {
            'width': 'mapData(load, 0, 1, 2.5, 9)',
            'line-color': 'mapData(load, 0, 1, #aab7b8, #f85149)',
          }
        },
        /* Drops: enlace rojo intenso */
        {
          selector: 'edge[drop > 0]',
          style: { 'line-color': '#f85149', 'line-style': 'dashed' }
        },
        /* Troncal central (cuello de botella) */
        {
          selector: 'edge[trunk > 0]',
          style: { 'line-color': '#e3b341', 'width': 6 }
        },
        /* QoS aplicada: discontinua naranja + etiqueta a media arista */
        {
          selector: 'edge[qos]',
          style: {
            'line-color': '#f0883e',
            'line-style': 'dashed',
            'label': 'data(qosLabel)',
            'text-rotation': 'autorotate',
            'color': '#f0883e',
            'font-size': '9px',
            'font-weight': 'bold',
            'text-background-color': '#1c1f24',
            'text-background-opacity': 1,
            'text-background-padding': '3px',
            'text-border-opacity': 0,
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

    // ═══════════════════════════════════════════════════════════════════════
    // CAPA VIVA — polling de las APIs del dashboard (mismo origen que el iframe)
    // ═══════════════════════════════════════════════════════════════════════

    // Índice puerto OVS → arista (p.ej. "s1-eth4" → arista s1↔srv3).
    // Las aristas ya llevan el nombre de interfaz en cada extremo.
    var portEdge = {};
    cy.edges().forEach(function(e) {
      var s = e.data('source'), t = e.data('target');
      var sl = e.data('sourceLabel'), tl = e.data('targetLabel');
      if (sl) portEdge[s + '-' + sl] = e;
      if (tl) portEdge[t + '-' + tl] = e;
    });

    var SVC_COLORS = {
      http: '#5794f2', http_alt: '#5794f2', https: '#3fb950', ssh: '#a371f7',
      dns: '#f0883e', sip: '#db61a2', rtp: '#e3b341', ftp: '#56d4dd',
      smtp: '#f85149', icmp: '#8b949e'
    };

    function applyServices(svc) {
      if (!svc) return;
      cy.batch(function() {
        cy.nodes('[type="server"]').forEach(function(n) {
          var info = svc[n.id()];
          if (info && info.type) {
            var t = String(info.type).toUpperCase();
            n.data('svc', t);
            n.data('svcColor', SVC_COLORS[info.type] || '#8b949e');
            n.data('label', n.id() + '\\n' + t);
          }
        });
      });
    }

    // Última muestra de /api/live-metrics (series de longitud 1 con limit=1).
    function applyMetrics(lm) {
      var ports = (lm && lm.ports) || {};
      // Sin puertos = arranque o lectura transitoria vacía: conservamos el
      // último heat pintado en vez de borrarlo (evita parpadeo de los enlaces).
      if (!Object.keys(ports).length) return;
      function last(arr) { return (arr && arr.length) ? arr[arr.length - 1] : 0; }
      var flat = {};
      Object.keys(ports).forEach(function(p) {
        flat[p] = { rx: last(ports[p].rx), tx: last(ports[p].tx), drop: last(ports[p].drop) };
      });
      var maxLoad = 1;
      var info = {};
      cy.edges().forEach(function(e) {
        var a = flat[e.data('source') + '-' + e.data('sourceLabel')] || {};
        var b = flat[e.data('target') + '-' + e.data('targetLabel')] || {};
        var load = Math.max((a.rx || 0) + (a.tx || 0), (b.rx || 0) + (b.tx || 0));
        var drop = (a.drop || 0) + (b.drop || 0);
        info[e.id()] = { load: load, drop: drop };
        if (load > maxLoad) maxLoad = load;
      });
      cy.batch(function() {
        cy.edges().forEach(function(e) {
          var d = info[e.id()];
          e.data('load', d.load > 0 ? d.load / maxLoad : 0);
          e.data('drop', d.drop > 0 ? 1 : 0);
        });
      });
    }

    // Restricciones QoS activas: recorre el historial y deja el último estado
    // por puerto. 'remove' lo limpia; 'apply'/'relax' lo mantienen.
    function activeQos(events) {
      var st = {};
      (events || []).forEach(function(ev) {
        var p = ev.port;
        if (!p) return;
        if (ev.event === 'remove') delete st[p];
        else st[p] = { action: ev.action, proto: ev.protocol };
      });
      return st;
    }

    function applyQos(events) {
      var st = activeQos(events);
      var count = 0;
      cy.batch(function() {
        cy.edges().forEach(function(e) { e.removeData('qos'); e.removeData('qosLabel'); });
        Object.keys(st).forEach(function(port) {
          var e = portEdge[port];
          if (!e) return;
          count++;
          var info = st[port];
          var lbl = '⚙ ' + (info.action || 'QoS');
          if (info.proto) lbl += ' ' + info.proto;
          e.data('qos', info.action || 'QoS');
          e.data('qosLabel', lbl);
        });
      });
      return count;
    }

    function applyTrunk(central) {
      var label = '—';
      cy.batch(function() {
        cy.edges().forEach(function(e) { e.removeData('trunk'); });
        if (central && central.trunk_link && central.trunk_link.length === 2) {
          var a = central.trunk_link[0], b = central.trunk_link[1];
          label = a + '–' + b;
          cy.edges().forEach(function(e) {
            var s = e.data('source'), t = e.data('target');
            if ((s === a && t === b) || (s === b && t === a)) e.data('trunk', 1);
          });
        }
      });
      return label;
    }

    function applyFlows(flows) {
      flows = flows || [];
      var maxB = 1;
      flows.forEach(function(f) { if ((f.bytes || 0) > maxB) maxB = f.bytes; });
      cy.batch(function() {
        cy.nodes().forEach(function(n) { n.data('flowAct', 0); });
        flows.forEach(function(f) {
          ['src_name', 'dst_name'].forEach(function(k) {
            var name = f[k];
            if (!name) return;
            var n = cy.getElementById(name);
            if (n && n.nonempty()) {
              n.data('flowAct', Math.max(n.data('flowAct') || 0, (f.bytes || 0) / maxB));
            }
          });
        });
      });
      return flows.length;
    }

    function _get(url, fallback) {
      return fetch(url, { cache: 'no-store' })
        .then(function(r) { return r.ok ? r.json() : fallback; })
        .catch(function() { return fallback; });
    }

    function refreshLive() {
      Promise.all([
        _get('/api/services', {}),
        _get('/api/live-metrics?limit=1', { ports: {} }),
        _get('/api/qos/history', []),
        _get('/api/central-link', {}),
        _get('/api/flows', { flows: [] }),
      ]).then(function(res) {
        var svc = res[0], lm = res[1], qos = res[2], cl = res[3], fl = res[4];
        applyServices(svc);
        applyMetrics(lm);
        var qn = applyQos(qos);
        var trunk = applyTrunk(cl && cl.central);
        var fn = applyFlows(fl && fl.flows);
        reconcileFlows(computeFlowPaths(fl && fl.flows));   // Nivel 2: rutas a animar
        document.getElementById('lv-flows').textContent = fn;
        document.getElementById('lv-qos').textContent = qn;
        document.getElementById('lv-trunk').textContent = trunk;
        document.getElementById('lv-ts').textContent =
          new Date().toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // NIVEL 2 — Flujos animados sobre su camino físico (partículas src→dst)
    // ═══════════════════════════════════════════════════════════════════════
    var fxEnabled = true;
    // Cada flujo (clave src→dst) guarda su propio estado de animación entre
    // refrescos. Las bolitas son partículas DISCRETAS que nacen en el origen y
    // viajan al destino: cuando la lista de /api/flows cambia, las que están en
    // vuelo terminan su trayecto y solo se dejan de generar nuevas — nada salta
    // ni se reinicia con cada actualización.
    var fxFlows = {};               // key -> {els, color, ratio, active, parts, lastSpawn}

    var FX_MAX_FLOWS = 24;          // nº máx de flujos animados a la vez (antes 8)
    var FX_FPS       = 30;          // las partículas no necesitan 60 fps
    var FX_FRAME_MS  = 1000 / FX_FPS;
    var FX_LIFETIME  = 4.5;         // segundos que tarda una bolita en cruzar la ruta (↑ = más lentas)
    var FX_TOTAL_CAP = 100;         // tope global de bolitas en vuelo (rendimiento)
    var _fxLast      = 0;
    var _panUntil    = 0;           // tiempo hasta el que aligeramos al panear/zoom

    // Canvas superpuesto al grafo (no captura ratón → arrastrar/zoom intactos).
    var fxCanvas = document.createElement('canvas');
    fxCanvas.style.cssText = 'position:absolute;left:0;top:0;pointer-events:none;z-index:6';
    document.getElementById('cy').appendChild(fxCanvas);
    var fxCtx = fxCanvas.getContext('2d');

    function resizeFx() {
      var c = document.getElementById('cy');
      var dpr = window.devicePixelRatio || 1;
      fxCanvas.width  = c.clientWidth  * dpr;
      fxCanvas.height = c.clientHeight * dpr;
      fxCanvas.style.width  = c.clientWidth  + 'px';
      fxCanvas.style.height = c.clientHeight + 'px';
      fxCtx.setTransform(dpr, 0, 0, dpr, 0, 0);  // dibujamos en píxeles CSS
    }
    window.addEventListener('resize', resizeFx);
    resizeFx();

    function toggleFx() {
      fxEnabled = !fxEnabled;
      var b = document.getElementById('fx-toggle');
      b.textContent = fxEnabled ? 'ON' : 'OFF';
      b.className = 'fxbtn' + (fxEnabled ? '' : ' off');
      if (!fxEnabled) fxCtx.clearRect(0, 0, fxCanvas.width, fxCanvas.height);
    }

    // Color de la partícula: el del servicio del extremo servidor, si lo hay.
    function flowColor(f) {
      var ends = [f.src_name, f.dst_name];
      for (var i = 0; i < ends.length; i++) {
        var n = ends[i] && cy.getElementById(ends[i]);
        if (n && n.nonempty() && n.data('svcColor')) return n.data('svcColor');
      }
      return '#22d3ee';  // cian por defecto (flujo host↔host)
    }

    // Resuelve el camino físico de cada flujo. /api/flows ya trae src_name/
    // dst_name como nombres de nodo; A* sobre el grafo da las aristas que
    // atraviesa (host→switch→…→switch→host). Top FX_MAX_FLOWS por volumen.
    function computeFlowPaths(flows) {
      flows = flows || [];
      var maxB = 1;
      flows.forEach(function(f) { if ((f.bytes || 0) > maxB) maxB = f.bytes; });
      var out = [];
      flows.slice(0, FX_MAX_FLOWS).forEach(function(f) {
        var s = f.src_name, d = f.dst_name;
        if (!s || !d || s === d) return;
        var sn = cy.getElementById(s), dn = cy.getElementById(d);
        if (sn.empty() || dn.empty()) return;
        var res = cy.elements().aStar({ root: sn, goal: dn, directed: false });
        if (!res.found) return;
        // Guardamos las REFERENCIAS de nodo (no los ids): así drawFx no hace
        // getElementById en cada frame, solo lee renderedPosition.
        var els = [];
        res.path.forEach(function(el) { if (el.isNode()) els.push(el); });
        if (els.length < 2) return;   // els[0]=origen … els[last]=destino
        out.push({ key: s + '>' + d, els: els,
                   ratio: (f.bytes || 0) / maxB, color: flowColor(f) });
      });
      return out;
    }

    // Reconcilia el conjunto deseado con el estado vivo: conserva la animación
    // de los flujos que siguen, da de alta los nuevos (sus bolitas nacerán en el
    // origen) y marca inactivos los que desaparecen (dejan de generar bolitas;
    // las que están en vuelo llegan a destino y se borran solas).
    function reconcileFlows(desired) {
      var seen = {};
      desired.forEach(function(fp) {
        seen[fp.key] = true;
        var ex = fxFlows[fp.key];
        if (ex) { ex.els = fp.els; ex.color = fp.color; ex.ratio = fp.ratio; ex.active = true; }
        else {
          fxFlows[fp.key] = { els: fp.els, color: fp.color, ratio: fp.ratio,
                              active: true, parts: [], lastSpawn: 0 };
        }
      });
      Object.keys(fxFlows).forEach(function(k) { if (!seen[k]) fxFlows[k].active = false; });
    }

    // Punto a la fracción frac∈[0,1] de la polilínea definida por los puntos.
    function pointAlong(pts, frac) {
      var segs = [], total = 0, i;
      for (i = 0; i < pts.length - 1; i++) {
        var dx = pts[i+1].x - pts[i].x, dy = pts[i+1].y - pts[i].y;
        var len = Math.sqrt(dx*dx + dy*dy);
        segs.push(len); total += len;
      }
      if (total === 0) return null;
      var target = frac * total, acc = 0;
      for (i = 0; i < segs.length; i++) {
        if (acc + segs[i] >= target) {
          var t = segs[i] === 0 ? 0 : (target - acc) / segs[i];
          return { x: pts[i].x + (pts[i+1].x - pts[i].x) * t,
                   y: pts[i].y + (pts[i+1].y - pts[i].y) * t };
        }
        acc += segs[i];
      }
      return pts[pts.length - 1];
    }

    // Mientras se panea/zoomea, marcamos una ventana corta para aligerar el
    // dibujado (sin halos) y que el arrastre no dé tirones.
    cy.on('viewport', function() { _panUntil = performance.now() + 100; });

    // Bucle de animación: lee renderedPosition cada frame (refleja pan/zoom).
    // Cada bolita es una partícula con su instante de nacimiento; su posición
    // depende solo de su propia edad → independiente de los refrescos, así que
    // un flujo que persiste nunca salta. Una bolita con edad≥1 llegó a destino.
    function drawFx(now) {
      requestAnimationFrame(drawFx);
      if (now - _fxLast < FX_FRAME_MS) return;   // throttle a FX_FPS
      _fxLast = now;
      fxCtx.clearRect(0, 0, fxCanvas.width, fxCanvas.height);
      if (!fxEnabled) return;
      var tsec = now / 1000;
      var panning = now < _panUntil;
      var keys = Object.keys(fxFlows);
      // total de bolitas en vuelo (para respetar el tope global)
      var total = 0;
      for (var a = 0; a < keys.length; a++) total += fxFlows[keys[a]].parts.length;
      for (var b = 0; b < keys.length; b++) {
        var f = fxFlows[keys[b]];
        // posiciones actuales de la ruta
        var pts = [], bad = false;
        for (var i = 0; i < f.els.length; i++) {
          var el = f.els[i];
          if (el.removed()) { bad = true; break; }
          pts.push(el.renderedPosition());
        }
        // generar una bolita nueva si el flujo sigue activo (cadencia ~ volumen)
        if (f.active && !bad && total < FX_TOTAL_CAP) {
          var interval = FX_LIFETIME * (0.18 + (1 - f.ratio) * 0.45);   // alto volumen → más juntas
          if (tsec - f.lastSpawn >= interval) { f.parts.push(tsec); f.lastSpawn = tsec; total++; }
        }
        var r = 2.3 + f.ratio * 2.2;
        var alive = [];
        for (var pi = 0; pi < f.parts.length; pi++) {
          var age = (tsec - f.parts[pi]) / FX_LIFETIME;
          if (age >= 1) continue;        // llegó a destino → desaparece
          alive.push(f.parts[pi]);
          if (bad || pts.length < 2) continue;
          var p = pointAlong(pts, age);
          if (!p) continue;
          if (!panning) {                // el halo se omite al panear
            fxCtx.globalAlpha = 0.16;
            fxCtx.beginPath(); fxCtx.arc(p.x, p.y, r * 2.0, 0, 6.2832);
            fxCtx.fillStyle = f.color; fxCtx.fill();
          }
          fxCtx.globalAlpha = 0.95;      // núcleo
          fxCtx.beginPath(); fxCtx.arc(p.x, p.y, r, 0, 6.2832);
          fxCtx.fillStyle = f.color; fxCtx.fill();
        }
        f.parts = alive;
        // flujo inactivo y ya sin bolitas en vuelo → se elimina del estado
        if (!f.active && f.parts.length === 0) delete fxFlows[keys[b]];
      }
      fxCtx.globalAlpha = 1;
    }
    requestAnimationFrame(drawFx);

    // Primer pintado con los servicios horneados, luego polling continuo.
    applyServices(SERVICES);
    refreshLive();
    setInterval(refreshLive, 3000);

    // Ctrl+rueda = zoom suave; rueda sola = scroll de la página padre
    var _zoomTarget   = cy.zoom();
    var _zoomCenterX  = 0;
    var _zoomCenterY  = 0;
    var _zoomRafId    = null;

    function _animateZoom() {
      var current = cy.zoom();
      var diff    = _zoomTarget - current;
      if (Math.abs(diff) < 0.001) {
        cy.zoom({ level: _zoomTarget, renderedPosition: { x: _zoomCenterX, y: _zoomCenterY } });
        _zoomRafId = null;
        return;
      }
      cy.zoom({ level: current + diff * 0.28, renderedPosition: { x: _zoomCenterX, y: _zoomCenterY } });
      _zoomRafId = requestAnimationFrame(_animateZoom);
    }

    document.getElementById('cy').addEventListener('wheel', function(e) {
      if (e.ctrlKey) {
        e.preventDefault();
        var factor = e.deltaY < 0 ? 1.12 : 0.89;
        _zoomTarget  = Math.min(cy.maxZoom(), Math.max(cy.minZoom(), _zoomTarget * factor));
        _zoomCenterX = e.offsetX;
        _zoomCenterY = e.offsetY;
        if (!_zoomRafId) _zoomRafId = requestAnimationFrame(_animateZoom);
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


def draw_topology(links, output_file="topologia_interactiva.html",
                  services=None, out_dir=None):
    """Genera un HTML estático con Cytoscape.js a partir de los enlaces de Mininet.

    links:    lista de tuplas (node1, intf1, node2, intf2)
    services: dict {srv: {type,...}} horneado para el primer pintado. Si es
              None se lee de tmp/server_services.json (comportamiento normal).
    out_dir:  directorio de salida (por defecto tmp/). Permite re-renderizar la
              topología de un saved_run sobre su propia carpeta.
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

    # Servicios horneados para el primer pintado (antes de que el polling
    # cliente refresque vía /api/services). Si no nos los pasan, se leen de
    # tmp/server_services.json; si tampoco existe, queda {} y la capa viva lo
    # rellena en cuanto el supervisor lo persista.
    if services is None:
        services = {}
        try:
            svc_path = os.path.join(TMP_DIR, "server_services.json")
            if os.path.exists(svc_path):
                with open(svc_path, encoding="utf-8") as f:
                    services = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[VISUALIZADOR] No se pudieron hornear los servicios: {e}")

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
        .replace("__SERVICES__", json.dumps(services, ensure_ascii=False))
        .replace("__ICON_ROUTER__", icons["router"])
        .replace("__ICON_SWITCH__", icons["switch"])
        .replace("__ICON_SERVER__", icons["server"])
        .replace("__ICON_HOST__",   icons["host"])
    )

    ruta_guardado = os.path.join(out_dir or TMP_DIR, output_file)
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
