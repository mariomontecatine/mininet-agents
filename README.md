<h1 align="center">Mininet Agents</h1>

<p align="center">
  <b>A fully autonomous Network Operations Center driven by local LLMs.</b><br>
  Describe a network in plain English — it gets deployed, watched, diagnosed and defended.<br>
  No cloud, no API keys, no data ever leaving the machine.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Mininet-Open%20vSwitch-orange">
  <img src="https://img.shields.io/badge/LLM-Ollama%20%C2%B7%20Qwen2.5-000000">
  <img src="https://img.shields.io/badge/MCP-Model%20Context%20Protocol-8A2BE2">
  <img src="https://img.shields.io/badge/License-MIT-green">
</p>

---

## 0) Plain summary

Network management is still anchored to the *human-in-the-loop* paradigm: someone
reads the telemetry, someone approves the change, someone runs the mitigation.
Handing that job to a cloud LLM would mean handing over topologies, credentials
and keys along with it.

This project is the other option. A concurrent multi-agent system runs **entirely
on local, open-weight models** and closes the full NOC loop — *observe → analyse →
decide → act* — over an emulated corporate network. It deploys topologies written
in natural language, injects realistic traffic and attacks, detects congestion and
anomalies from live telemetry, and applies dynamic QoS and security
countermeasures on its own. Everything is orchestrated from a web dashboard, and
the model talks to the network through a standard **Model Context Protocol**
server rather than an ad-hoc integration.

Built as a Telecommunications Engineering final-year project (TFG) at the
University of Granada.

---

## 1) The loop

```
 ┌───────────────────────────────────────────────────────────────────┐
 │  INTERFACE   dashboard/ (Flask + Chart.js)   mcp_server/ (MCP)    │
 │              noc_analyst — natural-language reports & Q&A         │
 ├───────────────────────────────────────────────────────────────────┤
 │  DECISION    resolver_agent (reactive QoS)   qos_intent (declar.) │
 │              failover (high availability)    central_link         │
 ├───────────────────────────────────────────────────────────────────┤
 │  OBSERVATION monitor_agent (telemetry + heuristics)   sflow       │
 │              traffic_identifier                                   │
 ├───────────────────────────────────────────────────────────────────┤
 │  GENERATION  deploy_agent (topology)   traffic   attack_tool      │
 │              topology (live map)       voip_test / rtp_tool       │
 ├───────────────────────────────────────────────────────────────────┤
 │  SUBSTRATE   Mininet VM + Open vSwitch, reached over SSH / tmux   │
 └───────────────────────────────────────────────────────────────────┘
```

An adaptive cycle (5 s under alert → 30 s when the network is clean) polls OVS
counters and sFlow flows, feeds an aggregated digest to the model, and escalates
or de-escalates countermeasures: `SHAPING → POLICING → BLOCK`, scoped to a single
port and protocol.

---

## 2) What it actually does

| | |
|---|---|
| **Zero-touch deployment** | A 7B model turns *"a campus with two routers, a DMZ and a VoIP server"* into a validated topology, an IPAM plan, BFS-computed static routes and running services. |
| **Real telemetry** | An sFlow v5 collector written from scratch (stdlib only, no `sflowtool`), plus OVS interface counters over a persistent SSH channel. |
| **Anomaly detection** | Fan-in / fan-out / volume heuristics with per-port EMA baselining, correlated against injected ground truth. |
| **Autonomous mitigation** | Linux `tc` (HTB / TBF / police) and OpenFlow drops, chosen by the LLM and applied per protocol. |
| **Intent-based QoS** | Plain-English bandwidth intents (*"prioritise calls over downloads"*) translated into an enforceable QoS plan. |
| **VoIP verification** | A real G.711 RTP call with RFC 3550 jitter and E-model MOS — the before/after audio is playable in the dashboard. |
| **Conversational analyst** | A read-only agent that explains the network state in natural language, grounded strictly in telemetry. |
| **MCP server** | 13 tools, 7 resources and 2 prompts — any MCP client can drive the network. |

---

## 3) Results

Measured on the test platform (CPU-only, no GPU):

| Objective | Result |
|---|---|
| Topologies generated from text | **5 / 5** complex corporate networks |
| Attack detection sensitivity | **86 %** over 146 injected attacks (**92.6 %** in declared scope) |
| Median detection latency | **13.9 s** |
| Mitigations decided by the LLM | **84.8 %** |
| Natural-language intent → QoS accuracy | **95.2 %** |
| VoIP under extreme congestion | packet loss **49.83 % → 0.00 %**, MOS **1.00 → 4.38** |

---

## 4) Repository layout

**4.1 `agents/` — the multi-agent core (17 modules)**

| Module | Role |
|---|---|
| `deploy_agent.py` | Natural language → topology JSON → deployed Mininet network, with a validate-and-repair loop |
| `topology.py` | Live topology extraction and interactive map |
| `traffic.py` · `attack_tool.py` | Background traffic and synthetic anomaly injection (ground truth) |
| `sflow.py` | Hand-rolled sFlow v5 agent + collector |
| `monitor_agent.py` | Telemetry collection, heuristics, per-cycle AI report |
| `resolver_agent.py` | Reactive mitigation and the escalation chain |
| `qos_intent.py` · `apps_catalog.py` | Declarative, intent-based QoS |
| `failover.py` · `central_link.py` | Server redundancy and trunk-link selection |
| `telemetry_digest.py` | Aggregates telemetry into a context a small model can reason about |
| `noc_analyst.py` | Conversational, read-only NOC analyst |
| `rtp_tool.py` · `voip_test.py` | End-to-end VoIP quality experiment |
| `attack_report.py` · `traffic_identifier.py` | Detection scoring and per-host traffic profiling |

**4.2 `supervisor.py`** — the NOC loop: startup, four concurrent collector
threads, a fast flow-watcher that acts between cycles, and graceful shutdown.

**4.3 `dashboard/`** — Flask backend (39 routes) and a single-page UI with 26
panels: live topology, flows, protocol mix, QoS timeline, security scorecard,
audit log, the analyst chat and the VoIP player.

**4.4 `mcp_server/`** — the network's capabilities published as a standard MCP
contract (read-only mode available via `MCP_READ_ONLY`).

**4.5 `utils/`** — centralised configuration (every threshold documented with the
measurement that justifies it) and the persistent SSH/tmux transport.

**4.6 `tests/`** — 128 automated tests across 9 files, plus isolated probes.

**4.7 `tools/`** — experiment drivers that produce the evaluation tables.

---

## 5) Running it

Requires a Mininet VM reachable over SSH (aliased as `mininet` in `~/.ssh/config`)
and [Ollama](https://ollama.com) on the host.

```bash
pip install -r requirements.txt
ollama pull qwen2.5:3b && ollama pull qwen2.5:7b

python supervisor.py          # starts the NOC loop + dashboard on :5000
```

The MCP server can also run standalone:

```bash
python -m mcp_server.server                                # stdio
python -m mcp_server.server --transport streamable-http    # network, :5001
```

---

## 6) License

MIT — see [LICENSE](LICENSE).
