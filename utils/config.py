# ============================================================
# config.py — Configuración centralizada del sistema NOC
# ============================================================

# --- Modelos LLM (Ollama) ---
MODEL_MONITOR = "qwen2.5:3b"  # análisis de telemetría (ciclo rápido, modelo ligero)
MODEL_DEPLOY = "qwen2.5:7b"  # diseño de topología (solo al arrancar)
MODEL_RESOLVER = "qwen2.5:3b"  # decisiones de QoS/seguridad

# --- Ciclo NOC (segundos) ---
INTERVALO_MIN = 5  # modo alerta activa
INTERVALO_BASE = 10  # condiciones normales con restricciones activas
INTERVALO_MAX = 30  # red completamente estable (sin alertas ni restricciones)
PASO_AMPLIACION = 5  # incremento por ciclo cuando la red está limpia

# --- Cadencia de tareas periódicas ---
CICLOS_ENTRE_RAFAGAS = 4  # inyectar tráfico realista cada N ciclos
CICLOS_PARA_DESESCALAR = 4  # ciclos limpios consecutivos para bajar un nivel de QoS

# --- Umbrales de telemetría ---
UMBRAL_TRAFICO_BYTES = (
    200 * 1024 * 1024
)  # 200 MB/ciclo → solo flag visual; el resolver ya no actúa sobre [TRÁFICO INTENSO]
TASA_POLICING_MBPS = 20  # límite por defecto en POLICING y SHAPING

# --- Resolver: split LLM/política ---
RESOLVER_LLM_TOPK = 3  # nº de alertas más críticas que decide el LLM; el resto va a política por defecto
RESOLVER_LLM_TIMEOUT = 45  # segundos máx por llamada al LLM antes de hacer fallback

# --- QoS por intent (chat del dashboard) ---
# Modelo usado para traducir NL→plan QoS. qwen2.5:3b es flojo con tool calling;
# qwen2.5:7b acierta mucho más (a costa de tardar más). Para una prueba de
# concepto donde quieres ver la precisión real del LLM, usa 7b.
MODEL_QOS_INTENT = "qwen2.5:7b"
# Timeout generoso: priorizamos que el LLM responda sobre la velocidad. El
# fallback heurístico solo salta si el modelo agota este tiempo o devuelve algo
# imposible de parsear.
QOS_INTENT_LLM_TIMEOUT = 600
# Si True, NUNCA se usa el fallback heurístico: si el LLM falla, se devuelve un
# error claro en vez de adivinar por keywords. Útil para evaluar el LLM puro.
QOS_INTENT_LLM_ONLY = False

# --- Servidor MCP (Model Context Protocol) ---
# Expone las capacidades de QoS y la telemetría como tools/resources estándar,
# consumibles por cualquier cliente MCP (Inspector, editores, o el analista de
# abajo). Puerto propio para no chocar con el dashboard.
MCP_SERVER_PORT = 5001
# Si True, las tools que ESCRIBEN (aplicar/limpiar QoS) no se registran: el
# servidor queda de solo consulta. Útil para demostrarlo sin riesgo.
MCP_READ_ONLY = False

# --- Tráfico bulk (simulación de usuarios reales) ---
DURACION_BULK = 35  # segundos de duración de cada ráfaga iperf
ESPERA_POST_BULK = 25  # segundos de margen tras lanzar los clientes

# --- Puertos estándar por servicio (referencia central) ---
# Lo consultan traffic (probes sintéticos) y las herramientas QoS por
# protocolo (resolver_agent.apply_*).
SERVICE_PORTS = {
    "http": 80,
    "https": 443,
    "http_alt": 8080,  # el python -m http.server escucha aquí en los srv*
    "dns": 53,
    "ssh": 22,
    "ftp": 21,
    "sip": 5060,
    "rtp": 16384,  # puerto RTP "pinneado" (media de voz/vídeo en tiempo real)
    "smtp": 25,
}

# --- Definición completa de cada servicio (para QoS por protocolo) ---
# ip_proto sigue los números IANA (1=ICMP, 6=TCP, 17=UDP).
# transport es la palabra clave OpenFlow ('tcp', 'udp', 'icmp').
SERVICE_DEFS = {
    "http": {"ip_proto": 6, "dport": 80, "transport": "tcp"},
    "http_alt": {"ip_proto": 6, "dport": 8080, "transport": "tcp"},
    "https": {"ip_proto": 6, "dport": 443, "transport": "tcp"},
    "dns": {"ip_proto": 17, "dport": 53, "transport": "udp"},
    "ssh": {"ip_proto": 6, "dport": 22, "transport": "tcp"},
    "sip": {"ip_proto": 17, "dport": 5060, "transport": "udp"},
    "rtp": {"ip_proto": 17, "dport": 16384, "transport": "udp"},
    "ftp": {"ip_proto": 6, "dport": 21, "transport": "tcp"},
    "smtp": {"ip_proto": 6, "dport": 25, "transport": "tcp"},
    "icmp": {"ip_proto": 1, "dport": None, "transport": "icmp"},
}

# Asignación cíclica de tipos a srv1, srv2, srv3… cuando el intent no
# especifica server_types explícitamente. Cubre los servicios "interesantes"
# para demos de red empresarial / campus.
DEFAULT_SERVER_TYPE_ROTATION = ("http", "dns", "ssh", "sip")

# --- Auditoría / log ---
LOG_MAX_BYTES = 1 * 1024 * 1024  # 1 MB por fichero antes de rotar
LOG_BACKUP_COUNT = 5  # noc_audit.log.1 … noc_audit.log.5

# --- Métricas históricas ---
METRICS_MAX_ENTRIES = (
    500  # entradas máximas en metrics_history.json (~83 min a 10s/ciclo)
)

# --- Dashboard web ---
DASHBOARD_PORT = 5000

# --- Failover (redundancia primario / secundario) ---
FAILOVER_PROBE_TIMEOUT = 2  # segundos para la sonda TCP de salud
FAILOVER_FAIL_THRESHOLD = 1  # sondas consecutivas fallidas → declarar servidor caído
FAILOVER_POLL_INTERVAL = (
    2  # segundos entre sondas (hilo dedicado, no atado al ciclo NOC)
)

# --- Inyección de anomalías (motor de ataques sintéticos) ---
ANOMALY_PROBABILITY = 0.30  # prob. por ciclo NOC de inyectar un ataque
ANOMALY_MIN_DURATION = 30  # duración mínima de un ataque (s)
ANOMALY_MAX_DURATION = 60  # duración máxima de un ataque (s)
ANOMALY_COOLDOWN = 90  # tras un ataque, descanso antes de poder inyectar otro
ANOMALY_RNG_SEED = None  # entero → resultados reproducibles; None → estocástico

# Umbrales de las heurísticas de anomalía sobre flujos sFlow
FAN_OUT_THRESHOLD = 12  # ≥N destinos distintos desde 1 origen → port scan.
FAN_OUT_SUBNETS_THRESHOLD = 2  # ≥N subredes /24 distintas → confirma scan
FAN_IN_THRESHOLD = 6  # ≥N orígenes simultáneos hacia 1 destino → DDoS
FAN_IN_BYTES_THRESHOLD = 12 * 1024 * 1024  # 12 MB combinados en ventana sFlow
# Calibrado para reducir falsos positivos: el bulk legítimo observado llega a
# ~3.8 MB de fan-in (2 srcs) y ~2.7 MB con 5 srcs concurrentes. Con threshold
# de 12 MB + multiplicador de rol servidor (5×) el floor queda en 60 MB hacia
# un srv*, separando holgadamente el tráfico de usuarios reales de los ataques
# (DDoS hping3 más intenso → 150-300 MB agregados hacia la víctima).
SURGE_BYTES_THRESHOLD = 10 * 1024 * 1024  # 10 MB en un solo flujo → DoS volumétrico
# RECALIBRADO (medido en la VM real, no teórico): el DoS hping3 single-source
# (-i u50 -d 1400) NO alcanza los 25-40 MB/ventana que se asumían — en esta VM
# (WSL2) rinde ~12-16 MB en la ventana sFlow de 20 s, con pico observado de
# 15.75 MB. El umbral previo de 20 MB lo dejaba SIEMPRE por debajo → 0 DoS
# detectados. El flujo único legítimo más grande medido es ~1.5 MB (bulk hasta
# ~2.5-3.8 MB), así que 10 MB separa limpiamente: ~4× sobre el legítimo y por
# debajo del pico DoS, que cruza el umbral en ≥2 ventanas consecutivas (basta
# para la confirmación N=2 del watcher).

# --- Capa A: multiplicadores por rol de puerto ---
# El detector aplica el umbral base × multiplier según rol topológico del puerto.
# Un uplink al router agrega ~20x el tráfico de un host hoja; un puerto-servidor ~5x.
PORT_ROLE_MULTIPLIER = {
    "host": 1.0,  # puerto que conecta un h*: línea base
    "server": 5.0,  # puerto que conecta un srv*: agrega N clientes
    "trunk": 20.0,  # uplink switch↔switch o switch↔router
}

# --- Capa C: baseline adaptativo (EMA por puerto) ---
BASELINE_EMA_ALPHA = 0.25  # peso del valor actual en la EMA. ~4-5 ciclos efectivos.
BASELINE_ALERT_K = 6.0  # delta actual > k × EMA → considerar anomalía. 6× evita
# falsos positivos por picos transitorios del bulk iperf.
BASELINE_WARMUP = 3  # ciclos de aprendizaje antes de empezar a alertar
