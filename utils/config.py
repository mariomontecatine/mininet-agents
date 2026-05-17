# ============================================================
# config.py — Configuración centralizada del sistema NOC
# ============================================================

# --- Modelos LLM (Ollama) ---
MODEL_MONITOR = "qwen2.5:3b"  # análisis de telemetría (ciclo rápido, modelo ligero)
MODEL_DEPLOY = "qwen2.5:3b"  # diseño de topología (solo al arrancar)
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
DEPLOY_LLM_TIMEOUT = 90  # segundos máx por llamada al LLM de despliegue (solo al arrancar)

# --- Tráfico bulk (simulación de usuarios reales) ---
DURACION_BULK = 35  # segundos de duración de cada ráfaga iperf
ESPERA_POST_BULK = 25  # segundos de margen tras lanzar los clientes

# --- Auditoría / log ---
LOG_MAX_BYTES = 1 * 1024 * 1024  # 1 MB por fichero antes de rotar
LOG_BACKUP_COUNT = 5  # noc_audit.log.1 … noc_audit.log.5

# --- Métricas históricas ---
METRICS_MAX_ENTRIES = (
    500  # entradas máximas en metrics_history.json (~83 min a 10s/ciclo)
)

# --- Dashboard web ---
DASHBOARD_PORT = 5000

# --- Inyección de anomalías (motor de ataques sintéticos) ---
ANOMALY_PROBABILITY = 0.30  # prob. por ciclo NOC de inyectar un ataque
ANOMALY_MIN_DURATION = 30  # duración mínima de un ataque (s)
ANOMALY_MAX_DURATION = 60  # duración máxima de un ataque (s)
ANOMALY_COOLDOWN = 90  # tras un ataque, descanso antes de poder inyectar otro
ANOMALY_RNG_SEED = None  # entero → resultados reproducibles; None → estocástico

# Umbrales de las heurísticas de anomalía sobre flujos sFlow
FAN_OUT_THRESHOLD = 5  # ≥N destinos distintos desde 1 origen → port scan
FAN_IN_THRESHOLD = 5  # ≥N orígenes simultáneos hacia 1 destino → DDoS (5 para evitar FP de tráfico cliente→servidor legítimo)
FAN_IN_BYTES_THRESHOLD = 50 * 1024 * 1024  # 50 MB combinados en ventana
SURGE_BYTES_THRESHOLD = 120 * 1024 * 1024  # 120 MB en un solo flujo → DoS volumétrico
# Punto medio entre el 50 MB original (ruido por bulk iperf legítimo) y el
# 250 MB de d0df926 (perdía ataques de 30 s a 150 Mbps cuando la muestra
# sFlow caía a caballo del ataque). Con ventana sFlow de 20 s, 120 MB pasa
# con ~6 s de ataque a 150 Mbps; el bulk legítimo (100-160 MB) sigue rozando
# pero no abre las puertas a todo.

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
BASELINE_ALERT_K = 4.0  # delta actual > k × EMA → considerar anomalía
BASELINE_WARMUP = 3  # ciclos de aprendizaje antes de empezar a alertar
