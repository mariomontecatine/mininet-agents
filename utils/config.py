# ============================================================
# config.py — Configuración centralizada del sistema NOC
# ============================================================

# --- Modelos LLM (Ollama) ---
MODEL_MONITOR  = "qwen2.5:3b"   # análisis de telemetría (ciclo rápido, modelo ligero)
MODEL_DEPLOY   = "qwen2.5:7b"   # diseño de topología (solo al arrancar)
MODEL_RESOLVER = "qwen2.5:3b"   # decisiones de QoS/seguridad

# --- Ciclo NOC (segundos) ---
INTERVALO_MIN   = 5    # modo alerta activa
INTERVALO_BASE  = 10   # condiciones normales con restricciones activas
INTERVALO_MAX   = 30   # red completamente estable (sin alertas ni restricciones)
PASO_AMPLIACION = 5    # incremento por ciclo cuando la red está limpia

# --- Cadencia de tareas periódicas ---
CICLOS_ENTRE_RAFAGAS = 4   # inyectar tráfico realista cada N ciclos
CICLOS_PARA_RELAJAR  = 3   # ciclos limpios consecutivos para bajar un nivel de QoS

# --- Umbrales de telemetría ---
UMBRAL_TRAFICO_BYTES = 10 * 1024 * 1024   # 10 MB/ciclo → dispara alerta de tráfico intenso
TASA_POLICING_MBPS   = 20                  # límite por defecto en POLICING y SHAPING

# --- Tráfico bulk (simulación de usuarios reales) ---
DURACION_BULK        = 35    # segundos de duración de cada ráfaga iperf
ESPERA_POST_BULK     = 25    # segundos de margen tras lanzar los clientes

# --- Auditoría / log ---
LOG_MAX_BYTES    = 1 * 1024 * 1024   # 1 MB por fichero antes de rotar
LOG_BACKUP_COUNT = 5                  # noc_audit.log.1 … noc_audit.log.5

# --- Métricas históricas ---
METRICS_MAX_ENTRIES = 500   # entradas máximas en metrics_history.json (~83 min a 10s/ciclo)

# --- Dashboard web ---
DASHBOARD_PORT = 5000
