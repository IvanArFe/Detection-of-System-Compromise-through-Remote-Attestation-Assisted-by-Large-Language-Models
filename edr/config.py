"""Configuración central del EDR.

Todo se lee del entorno con un valor por defecto seguro, de modo que el sistema
arranca sin configurar nada pero se puede ajustar sin tocar código.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Raíz del proyecto: dos niveles arriba de este fichero (edr/config.py).
BASE_DIR = Path(__file__).resolve().parent.parent

# El .env se carga AQUÍ, antes de leer ninguna variable. Los entrypoints también
# llaman a load_dotenv, pero lo hacen después de sus imports, así que para cuando
# se ejecuta ya se habría evaluado este módulo y los valores del .env se habrían
# ignorado en silencio. `load_dotenv` no pisa lo que ya exista en el entorno, de
# modo que una variable pasada en la línea de comandos sigue teniendo prioridad.
load_dotenv(BASE_DIR / ".env")

# ──────────────────────────────────────────────
# Rutas
# ──────────────────────────────────────────────

# Registro forense append-only. A diferencia del antiguo kernel_events.json,
# este fichero no se reescribe nunca: es un JSONL al que solo se añaden líneas.
EVENTS_JSONL = Path(os.environ.get("EDR_EVENTS_FILE", BASE_DIR / "events.jsonl"))

# Respaldo local cuando Supabase no está disponible. Que la base de datos remota
# esté caída no puede detener la detección.
DB_FALLBACK_JSONL = Path(os.environ.get("EDR_DB_FALLBACK", BASE_DIR / "detections_fallback.jsonl"))

# ──────────────────────────────────────────────
# Modo de operación
# ──────────────────────────────────────────────

MODE_DRY_RUN = "dry-run"
MODE_AUTONOMOUS = "autonomous"
VALID_MODES = (MODE_DRY_RUN, MODE_AUTONOMOUS)

# Por defecto NO se señaliza. El sistema razona, decide y valida, pero se queda a
# un paso de actuar. Pasar a `autonomous` es una decisión explícita del operador,
# no un descuido de configuración.
EDR_MODE = os.environ.get("EDR_MODE", MODE_DRY_RUN).strip().lower()
if EDR_MODE not in VALID_MODES:
    EDR_MODE = MODE_DRY_RUN

# ──────────────────────────────────────────────
# Salvaguardas de remediación
# ──────────────────────────────────────────────

VALID_ACTIONS = ("freeze", "kill")

# Procesos que nunca deben ser señalizados, pase lo que pase. No es una lista
# exhaustiva de "procesos importantes": es el mínimo cuya muerte deja la máquina
# inutilizable o corta el acceso remoto a quien está investigando el incidente.
_DEFAULT_PROTECTED = (
    "systemd", "init", "kthreadd", "sshd", "dockerd",
    "containerd", "dbus-daemon", "agetty", "login",
)
PROTECTED_COMMS = frozenset(
    c.strip() for c in os.environ.get(
        "EDR_PROTECTED_COMMS", ",".join(_DEFAULT_PROTECTED)
    ).split(",") if c.strip()
)

# Límite de tasa: un bucle de alucinación del modelo no puede arrasar la máquina.
RATE_LIMIT_MAX = int(os.environ.get("EDR_RATE_LIMIT_MAX", "3"))
RATE_LIMIT_WINDOW_S = float(os.environ.get("EDR_RATE_LIMIT_WINDOW", "300"))

# ──────────────────────────────────────────────
# Modelo y cliente de Ollama
# ──────────────────────────────────────────────

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("EDR_MODEL", "llama3.1:8b")

# (conexión, lectura). Sin timeout, un Ollama colgado cuelga el EDR para siempre.
# La lectura es generosa porque una primera inferencia en frío carga ~5 GB en VRAM.
LLM_CONNECT_TIMEOUT = float(os.environ.get("EDR_LLM_CONNECT_TIMEOUT", "5"))
LLM_READ_TIMEOUT = float(os.environ.get("EDR_LLM_READ_TIMEOUT", "180"))

# El contexto por defecto de Ollama 0.32 es 4096, y un prompt de ronda 2 con 50
# eventos execve ya ocupa ~2563 tokens solo en esa sección. Se sube a 8192 y
# además se recorta explícitamente en edr/prompts.py: medido que Ollama descarta
# la CABEZA del prompt y conserva la cola, así que un desbordamiento no rompe el
# veredicto pero borra la evidencia en silencio.
LLM_NUM_CTX = int(os.environ.get("EDR_LLM_NUM_CTX", "8192"))
LLM_NUM_PREDICT = int(os.environ.get("EDR_LLM_NUM_PREDICT", "512"))

# Temperatura baja: las decisiones deben ser reproducibles. Si repetir el
# laboratorio da resultados distintos, la comparativa de modelos no vale nada.
LLM_TEMPERATURE = float(os.environ.get("EDR_LLM_TEMPERATURE", "0.1"))
LLM_TOP_P = float(os.environ.get("EDR_LLM_TOP_P", "0.9"))

# Sin esto, el modelo se descarga de VRAM entre ciclos de 20 s.
LLM_KEEP_ALIVE = os.environ.get("EDR_LLM_KEEP_ALIVE", "30m")

# ──────────────────────────────────────────────
# Presupuesto de contexto (edr/prompts.py)
# ──────────────────────────────────────────────

MAX_ALERTS = int(os.environ.get("EDR_MAX_ALERTS", "10"))
MAX_EXECVE = int(os.environ.get("EDR_MAX_EXECVE", "20"))
MAX_FDS = int(os.environ.get("EDR_MAX_FDS", "30"))
MAX_CONNECTIONS = int(os.environ.get("EDR_MAX_CONNECTIONS", "15"))
MAX_FIELD_CHARS = int(os.environ.get("EDR_MAX_FIELD_CHARS", "256"))
MAX_SECTION_CHARS = int(os.environ.get("EDR_MAX_SECTION_CHARS", "4000"))

# ──────────────────────────────────────────────
# Event store
# ──────────────────────────────────────────────

# Eventos retenidos en memoria. El JSONL conserva el histórico completo.
EVENT_CAP = int(os.environ.get("EDR_EVENT_CAP", "2000"))

# Tipos de evento conocidos. Se amplía en las fases 3 y 4.
KIND_MODULE_LOAD = "module_load"
KIND_EXECVE = "execve"

# ──────────────────────────────────────────────
# Triaje (edr/triage.py)
# ──────────────────────────────────────────────

# Puntuación a partir de la cual un proceso se escala al modelo. Con las
# ponderaciones actuales, una sola señal débil no basta y dos sí: es lo que evita
# que el uso legítimo de /tmp inunde el prompt.
TRIAGE_THRESHOLD = int(os.environ.get("EDR_TRIAGE_THRESHOLD", "50"))
