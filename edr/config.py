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
# Event store
# ──────────────────────────────────────────────

# Eventos retenidos en memoria. El JSONL conserva el histórico completo.
EVENT_CAP = int(os.environ.get("EDR_EVENT_CAP", "2000"))

# Tipos de evento conocidos. Se amplía en las fases 3 y 4.
KIND_MODULE_LOAD = "module_load"
KIND_EXECVE = "execve"
