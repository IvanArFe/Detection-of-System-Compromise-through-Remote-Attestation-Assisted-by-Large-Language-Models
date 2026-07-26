#!/usr/bin/env bash
#
# Comprobaciones previas al arranque del EDR.
# Responde en un solo comando a la pregunta "¿por qué no arranca?".
#
#   bash scripts/preflight.sh
#
# Sale con código 1 si alguna comprobación crítica falla.

set -uo pipefail   # sin -e a propósito: queremos ejecutar TODAS las comprobaciones

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$BASE_DIR/venv/bin/python3"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
MODEL="${EDR_MODEL:-llama3.1:8b}"

FAILED=0
ok()   { printf '  \033[32m[ OK ]\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m[WARN]\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '         → %s\n' "$2"; FAILED=1; }

echo
echo "Preflight del EDR — $BASE_DIR"

# ─────────────────────────────────────────────────────────────
echo
echo "Python y dependencias"
# ─────────────────────────────────────────────────────────────
if [[ -x "$VENV_PY" ]]; then
    ok "venv presente ($("$VENV_PY" --version 2>&1))"

    for mod in mcp requests dotenv supabase; do
        if "$VENV_PY" -c "import $mod" 2>/dev/null; then
            ok "módulo '$mod' importable"
        else
            bad "módulo '$mod' NO importable" "source venv/bin/activate && pip install -r requirements.txt"
        fi
    done

    # bcc no se instala con pip: es un paquete del sistema enlazado al venv.
    if "$VENV_PY" -c "import bcc" 2>/dev/null; then
        ok "módulo 'bcc' importable desde el venv"
    else
        bad "módulo 'bcc' NO importable desde el venv" \
            "sudo apt install python3-bpfcc y enlaza /usr/lib/python3/dist-packages/bcc al site-packages del venv"
    fi
else
    bad "no existe $VENV_PY" "python3 -m venv venv && venv/bin/pip install -r requirements.txt"
fi

# ─────────────────────────────────────────────────────────────
echo
echo "Kernel y eBPF"
# ─────────────────────────────────────────────────────────────
echo "  [INFO] kernel $(uname -r)"

if [[ -r /sys/kernel/btf/vmlinux ]]; then
    ok "BTF disponible (BCC puede compilar sin cabeceras del kernel)"
else
    warn "sin BTF en /sys/kernel/btf/vmlinux" \
         "BCC necesitará cabeceras: sudo modprobe kheaders"
fi

if mountpoint -q /sys/kernel/tracing 2>/dev/null; then
    ok "tracefs montado en /sys/kernel/tracing"
else
    warn "tracefs no montado" "sudo mount -t tracefs nodev /sys/kernel/tracing"
fi

if [[ -d /lib/modules/$(uname -r)/build ]]; then
    ok "cabeceras del kernel presentes"
else
    warn "sin cabeceras del kernel (normal en WSL2)" \
         "No podrás compilar un módulo propio aquí; usa la VM del laboratorio"
fi

if [[ $EUID -eq 0 ]]; then
    ok "ejecutando como root"
else
    warn "no eres root" "el EDR necesita root: sudo venv/bin/python3 orchestrator.py"
fi

# ─────────────────────────────────────────────────────────────
echo
echo "Ollama"
# ─────────────────────────────────────────────────────────────
TAGS="$(curl -s --max-time 5 "$OLLAMA_URL/api/tags" 2>/dev/null)"
if [[ -n "$TAGS" ]]; then
    ok "Ollama responde en $OLLAMA_URL"

    if grep -q "\"$MODEL\"" <<<"$TAGS"; then
        ok "modelo '$MODEL' descargado"
    else
        bad "modelo '$MODEL' NO descargado" "docker exec ollama ollama pull $MODEL"
    fi

    # Un modelo cargado en CPU hace el bucle de decisión inutilizablemente lento.
    if command -v docker >/dev/null 2>&1; then
        PS_OUT="$(docker exec ollama ollama ps 2>/dev/null)"
        if grep -q "CPU" <<<"$PS_OUT"; then
            warn "hay un modelo corriendo en CPU, no en GPU" \
                 "Revisa el driver NVIDIA (>=572) y que la imagen de Ollama sea reciente (RTX 5070 = Blackwell, necesita CUDA 12.8+)"
        fi
    fi
else
    bad "Ollama no responde en $OLLAMA_URL" "cd $BASE_DIR && docker compose up -d"
fi

# ─────────────────────────────────────────────────────────────
echo
echo "Configuración"
# ─────────────────────────────────────────────────────────────
if [[ -f "$BASE_DIR/.env" ]]; then
    ok ".env presente"
    for var in SUPABASE_URL SUPABASE_KEY; do
        if grep -qE "^${var}=.+" "$BASE_DIR/.env"; then
            ok "$var definida"
        else
            bad "$var ausente o vacía en .env" "ver .env.example"
        fi
    done
else
    bad "falta $BASE_DIR/.env" "cp .env.example .env y rellena las credenciales"
fi

# ─────────────────────────────────────────────────────────────
echo
if [[ $FAILED -eq 0 ]]; then
    printf '\033[32mTodo listo.\033[0m Arranca con:  sudo venv/bin/python3 orchestrator.py\n\n'
else
    printf '\033[31mHay comprobaciones fallidas.\033[0m Resuélvelas antes de arrancar.\n\n'
fi
exit $FAILED
