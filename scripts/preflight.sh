#!/usr/bin/env bash
#
# Pre-flight checks. Answers "why won't it start?" in a single command.
#
#   bash scripts/preflight.sh
#
# Exits 1 if any critical check fails.

set -uo pipefail   # no -e on purpose: we want ALL the checks to run

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="$BASE_DIR/venv/bin/python3"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
MODEL="${EDR_MODEL:-llama3.1:8b}"

FAILED=0
ok()   { printf '  \033[32m[ OK ]\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m[WARN]\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '         -> %s\n' "$2"; FAILED=1; }

echo
echo "EDR preflight — $BASE_DIR"

# ─────────────────────────────────────────────────────────────
echo
echo "Python and dependencies"
# ─────────────────────────────────────────────────────────────
if [[ -x "$VENV_PY" ]]; then
    ok "venv present ($("$VENV_PY" --version 2>&1))"

    for mod in mcp requests dotenv supabase; do
        if "$VENV_PY" -c "import $mod" 2>/dev/null; then
            ok "module '$mod' importable"
        else
            bad "module '$mod' NOT importable" "source venv/bin/activate && pip install -r requirements.txt"
        fi
    done

    # bcc does not install with pip: it is a system package linked into the venv.
    if "$VENV_PY" -c "import bcc" 2>/dev/null; then
        ok "module 'bcc' importable from the venv"
    else
        bad "module 'bcc' NOT importable from the venv" \
            "sudo apt install python3-bpfcc, then symlink /usr/lib/python3/dist-packages/bcc into the venv site-packages"
    fi
else
    bad "$VENV_PY does not exist" "python3 -m venv venv && venv/bin/pip install -r requirements.txt"
fi

# ─────────────────────────────────────────────────────────────
echo
echo "Kernel and eBPF"
# ─────────────────────────────────────────────────────────────
echo "  [INFO] kernel $(uname -r)"

if [[ -r /sys/kernel/btf/vmlinux ]]; then
    ok "BTF available (BCC can compile without kernel headers)"
else
    warn "no BTF at /sys/kernel/btf/vmlinux" \
         "BCC will need headers: sudo modprobe kheaders"
fi

if mountpoint -q /sys/kernel/tracing 2>/dev/null; then
    ok "tracefs mounted at /sys/kernel/tracing"
else
    warn "tracefs not mounted" "sudo mount -t tracefs nodev /sys/kernel/tracing"
fi

if [[ -d /lib/modules/$(uname -r)/build ]]; then
    ok "kernel headers present"
else
    warn "no kernel headers (normal on WSL2)" \
         "You cannot build your own module here; use the lab VM"
fi

if [[ $EUID -eq 0 ]]; then
    ok "running as root"
else
    warn "not root" "the EDR needs root: sudo venv/bin/python3 orchestrator.py"
fi

# ─────────────────────────────────────────────────────────────
echo
echo "Ollama"
# ─────────────────────────────────────────────────────────────
TAGS="$(curl -s --max-time 5 "$OLLAMA_URL/api/tags" 2>/dev/null)"
if [[ -n "$TAGS" ]]; then
    ok "Ollama responds at $OLLAMA_URL"

    if grep -q "\"$MODEL\"" <<<"$TAGS"; then
        ok "model '$MODEL' pulled"
    else
        bad "model '$MODEL' NOT pulled" "docker exec ollama ollama pull $MODEL"
    fi

    # A model loaded on CPU makes the decision loop unusably slow.
    if command -v docker >/dev/null 2>&1; then
        PS_OUT="$(docker exec ollama ollama ps 2>/dev/null)"
        if grep -q "CPU" <<<"$PS_OUT"; then
            warn "a model is running on CPU, not GPU" \
                 "Check the NVIDIA driver (>=572) and that the Ollama image is recent (RTX 5070 = Blackwell, needs CUDA 12.8+)"
        fi
    fi
else
    bad "Ollama does not respond at $OLLAMA_URL" "cd $BASE_DIR && docker compose up -d"
fi

# ─────────────────────────────────────────────────────────────
echo
echo "Configuration"
# ─────────────────────────────────────────────────────────────
if [[ -f "$BASE_DIR/.env" ]]; then
    ok ".env present"
    for var in SUPABASE_URL SUPABASE_KEY; do
        if grep -qE "^${var}=.+" "$BASE_DIR/.env"; then
            ok "$var defined"
        else
            bad "$var missing or empty in .env" "see .env.example"
        fi
    done
else
    bad "$BASE_DIR/.env is missing" "cp .env.example .env and fill in the credentials"
fi

# ─────────────────────────────────────────────────────────────
echo
if [[ $FAILED -eq 0 ]]; then
    printf '\033[32mAll set.\033[0m Start with:  sudo venv/bin/python3 orchestrator.py\n\n'
else
    printf '\033[31mSome checks failed.\033[0m Fix them before starting.\n\n'
fi
exit $FAILED
