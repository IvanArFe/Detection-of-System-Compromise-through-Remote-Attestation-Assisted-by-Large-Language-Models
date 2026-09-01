#!/usr/bin/env bash
#
# Installs native Docker Engine + NVIDIA Container Toolkit inside WSL2.
#
# Why: with Docker Desktop the Ollama port lands on Windows' localhost and the
# whole thing depends on Desktop being up with WSL integration enabled. With a
# native engine inside WSL2, Ollama listens on the WSL2 IP and the phase 7 lab
# VMs reach it directly.
#
# Run as root:  sudo bash scripts/install-docker-wsl.sh
# Idempotent: safe to re-run.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must run as root: sudo bash $0" >&2
    exit 1
fi

TARGET_USER="${SUDO_USER:-ivan}"
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"

echo "[*] Distribution: Debian $CODENAME | target user: $TARGET_USER"

# ─────────────────────────────────────────────────────────────
# 1. Docker Engine from the official repository
# ─────────────────────────────────────────────────────────────
echo "[*] Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg

if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    echo "[*] Adding Docker GPG key and repository..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $CODENAME stable
EOF
else
    echo "[-] Docker repository already configured."
fi

# ─────────────────────────────────────────────────────────────
# 2. NVIDIA Container Toolkit (GPU passthrough into containers)
# ─────────────────────────────────────────────────────────────
if [[ ! -f /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg ]]; then
    echo "[*] Adding NVIDIA Container Toolkit GPG key and repository..."
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        > /etc/apt/sources.list.d/nvidia-container-toolkit.list
else
    echo "[-] NVIDIA repository already configured."
fi

echo "[*] Installing packages..."
apt-get update -qq
apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    nvidia-container-toolkit

# ─────────────────────────────────────────────────────────────
# 3. Configuration
# ─────────────────────────────────────────────────────────────
echo "[*] Registering the NVIDIA runtime with Docker..."
nvidia-ctk runtime configure --runtime=docker

echo "[*] Enabling the service (systemd is PID 1 in this WSL2)..."
systemctl enable --now docker

if ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker; then
    echo "[*] Adding $TARGET_USER to the docker group..."
    usermod -aG docker "$TARGET_USER"
    echo "[!] Close and reopen the WSL session for the group to take effect."
else
    echo "[-] $TARGET_USER already belongs to the docker group."
fi

# ─────────────────────────────────────────────────────────────
# 4. Verification
# ─────────────────────────────────────────────────────────────
echo
echo "[*] Verifying..."
docker version --format '    Engine: {{.Server.Version}}' || true
docker compose version || true

echo "[*] Checking GPU access from a container..."
if docker run --rm --gpus all nvidia/cuda:12.8.0-base-ubuntu24.04 nvidia-smi \
        --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null; then
    echo "[+] GPU reachable from containers."
else
    echo "[!] The GPU did not respond from the test container."
    echo "    Check the Windows driver is >= 572 and that /usr/lib/wsl/lib exists."
fi

echo
echo "[+] Done. Next step:"
echo "    cd /home/ivan/TFG && docker compose up -d"
echo "    docker exec ollama ollama pull llama3.1:8b"
