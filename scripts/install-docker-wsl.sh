#!/usr/bin/env bash
#
# Instala Docker Engine nativo + NVIDIA Container Toolkit dentro de WSL2.
#
# Por qué: el proyecto usaba Docker Desktop de Windows, lo que obliga a tenerlo
# arrancado con la integración WSL activada y deja el puerto de Ollama en el
# localhost de Windows. Con Docker Engine nativo dentro de WSL2, Ollama escucha
# en la IP de WSL2 y las VMs del laboratorio (fase 7) lo alcanzan directamente.
#
# Ejecutar como root:  sudo bash scripts/install-docker-wsl.sh
# Es idempotente: se puede volver a lanzar sin romper nada.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] Este script debe ejecutarse como root: sudo bash $0" >&2
    exit 1
fi

TARGET_USER="${SUDO_USER:-ivan}"
CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"

echo "[*] Distribución: Debian $CODENAME | usuario destino: $TARGET_USER"

# ─────────────────────────────────────────────────────────────
# 1. Docker Engine desde el repositorio oficial
# ─────────────────────────────────────────────────────────────
echo "[*] Instalando prerrequisitos..."
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg

if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    echo "[*] Añadiendo clave GPG y repositorio de Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $CODENAME stable
EOF
else
    echo "[-] Repositorio de Docker ya configurado."
fi

# ─────────────────────────────────────────────────────────────
# 2. NVIDIA Container Toolkit (passthrough de la GPU a los contenedores)
# ─────────────────────────────────────────────────────────────
if [[ ! -f /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg ]]; then
    echo "[*] Añadiendo clave GPG y repositorio de NVIDIA Container Toolkit..."
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        > /etc/apt/sources.list.d/nvidia-container-toolkit.list
else
    echo "[-] Repositorio de NVIDIA ya configurado."
fi

echo "[*] Instalando paquetes..."
apt-get update -qq
apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
    nvidia-container-toolkit

# ─────────────────────────────────────────────────────────────
# 3. Configuración
# ─────────────────────────────────────────────────────────────
echo "[*] Registrando el runtime de NVIDIA en Docker..."
nvidia-ctk runtime configure --runtime=docker

echo "[*] Habilitando el servicio (systemd es PID 1 en este WSL2)..."
systemctl enable --now docker

if ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker; then
    echo "[*] Añadiendo $TARGET_USER al grupo docker..."
    usermod -aG docker "$TARGET_USER"
    echo "[!] Cierra y reabre la sesión de WSL para que el grupo tenga efecto."
else
    echo "[-] $TARGET_USER ya pertenece al grupo docker."
fi

# ─────────────────────────────────────────────────────────────
# 4. Verificación
# ─────────────────────────────────────────────────────────────
echo
echo "[*] Verificando..."
docker version --format '    Engine: {{.Server.Version}}' || true
docker compose version || true

echo "[*] Comprobando acceso a la GPU desde un contenedor..."
if docker run --rm --gpus all nvidia/cuda:12.8.0-base-ubuntu24.04 nvidia-smi \
        --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null; then
    echo "[+] GPU accesible desde contenedores."
else
    echo "[!] La GPU no respondió desde el contenedor de prueba."
    echo "    Revisa que el driver de Windows sea >= 572 y que /usr/lib/wsl/lib exista."
fi

echo
echo "[+] Listo. Siguiente paso:"
echo "    cd /home/ivan/TFG && docker compose up -d"
echo "    docker exec ollama ollama pull llama3.1:8b"
