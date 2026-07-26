# EDR autónomo con eBPF, MCP y LLM local

Sistema de detección y respuesta en endpoint (EDR) que monitoriza el kernel de Linux con eBPF, expone
herramientas forenses a un modelo de lenguaje mediante MCP, y deja que el modelo razone y decida la
respuesta sin intervención humana.

Trabajo de Fin de Grado.

---

## Arquitectura

Tres capas que se comunican por MCP sobre transporte stdio:

```
┌─ forensic_mcp.py ──────────────┐      ┌─ orchestrator.py ─────────────────┐
│  (proceso root)                │      │  (proceso root)                   │
│                                │      │                                   │
│  Hilos del sensor eBPF         │◄────►│  Cliente MCP                      │
│   → kernel_events.json         │ MCP  │   → consulta alertas cada 20 s    │
│      (carga de módulos)        │stdio │   → envía la telemetría a Ollama  │
│   → execve_events.json         │      │   → parsea el veredicto           │
│      (ejecución de procesos)   │      │   → invoca herramientas MCP       │
│                                │      │   → bucle de dos rondas           │
│  Servidor FastMCP              │      │                                   │
│   herramientas forenses ───────┼──────┤   → persiste en Supabase          │
└────────────────────────────────┘      └───────────────────────────────────┘
                                                        │
                                                        ▼
                                              Ollama (contenedor, GPU)
```

**Flujo de decisión:**

1. Los kprobes de eBPF sobre `init_module` / `finit_module` capturan cargas de módulos de kernel.
2. Un tracepoint sobre `sys_enter_execve` captura todas las ejecuciones de procesos.
3. El orquestador consulta `get_kernel_alerts` cada 20 segundos.
4. Si hay alertas, el LLM responde en la **ronda 1** con un veredicto estructurado:
   `DECISION: INVESTIGATE pid=X` / `DECISION: MITIGATE pid=X action=freeze|kill` / `DECISION: NOTHING`.
5. Si es `INVESTIGATE`, el orquestador recopila evidencia forense (descriptores abiertos, conexiones
   de red, ejecuciones del proceso y sus hijos) y la envía al LLM en la **ronda 2** para un veredicto
   final.
6. Si es `MITIGATE`, se invoca `remediate_incident`: `SIGSTOP` (freeze) o `SIGKILL` (kill).

### Herramientas MCP

| Herramienta | Descripción |
|---|---|
| `get_kernel_alerts()` | Eventos de carga de módulos capturados por eBPF |
| `inspect_pid_resources(pid)` | Descriptores de fichero abiertos vía `/proc/{pid}/fd` |
| `inspect_pid_network(pid)` | Conexiones TCP activas, cruzando inodos de socket con `/proc/{pid}/net/tcp` |
| `get_execve_events(pid)` | Ejecuciones del PID o de sus hijos directos |
| `remediate_incident(pid, action)` | Congela (`SIGSTOP`) o termina (`SIGKILL`) un proceso |

---

## Requisitos

- Debian sobre WSL2, kernel 6.6+ con soporte eBPF
- Python 3.13 (venv en `./venv`)
- BCC como paquete del sistema (`python3-bpfcc`) — **no se instala con pip**
- Docker Engine dentro de WSL2, con NVIDIA Container Toolkit para el passthrough de la GPU
- Una cuenta de Supabase (persistencia de detecciones y evidencia)

### Instalación

```bash
# 1. Dependencias del sistema
sudo apt install python3-bpfcc

# 2. Docker Engine + NVIDIA Container Toolkit dentro de WSL2
sudo bash scripts/install-docker-wsl.sh

# 3. Entorno de Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Credenciales
cp .env.example .env    # rellenar SUPABASE_URL, SUPABASE_KEY, SUPABASE_ACCESS_TOKEN

# 5. Crear las tablas en Supabase (solo la primera vez)
python setup_db.py
```

**BCC dentro del venv:** BCC no se puede instalar con pip. La solución adoptada es enlazar las
bibliotecas del sistema al `site-packages` del venv. Si `from bcc import BPF` falla dentro del venv,
comprueba que los enlaces existan bajo `venv/lib/python3.13/site-packages/`.

---

## Arranque

```bash
# 1. Verificar que todo está en su sitio
bash scripts/preflight.sh

# 2. Levantar Ollama
docker compose up -d
docker exec ollama ollama pull llama3.1:8b     # solo la primera vez

# 3. Arrancar el sistema completo
sudo venv/bin/python3 orchestrator.py
```

El orquestador lanza `forensic_mcp.py` automáticamente como subproceso MCP, con el mismo intérprete y
los mismos privilegios. No hace falta arrancarlo por separado.

Gracias a las rutas absolutas, **el sistema funciona desde cualquier directorio**.

### Generar eventos de prueba

En otra terminal, con el orquestador corriendo:

```bash
sudo modprobe tcrypt && sudo rmmod tcrypt   # carga de módulo con éxito
sudo insmod /etc/hostname                   # intento fallido (-ENOEXEC), la kprobe dispara igual
sudo modprobe dummy && sudo modprobe -r dummy
curl -s http://example.com > /dev/null      # ejecución de proceso
```

Y revisa la telemetría cruda:

```bash
cat kernel_events.json    # eventos de módulos (últimos 30)
cat execve_events.json    # ejecuciones de procesos (últimas 200)
```

### Ejecutar componentes por separado (depuración)

```bash
# Solo el servidor MCP y los sensores. Habla JSON-RPC por stdin: útil con un inspector MCP.
sudo venv/bin/python3 forensic_mcp.py
```

### Tests

```bash
pytest
```

---

## Persistencia en Supabase

Implementada en `db.py`, invocada desde el orquestador en tres puntos del ciclo de decisión.

**Tablas** (creadas por `setup_db.py` mediante la Management API sobre HTTPS):

- **`detections`** — una fila por ciclo de decisión del LLM: `pid`, `process`, `decision`, `action`,
  `llm_round1`, `llm_round2`, `remediation`.
- **`evidence`** — resultados de las herramientas forenses, ligados a una detección:
  `detection_id` (FK), `tool`, `result`.

**Nota sobre WSL2:** las conexiones directas a PostgreSQL en `db.*.supabase.co:5432` fallan por
problemas de resolución DNS en WSL2. Tanto `setup_db.py` como `db.py` usan APIs HTTPS para evitarlo.

---

## Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| La sesión MCP se cuelga sin mensaje | `sudo` pidiendo contraseña dentro del canal stdio | Ya resuelto: el servidor se lanza con `sys.executable`. Si reaparece, ejecuta `sudo -v` antes |
| `Ollama no responde` en el preflight | El contenedor no está levantado | `docker compose up -d` |
| El modelo va lentísimo | Ollama cargó el modelo en CPU | `docker exec ollama ollama ps` debe decir 100% GPU. La RTX 5070 es Blackwell: necesita CUDA 12.8+ y driver de Windows ≥572 |
| `from bcc import BPF` falla | Faltan los enlaces de BCC en el venv | Ver la nota de instalación arriba |
| El LLM analiza siempre la misma alerta | Los eventos no se consumen de `kernel_events.json` | Limitación conocida; se resuelve en la fase 1 del plan de evolución |

---

## Estructura del repositorio

```
forensic_mcp.py          Servidor MCP + sensores eBPF (requiere root)
orchestrator.py          Cliente MCP + bucle de decisión con el LLM
db.py                    Persistencia en Supabase
setup_db.py              Creación de tablas (ejecutar una vez)
docker-compose.yml       Ollama con passthrough de GPU
scripts/
  preflight.sh           Comprobaciones previas al arranque
  install-docker-wsl.sh  Docker Engine + NVIDIA Container Toolkit en WSL2
```
