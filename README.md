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
│  Hilos del sensor eBPF         │      │  Cliente MCP                      │
│   kprobe init_module           │      │   → consulta alertas cada 20 s    │
│   tracepoint sys_enter_execve  │      │   → sanea y presupuesta el prompt │
│            │                   │ MCP  │   → consulta a Ollama             │
│            ▼                   │stdio │   → interpreta el veredicto       │
│      EventStore  ──────────────┼─────►│   → invoca herramientas MCP       │
│   (memoria + events.jsonl)     │      │   → bucle de dos rondas           │
│                                │      │                                   │
│  Servidor FastMCP              │      │   → confirma con ack_alerts       │
│   herramientas forenses ───────┼──────┤   → persiste en Supabase          │
└────────────────────────────────┘      └───────────────────────────────────┘
                                                        │
                                                        ▼
                                              Ollama (contenedor, GPU)
```

**Flujo de decisión:**

1. Los kprobes de eBPF sobre `init_module` / `finit_module` capturan cargas de módulos de kernel.
2. Un tracepoint sobre `sys_enter_execve` captura todas las ejecuciones de procesos.
3. Ambos callbacks añaden el evento al `EventStore`: en memoria bajo un lock, y como línea en
   `events.jsonl` para el registro forense.
4. El orquestador consulta `get_kernel_alerts` cada 20 segundos. **Solo recibe lo aún no confirmado.**
5. La telemetría se sanea y se recorta antes de entrar en el prompt. El LLM responde en la **ronda 1**
   con `INVESTIGATE`, `MITIGATE` o `NOTHING`, por salida estructurada JSON o, en su defecto, por una
   línea `DECISION:` que se parsea anclada al final.
6. Si es `INVESTIGATE`, se recopila evidencia forense (descriptores, conexiones, ejecuciones del
   proceso y sus hijos) y se envía en la **ronda 2** para el veredicto final.
7. Si es `MITIGATE`, se invoca `remediate_incident` con el `starttime` del evento original, que pasa
   por las siete salvaguardas antes de señalizar nada.
8. `ack_alerts` cierra el ciclo para que esas alertas no se reanalicen.

### Herramientas MCP

| Herramienta | Descripción |
|---|---|
| `get_kernel_alerts()` | Alertas de carga de módulos **aún sin confirmar** |
| `ack_alerts(max_seq)` | Marca como procesadas las alertas hasta `max_seq` |
| `inspect_pid_resources(pid)` | Descriptores de fichero abiertos vía `/proc/{pid}/fd` |
| `inspect_pid_network(pid)` | Conexiones TCP activas, cruzando inodos de socket con `/proc/{pid}/net/tcp` |
| `get_execve_events(pid)` | Ejecuciones del PID o de sus hijos directos |
| `remediate_incident(pid, action, expected_starttime, reason)` | Congela (`SIGSTOP`) o termina (`SIGKILL`) un proceso, tras siete validaciones |
| `sensor_stats()` | Contadores del almacén de eventos |

### Salvaguardas de respuesta

La respuesta autónoma no es incondicional. Antes de enviar ninguna señal,
`edr/safety.py` evalúa siete comprobaciones en orden:

| # | Comprobación | Por qué |
|---|---|---|
| 1 | `pid <= 1` | `os.kill(0, …)` señaliza el **grupo de procesos entero** del EDR; 1 es systemd |
| 2 | Acción válida | Solo `freeze` y `kill` |
| 3 | Autoprotección | El PID no puede ser el EDR ni ninguno de sus ancestros |
| 4 | Hilo de kernel | No tiene espacio de usuario que señalizar |
| 5 | Proceso protegido | Matar `sshd` durante un incidente te deja fuera de la máquina |
| 6 | **Reutilización de PID** | El `starttime` capturado con el evento debe seguir coincidiendo. Sin identidad capturada, no se remedia |
| 7 | Límite de tasa | Un bucle de alucinación no puede arrasar la máquina |

La comprobación 6 es la más importante: entre que el sensor captura el evento y el modelo decide
pasan decenas de segundos, tiempo de sobra para que el kernel recicle el PID. La identidad real de un
proceso es el par `(pid, starttime)`, no el PID.

**`EDR_MODE` viene en `dry-run` por defecto**: el sistema razona, decide y valida, pero no envía la
señal. Para que actúe de verdad, `EDR_MODE=autonomous`.

### Robustez de la decisión

El veredicto del modelo no se toma al pie de la letra. Se lee por dos vías, en orden de preferencia:
la **salida estructurada nativa** de Ollama con un JSON Schema, y como respaldo un **parser anclado**
que recorre las líneas de abajo arriba exigiendo que la línea entera sea el veredicto.

Tres defensas se refuerzan entre sí:

| Defensa | Ataque que corta |
|---|---|
| `fullmatch` sobre la línea completa, de abajo arriba | Una frase que *menciona* o *niega* un veredicto deja de contar |
| Ejemplos con el literal `pid=<PID>` | El modelo repite las instrucciones y el eco no es accionable |
| `allowed_pids` sacado de la telemetría mostrada | Un PID alucinado o inyectado se rechaza |

Además, todo dato controlable por el atacante (`comm`, rutas, argumentos) se sanea antes de entrar en
el prompt y la evidencia va encapsulada entre delimitadores marcados explícitamente como dato no
confiable.

**`INVALID` no es lo mismo que `NOTHING`.** Antes ambos colapsaban, así que "el modelo no supo
responder" era indistinguible de "el modelo decidió no actuar" — cosas muy distintas al calcular
falsos negativos.

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
tail -f events.jsonl      # registro forense: una línea JSON por evento
```

`events.jsonl` es append-only: nunca se reescribe. Los eventos vivos están en memoria, compartidos
entre el hilo del sensor y las herramientas MCP bajo un lock; el fichero es solo el registro. Así una
línea corrupta no invalida el resto y no hay ninguna carrera de escritura.

### Ejecutar componentes por separado (depuración)

```bash
# Solo el servidor MCP y los sensores. Habla JSON-RPC por stdin: útil con un inspector MCP.
sudo venv/bin/python3 forensic_mcp.py
```

### Tests

```bash
venv/bin/python3 -m pytest -q
```

165 tests en unos 4 segundos. **Sin root, sin BCC y sin red**, a propósito: son para ejecutarlos
constantemente mientras se desarrolla. Cubren el parseo de `/proc` (incluidos los `comm` patológicos
como `(sd-pam)`), la concurrencia del almacén de eventos (20 hilos × 500 escrituras con lecturas
simultáneas), las salvaguardas de remediación, y la interpretación del veredicto del modelo —
incluidas las inyecciones de prompt y el eco de las instrucciones.

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
| El LLM analiza siempre la misma alerta | Los eventos no se confirmaban nunca | Resuelto: `ack_alerts` marca lo procesado. Revisa `sensor_stats()` |
| El EDR decide MITIGATE pero no mata nada | Está en `dry-run`, el modo por defecto | `EDR_MODE=autonomous` para que actúe de verdad |
| `[BLOQUEADO] pid_reused` al remediar | El PID ya pertenece a otro proceso | Nada que arreglar: es exactamente el comportamiento correcto |
| `Supabase no disponible` al arrancar | Base de datos caída o proyecto gratuito pausado | El EDR sigue detectando y guarda en `detections_fallback.jsonl`. Reactívalo en el dashboard |

---

## Estructura del repositorio

```
forensic_mcp.py          Servidor MCP + sensores eBPF (requiere root)
orchestrator.py          Cliente MCP + bucle de decisión con el LLM
db.py                    Persistencia en Supabase, con respaldo local
setup_db.py              Creación de tablas (ejecutar una vez)
edr/                     Núcleo: lógica pura, importable sin root ni BCC
  config.py              Configuración desde el entorno
  procinfo.py            Lectura de /proc e identidad (pid, starttime)
  eventstore.py          Almacén de eventos thread-safe
  safety.py              Salvaguardas de remediación y modos de operación
  llm.py                 Cliente de Ollama con timeout, options y métricas
  prompts.py             Sanitización y presupuesto de contexto
  decision.py            Interpretación del veredicto (estructurada + parser)
tests/                   Suite sin root, sin BCC y sin red
docker-compose.yml       Ollama con passthrough de GPU
scripts/
  preflight.sh           Comprobaciones previas al arranque
  install-docker-wsl.sh  Docker Engine + NVIDIA Container Toolkit en WSL2
```
