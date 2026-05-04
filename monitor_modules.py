from bcc import BPF
import json
import os
from datetime import datetime

# Definimos el fichero donde escribiremos los logs pertinentes a la auditoría.
LOG_FILE = "kernel_events.json"

# Código C perteneciente a la estructura para gestionar la información y métodos de obtención.
ebpf_code = """
#include <linux/sched.h>

struct data_t {
    u32 pid; // Identificador del proceso
    char command[16]; // Información sobre el comando ejecutado
    char message[64]; // Mensaje descriptivo para el usuario.
};

// Creamos buzón
BPF_PERF_OUTPUT(eventos);

int kprobe_monitor(void *ctx) {
    
    // Creamos una instancia de struct
    struct data_t data = {};

    // Primero obtenemos el PID del proceso (desplazamiento de 32 bits)
    data.pid = bpf_get_current_pid_tgid() >> 32;

    // Obtenemos el nombre del proceso (comando)
    bpf_get_current_comm(&data.command, sizeof(data.command));

    // Añadimos un mensaje a modo informativo
    __builtin_memcpy(data.message, "Se ha detectado una carga de modulo", sizeof(data.message));
    
    // Pasamos esta instancia al buzón
    eventos.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Cargamos el código
b = BPF(text=ebpf_code)

# Buscamos el nombre real de la syscall
# Esto resolverá automáticamente si es __x64_sys_finit_module o sys_finit_module
fnname_finit = b.get_syscall_fnname("finit_module")
fnname_init = b.get_syscall_fnname("init_module")

# Enganchamos nuestra función 'kprobe_monitor' a esos nombres reales
b.attach_kprobe(event=fnname_finit, fn_name="kprobe_monitor")
b.attach_kprobe(event=fnname_init, fn_name="kprobe_monitor")

print(f"[*] Monitorizando syscalls: {fnname_finit} e {fnname_init}")
print("[*] Centinela activo. Esperando eventos... (Ctrl+C para salir)\n")

# Definimos una funcion para interpretar cada evento que se capture.
def procesar_evento(cpu, data, size):
    evento = b["eventos"].event(data)

    # Creamos diccionario para escribir en el archivo de log
    evento_detectado = {
        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "pid": evento.pid,
        "comando": evento.command.decode(),
        "evento": evento.message.decode()
    }

    # Leemos eventos anteriores en caso de que existan
    array_eventos = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                array_eventos = json.load(f)
            except json.JSONDecodeError:
                array_eventos = []

    # Añadimos el nuevo evento al fichero de log
    array_eventos.append(evento_detectado)

    # Limitamos numero de eventos de cara al LLM
    if len(array_eventos) > 30:
        array_eventos = array_eventos[-30:]
    
    # Persistimos en el log
    with open(LOG_FILE, "w") as f:
        try:
            json.dump(array_eventos, f, indent=4)
        except Exception as e:
            print(e.message)
            exit()
    
    # Depuración (momentaneo)
    print(f"[+] Evento guardado en JSON: {evento_detectado['comando']} (PID: {evento_detectado['pid']})")

try:
    b["eventos"].open_perf_buffer(procesar_evento)
    while True:
        b.perf_buffer_poll() # Revisamos el buzón constantemente por si detectamos algún cambio.

except KeyboardInterrupt:
    exit()
