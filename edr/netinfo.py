"""Decodificación de las tablas de sockets de /proc/net.

El kernel expone las direcciones en hexadecimal y en **orden de byte nativo**, que
en x86 es little-endian. Eso obliga a invertir bytes, y es donde estaba el fallo:
`/proc/{pid}/net/tcp6` se pasaba por el decodificador de IPv4, que se queda con 4
bytes de una dirección de 128 bits. El LLM recibía **direcciones inventadas** y
razonaba sobre ellas como si fueran reales — con la lógica anterior, `::1` se le
presentaba como `0.0.0.1`.

No es un caso rebuscado: esta máquina tiene un socket IPv6 escuchando en el puerto
11434, que es el propio Ollama.
"""

import socket
import struct

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",    "0C": "NEW_SYN_RECV",
}


def decode_ipv4(hex_str):
    """8 dígitos hex, un u32 little-endian."""
    try:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(hex_str, 16)))
    except (ValueError, OSError, struct.error):
        return "?"


def decode_ipv6(hex_str):
    """32 dígitos hex: cuatro u32 little-endian consecutivos.

    Cada grupo de 8 se invierte por separado; los grupos NO se invierten entre sí.
    Validado contra `::1` (`00000000000000000000000001000000`) y contra
    `::ffff:127.0.0.1` (`0000000000000000FFFF00000100007F`).

    Las direcciones IPv4-mapeadas se devuelven en su forma IPv4: es lo que el
    analista espera ver, y `inet_ntop` ya lo hace por su cuenta.
    """
    try:
        raw = b"".join(
            struct.pack("<I", int(hex_str[i:i + 8], 16)) for i in range(0, 32, 8)
        )
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (ValueError, OSError, struct.error):
        return "?"


def decode_addr(hex_str):
    """Elige el decodificador por la longitud de la cadena, que es lo que la distingue."""
    if len(hex_str) == 8:
        return decode_ipv4(hex_str)
    if len(hex_str) == 32:
        return decode_ipv6(hex_str)
    return "?"


def parse_endpoint(field):
    """`"0100007F:1F90"` → `("127.0.0.1", 8080)`."""
    addr, _, port = field.partition(":")
    try:
        return decode_addr(addr), int(port, 16)
    except ValueError:
        return "?", 0


def format_connection(line, wanted_inodes):
    """Convierte una línea de /proc/net/tcp[6] en texto, o None si no interesa.

    `wanted_inodes` filtra por los sockets que pertenecen al PID investigado.
    """
    parts = line.split()
    if len(parts) < 10 or parts[9] not in wanted_inodes:
        return None

    local_ip, local_port = parse_endpoint(parts[1])
    remote_ip, remote_port = parse_endpoint(parts[2])
    state = TCP_STATES.get(parts[3].upper(), parts[3])

    return f"{local_ip}:{local_port} → {remote_ip}:{remote_port} [{state}]"
