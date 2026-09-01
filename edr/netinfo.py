"""Decoding the /proc/net socket tables.

The kernel exposes addresses in hex and in native byte order, which on x86 is
little-endian. IPv6 tables used to be run through the IPv4 decoder, which keeps
4 bytes of a 128-bit address: the LLM was shown `0.0.0.1` for `::1` and reasoned
about it as if it were real.
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
    """8 hex digits, one little-endian u32."""
    try:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(hex_str, 16)))
    except (ValueError, OSError, struct.error):
        return "?"


def decode_ipv6(hex_str):
    """32 hex digits: four consecutive little-endian u32.

    Each group of 8 is byte-swapped individually; the groups themselves are NOT
    reordered. Validated against `::1` and `::ffff:127.0.0.1`.
    """
    try:
        raw = b"".join(
            struct.pack("<I", int(hex_str[i:i + 8], 16)) for i in range(0, 32, 8)
        )
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (ValueError, OSError, struct.error):
        return "?"


def decode_addr(hex_str):
    """Pick the decoder by string length, which is what tells them apart."""
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
    """Render a /proc/net/tcp[6] line, or None if it is not of interest.

    `wanted_inodes` selects the sockets belonging to the investigated pid.
    """
    parts = line.split()
    if len(parts) < 10 or parts[9] not in wanted_inodes:
        return None

    local_ip, local_port = parse_endpoint(parts[1])
    remote_ip, remote_port = parse_endpoint(parts[2])
    state = TCP_STATES.get(parts[3].upper(), parts[3])

    return f"{local_ip}:{local_port} → {remote_ip}:{remote_port} [{state}]"
