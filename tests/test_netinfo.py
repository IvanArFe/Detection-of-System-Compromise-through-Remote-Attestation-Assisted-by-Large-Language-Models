"""Tests de la decodificación de /proc/net/tcp.

El bloque de IPv6 es una regresión: el código anterior pasaba las direcciones de
128 bits por el decodificador de IPv4, que se queda con 4 bytes. El LLM recibía
direcciones inventadas y razonaba sobre ellas.
"""

import pytest

from edr import netinfo


# ── IPv4 ───────────────────────────────────────────────────────

@pytest.mark.parametrize("hexa,esperado", [
    ("0100007F", "127.0.0.1"),      # little-endian: 7F 00 00 01
    ("00000000", "0.0.0.0"),
    ("0101A8C0", "192.168.1.1"),
    ("08080808", "8.8.8.8"),
])
def test_decode_ipv4(hexa, esperado):
    assert netinfo.decode_ipv4(hexa) == esperado


# ── IPv6: la regresión ─────────────────────────────────────────

@pytest.mark.parametrize("hexa,esperado", [
    ("00000000000000000000000001000000", "::1"),
    ("00000000000000000000000000000000", "::"),
    # Las IPv4-mapeadas se muestran en forma IPv4: es lo que el analista espera.
    ("0000000000000000FFFF00000100007F", "::ffff:127.0.0.1"),
])
def test_decode_ipv6(hexa, esperado):
    assert netinfo.decode_ipv6(hexa) == esperado


def test_una_ipv6_no_se_degrada_a_ipv4():
    """Antes `::1` se le presentaba al modelo como `0.0.0.1`."""
    resultado = netinfo.decode_ipv6("00000000000000000000000001000000")
    assert ":" in resultado
    assert resultado != "0.0.0.1"


def test_los_cuatro_grupos_se_invierten_por_separado():
    """Cada grupo de 8 hex es un u32 little-endian; los grupos NO se invierten entre sí.

    Con cuatro grupos distintos, invertir el conjunto entero daría el orden
    contrario y el test lo detectaría.
    """
    assert netinfo.decode_ipv6("01000000020000000300000004000000") == "0:1:0:2:0:3:0:4"


# ── Elección de decodificador ──────────────────────────────────

def test_se_elige_por_longitud():
    assert netinfo.decode_addr("0100007F") == "127.0.0.1"
    assert netinfo.decode_addr("00000000000000000000000001000000") == "::1"


@pytest.mark.parametrize("basura", ["", "XYZ", "0100", "0" * 31, "0" * 33])
def test_entrada_invalida_no_lanza(basura):
    """Una tabla de /proc con un formato inesperado no puede tumbar la herramienta."""
    assert netinfo.decode_addr(basura) == "?"


def test_hex_invalido_no_lanza():
    assert netinfo.decode_ipv4("ZZZZZZZZ") == "?"
    assert netinfo.decode_ipv6("Z" * 32) == "?"


# ── Líneas completas ───────────────────────────────────────────

def test_parse_endpoint():
    assert netinfo.parse_endpoint("0100007F:1F90") == ("127.0.0.1", 8080)
    assert netinfo.parse_endpoint("00000000000000000000000001000000:0050") == ("::1", 80)


def test_format_connection_ipv4():
    linea = ("   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 "
             "00:00000000 00000000  1000  0 12345 1 0000 20 0 0 10 -1")
    assert netinfo.format_connection(linea, {"12345"}) == \
        "127.0.0.1:8080 → 127.0.0.1:40000 [ESTABLISHED]"


def test_format_connection_ipv6():
    linea = ("   0: 00000000000000000000000001000000:2CAA "
             "00000000000000000000000000000000:0000 0A 00000000:00000000 "
             "00:00000000 00000000     0        0 27556 1 0000 100 0 0 10 0")
    resultado = netinfo.format_connection(linea, {"27556"})
    assert "::1:11434" in resultado
    assert "LISTEN" in resultado


def test_format_connection_filtra_por_inodo():
    """Solo interesan los sockets del PID investigado."""
    linea = ("   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 "
             "00:00000000 00000000  1000  0 12345 1 0000 20 0 0 10 -1")
    assert netinfo.format_connection(linea, {"99999"}) is None


def test_format_connection_ignora_lineas_cortas():
    assert netinfo.format_connection("basura", {"1"}) is None
    assert netinfo.format_connection("", {"1"}) is None


def test_estado_desconocido_se_muestra_tal_cual():
    linea = ("   1: 0100007F:1F90 0100007F:9C40 FF 00000000:00000000 "
             "00:00000000 00000000  1000  0 12345 1 0000 20 0 0 10 -1")
    assert "FF" in netinfo.format_connection(linea, {"12345"})
