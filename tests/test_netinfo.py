"""Tests for the /proc/net/tcp decoding.

The IPv6 block is a regression: the old code ran 128-bit addresses through the
IPv4 decoder, which keeps 4 bytes. The LLM was given invented addresses and
reasoned about them.
"""

import pytest

from edr import netinfo


# ── IPv4 ───────────────────────────────────────────────────────

@pytest.mark.parametrize("hex_str,expected", [
    ("0100007F", "127.0.0.1"),      # little-endian: 7F 00 00 01
    ("00000000", "0.0.0.0"),
    ("0101A8C0", "192.168.1.1"),
    ("08080808", "8.8.8.8"),
])
def test_decode_ipv4(hex_str, expected):
    assert netinfo.decode_ipv4(hex_str) == expected


# ── IPv6: the regression ───────────────────────────────────────

@pytest.mark.parametrize("hex_str,expected", [
    ("00000000000000000000000001000000", "::1"),
    ("00000000000000000000000000000000", "::"),
    # IPv4-mapped addresses are shown in IPv4 form: what the analyst expects.
    ("0000000000000000FFFF00000100007F", "::ffff:127.0.0.1"),
])
def test_decode_ipv6(hex_str, expected):
    assert netinfo.decode_ipv6(hex_str) == expected


def test_an_ipv6_is_not_degraded_to_ipv4():
    """`::1` used to be presented to the model as `0.0.0.1`."""
    result = netinfo.decode_ipv6("00000000000000000000000001000000")
    assert ":" in result
    assert result != "0.0.0.1"


def test_the_four_groups_are_swapped_individually():
    """Each group of 8 hex digits is a little-endian u32; the groups themselves
    are NOT reordered. With four distinct groups, swapping the whole thing would
    give the opposite order and this test would catch it."""
    assert netinfo.decode_ipv6("01000000020000000300000004000000") == "0:1:0:2:0:3:0:4"


# ── Decoder selection ──────────────────────────────────────────

def test_the_decoder_is_chosen_by_length():
    assert netinfo.decode_addr("0100007F") == "127.0.0.1"
    assert netinfo.decode_addr("00000000000000000000000001000000") == "::1"


@pytest.mark.parametrize("junk", ["", "XYZ", "0100", "0" * 31, "0" * 33])
def test_invalid_input_does_not_raise(junk):
    """A /proc table in an unexpected format must not bring the tool down."""
    assert netinfo.decode_addr(junk) == "?"


def test_invalid_hex_does_not_raise():
    assert netinfo.decode_ipv4("ZZZZZZZZ") == "?"
    assert netinfo.decode_ipv6("Z" * 32) == "?"


# ── Whole lines ────────────────────────────────────────────────

def test_parse_endpoint():
    assert netinfo.parse_endpoint("0100007F:1F90") == ("127.0.0.1", 8080)
    assert netinfo.parse_endpoint("00000000000000000000000001000000:0050") == ("::1", 80)


def test_format_connection_ipv4():
    line = ("   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 "
            "00:00000000 00000000  1000  0 12345 1 0000 20 0 0 10 -1")
    assert netinfo.format_connection(line, {"12345"}) == \
        "127.0.0.1:8080 → 127.0.0.1:40000 [ESTABLISHED]"


def test_format_connection_ipv6():
    line = ("   0: 00000000000000000000000001000000:2CAA "
            "00000000000000000000000000000000:0000 0A 00000000:00000000 "
            "00:00000000 00000000     0        0 27556 1 0000 100 0 0 10 0")
    result = netinfo.format_connection(line, {"27556"})
    assert "::1:11434" in result
    assert "LISTEN" in result


def test_format_connection_filters_by_inode():
    """Only the investigated pid's sockets are of interest."""
    line = ("   1: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 "
            "00:00000000 00000000  1000  0 12345 1 0000 20 0 0 10 -1")
    assert netinfo.format_connection(line, {"99999"}) is None


def test_format_connection_ignores_short_lines():
    assert netinfo.format_connection("junk", {"1"}) is None
    assert netinfo.format_connection("", {"1"}) is None


def test_an_unknown_state_is_shown_as_is():
    line = ("   1: 0100007F:1F90 0100007F:9C40 FF 00000000:00000000 "
            "00:00000000 00000000  1000  0 12345 1 0000 20 0 0 10 -1")
    assert "FF" in netinfo.format_connection(line, {"12345"})
