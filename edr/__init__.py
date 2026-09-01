"""EDR core: pure logic, testable without root, without BCC and without network.

The entrypoints (`forensic_mcp.py`, `orchestrator.py`) import from here. Nothing
in this package may import `bcc` or load eBPF at import time — that is the whole
point of it.
"""
