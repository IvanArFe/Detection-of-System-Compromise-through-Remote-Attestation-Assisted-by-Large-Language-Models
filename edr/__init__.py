"""Núcleo del EDR: lógica pura, testeable sin root, sin BCC y sin red.

Los entrypoints (`forensic_mcp.py`, `orchestrator.py`) importan de aquí. Nada de
este paquete debe importar `bcc` ni cargar programas eBPF al importarse: ésa es
justamente la razón de que exista.
"""
