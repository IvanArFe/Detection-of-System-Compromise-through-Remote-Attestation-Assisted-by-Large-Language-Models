#!/usr/bin/env python3
"""Compila y carga el programa eBPF, sin arrancar nada más.

    sudo venv/bin/python3 scripts/check-bpf.py

Existe porque un error de sintaxis en C, o un rechazo del verificador de eBPF, no
se puede detectar sin root: BCC necesita las cabeceras del kernel y las obtiene
cargando el módulo `kheaders`, cosa que requiere privilegios. Sin esto, el único
modo de descubrir un fallo en el C sería una ejecución completa del sistema, que
mezcla ese fallo con los de todo lo demás.

Devuelve 0 si el programa compila, carga y engancha; 1 en caso contrario.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import forensic_mcp  # noqa: E402


def main():
    if __import__("os").geteuid() != 0:
        print("[!] Necesita root: BCC carga el módulo kheaders para compilar.")
        print("    sudo venv/bin/python3 scripts/check-bpf.py")
        return 1

    lineas = forensic_mcp.ebpf_code.count("\n")
    print(f"[*] Compilando el programa eBPF ({lineas} líneas de C)…")

    try:
        from bcc import BPF
        bpf = BPF(text=forensic_mcp.ebpf_code)
    except Exception as e:
        print("\n[FALLO] el programa no compila o el verificador lo rechaza:\n")
        print(str(e)[:4000])
        return 1

    print("[ OK ] compila, carga y pasa el verificador.")

    # Enganchar las sondas es un paso aparte: un símbolo puede no existir aunque
    # el programa sea válido.
    print("\n[*] Enganchando sondas…")
    for syscall in ("finit_module", "init_module"):
        try:
            fnname = bpf.get_syscall_fnname(syscall)
            bpf.attach_kprobe(event=fnname, fn_name="kprobe_module_load")
            print(f"  [ OK ] kprobe:{syscall}  ({fnname.decode()})")
        except Exception as e:
            print(f"  [FALLO] kprobe:{syscall}: {e}")
            return 1

    # Comprobar que las estructuras de ctypes cuadran con las de C: si no, los
    # eventos se leerían con los campos desplazados y en silencio.
    import ctypes as ct
    print("\n[*] Comprobando el espejo de ctypes…")
    print(f"  sizeof(EvHdr)      = {ct.sizeof(forensic_mcp.EvHdr)}")
    print(f"  sizeof(ExecEvent)  = {ct.sizeof(forensic_mcp.ExecEvent)}")

    print("\n[+] Todo correcto. Puedes arrancar el sistema.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
