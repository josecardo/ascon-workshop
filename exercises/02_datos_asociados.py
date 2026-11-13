"""
Bloque 2 — Datos asociados (AD) y detección de manipulación   [VERSIÓN PARTICIPANTE]
===================================================================================

La CABECERA de un paquete (device_id, timestamp) suele ir EN CLARO para que la
red pueda enrutarlo. Los ASSOCIATED DATA (AD) no se cifran, pero SÍ se autentican:
si alguien les cambia un bit, el descifrado falla igual que si tocaran el payload.

Objetivo: pasar la cabecera como AD y comprobar que queda protegida.
API: ascon.ascon_encrypt(key, nonce, associateddata, plaintext)
     ascon.ascon_decrypt(key, nonce, associateddata, ciphertext)  # -> bytes o None
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon


def __TODO__(msg):
    raise NotImplementedError("TODO: " + msg)


CLAVE = os.urandom(16)


def emisor(device_id: bytes, timestamp: bytes, valor_glucosa: bytes):
    cabecera = device_id + b"|" + timestamp   # viaja EN CLARO -> será nuestro AD
    nonce = os.urandom(16)
    # TODO 1: cifra `valor_glucosa` usando `cabecera` como associated data.
    ciphertext = __TODO__("ascon.ascon_encrypt(CLAVE, nonce, cabecera, valor_glucosa)")
    return {"cabecera": cabecera, "nonce": nonce, "ciphertext": ciphertext}


def receptor(paquete: dict):
    # TODO 2: verifica y descifra. El AD debe ser EXACTAMENTE paquete["cabecera"].
    return __TODO__("ascon.ascon_decrypt(CLAVE, paquete['nonce'], paquete['cabecera'], paquete['ciphertext'])")


def main():
    paquete = emisor(b"glucometro-07", b"2026-10-10T08:15:00", b"GLUCOSA=126")
    print("Paquete transmitido:")
    print(f"  cabecera (clara) : {paquete['cabecera']!r}")
    print(f"  ciphertext       : {paquete['ciphertext'].hex()}")

    print("\n[1] Recepción normal:")
    print("   ->", receptor(paquete))

    print("\n[2] Atacante modifica el contenido cifrado:")
    p2 = dict(paquete); ct = bytearray(paquete["ciphertext"]); ct[0] ^= 0x80; p2["ciphertext"] = bytes(ct)
    print("   ->", receptor(p2), "(debería ser None)")

    print("\n[3] Atacante falsifica el device_id de la cabecera:")
    p3 = dict(paquete); p3["cabecera"] = paquete["cabecera"].replace(b"glucometro-07", b"glucometro-99")
    print("   ->", receptor(p3), "(debería ser None)")
    print("\n   La cabecera iba en claro, pero como era AD, tocarla rompe la verificación.")


if __name__ == "__main__":
    main()
