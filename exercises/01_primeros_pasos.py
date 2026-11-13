"""
Bloque 1 — Primeros pasos con Ascon-AEAD128   [VERSIÓN PARTICIPANTE]
===================================================================

AEAD = Authenticated Encryption with Associated Data. En una operación:
  - Confidencialidad: nadie lee el mensaje sin la clave.
  - Integridad + autenticidad: si alguien altera un bit, el descifrado FALLA.

Ascon-AEAD128 (NIST SP 800-232):
  - clave: 16 bytes   nonce: 16 bytes (único por cifrado)   tag: 16 bytes (va al final del ciphertext)

Completa los TODO. Cuando corras el archivo, el programa te llevará al primero.
API:  ascon.ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-AEAD128")
      ascon.ascon_decrypt(key, nonce, associateddata, ciphertext, variant="Ascon-AEAD128")  # -> bytes o None
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon


def __TODO__(msg):
    raise NotImplementedError("TODO: " + msg)


def main():
    clave = os.urandom(16)
    nonce = os.urandom(16)

    lectura = b"GLUCOSA=126 mg/dL"
    print(f"Lectura original : {lectura!r}  ({len(lectura)} bytes)")

    # TODO 1: cifra `lectura` con Ascon-AEAD128 (associated data = b"").
    ciphertext = __TODO__("cifra la lectura con ascon.ascon_encrypt(clave, nonce, b'', lectura)")
    print(f"Ciphertext+tag   : {ciphertext.hex()}  ({len(ciphertext)} bytes)")
    print(f"  -> Overhead de {len(ciphertext) - len(lectura)} bytes = el TAG de 16 bytes.")

    # TODO 2: descifra y verifica.
    descifrado = __TODO__("descifra con ascon.ascon_decrypt(clave, nonce, b'', ciphertext)")
    print(f"Descifrado       : {descifrado!r}")
    assert descifrado == lectura
    print("\nOK: cifrado y descifrado correctos.")

    # (Ya resuelto) ¿Y si cambia un bit del ciphertext?
    corrupto = bytearray(ciphertext)
    corrupto[0] ^= 0x01
    resultado = ascon.ascon_decrypt(clave, nonce, b"", bytes(corrupto), variant="Ascon-AEAD128")
    print(f"\nCiphertext con 1 bit alterado -> descifrado: {resultado}")
    print("  -> None = manipulación detectada. Esa es la 'A' de AEAD.")


if __name__ == "__main__":
    main()
