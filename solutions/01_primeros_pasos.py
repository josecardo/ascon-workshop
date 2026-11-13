"""
Bloque 1 — Primeros pasos con Ascon-AEAD128
===========================================

AEAD = Authenticated Encryption with Associated Data.
En una sola operación obtienes:
  - Confidencialidad: nadie lee el mensaje sin la clave.
  - Integridad + autenticidad: si alguien altera un solo bit, el descifrado FALLA.

Ascon-AEAD128 (NIST SP 800-232) trabaja con:
  - clave  (key):   16 bytes (128 bits)  -> secreta, compartida entre emisor y receptor
  - nonce:          16 bytes (128 bits)  -> "number used once": ÚNICO por cada cifrado con la misma clave
  - tag:            16 bytes (128 bits)  -> se agrega automáticamente al final del ciphertext

Objetivo del bloque: cifrar y descifrar la lectura de un sensor y entender cada parámetro.
"""

import os
import sys

# Hacemos visible la implementación de referencia vendorizada en ../vendor/ascon.py
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon


def main():
    # --- 1. Material criptográfico -------------------------------------------
    # En un dispositivo real la clave se provisiona de fábrica o en el enrolamiento.
    # Aquí la generamos aleatoria. NUNCA uses una clave fija en producción.
    clave = os.urandom(16)   # 128 bits
    nonce = os.urandom(16)   # 128 bits, único para este mensaje

    # --- 2. La telemetría del "sensor" ---------------------------------------
    lectura = b"GLUCOSA=126 mg/dL"
    print(f"Lectura original : {lectura!r}  ({len(lectura)} bytes)")

    # --- 3. Cifrado autenticado ----------------------------------------------
    # associateddata vacío por ahora (lo exploramos en el bloque 2).
    ciphertext = ascon.ascon_encrypt(clave, nonce, b"", lectura, variant="Ascon-AEAD128")
    print(f"Ciphertext+tag   : {ciphertext.hex()}  ({len(ciphertext)} bytes)")
    print(f"  -> El overhead es de {len(ciphertext) - len(lectura)} bytes: ese es el TAG de 16 bytes.")

    # --- 4. Descifrado + verificación ----------------------------------------
    # ascon_decrypt devuelve los bytes originales... o None si el tag no cuadra.
    descifrado = ascon.ascon_decrypt(clave, nonce, b"", ciphertext, variant="Ascon-AEAD128")
    print(f"Descifrado       : {descifrado!r}")
    assert descifrado == lectura, "El descifrado no coincide con el original (no debería pasar)"
    print("\nOK: cifrado y descifrado correctos.")

    # --- 5. ¿Y si cambia un solo bit del ciphertext? -------------------------
    corrupto = bytearray(ciphertext)
    corrupto[0] ^= 0x01  # volteamos un bit del primer byte
    resultado = ascon.ascon_decrypt(clave, nonce, b"", bytes(corrupto), variant="Ascon-AEAD128")
    print(f"\nCiphertext con 1 bit alterado -> descifrado: {resultado}")
    print("  -> None significa 'manipulación detectada'. Eso es la 'A' de AEAD en acción.")


if __name__ == "__main__":
    main()
