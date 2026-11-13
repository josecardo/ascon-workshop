"""
Bloque 2 — Datos asociados (associated data) y detección de manipulación
========================================================================

En un paquete real no todo puede ir cifrado. La CABECERA (a quién va, de qué
dispositivo viene, timestamp) normalmente tiene que viajar EN CLARO para que
la red/el broker pueda enrutar el mensaje.

Pero "en claro" no debería significar "manipulable". Los ASSOCIATED DATA (AD)
son datos que NO se cifran pero SÍ se autentican: si alguien les cambia un bit,
el descifrado falla igual que si hubieran tocado el contenido cifrado.

Analogía: el sobre de una carta. La dirección va a la vista (AD), la carta va
sellada (ciphertext). Ascon te garantiza que ni la carta ni la dirección fueron
alteradas en el camino.

Objetivo: construir un paquete IoMT realista y comprobar que AD protege la
cabecera igual que el payload.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon


CLAVE = os.urandom(16)  # clave pre-compartida dispositivo <-> servidor


def emisor(device_id: bytes, timestamp: bytes, valor_glucosa: bytes):
    """Arma un paquete: cabecera en claro (autenticada) + valor cifrado."""
    cabecera = device_id + b"|" + timestamp          # viaja en claro -> es AD
    nonce = os.urandom(16)                            # único por mensaje
    ciphertext = ascon.ascon_encrypt(CLAVE, nonce, cabecera, valor_glucosa,
                                     variant="Ascon-AEAD128")
    # Lo que de verdad se transmite por el canal:
    paquete = {"cabecera": cabecera, "nonce": nonce, "ciphertext": ciphertext}
    return paquete


def receptor(paquete: dict):
    """Verifica y descifra. Devuelve el valor o None si algo fue manipulado."""
    return ascon.ascon_decrypt(
        CLAVE,
        paquete["nonce"],
        paquete["cabecera"],      # el AD tiene que ser EXACTAMENTE el mismo
        paquete["ciphertext"],
        variant="Ascon-AEAD128",
    )


def main():
    paquete = emisor(b"glucometro-07", b"2026-10-10T08:15:00", b"GLUCOSA=126")
    print("Paquete transmitido:")
    print(f"  cabecera (clara) : {paquete['cabecera']!r}")
    print(f"  nonce            : {paquete['nonce'].hex()}")
    print(f"  ciphertext       : {paquete['ciphertext'].hex()}")

    # --- Caso 1: todo intacto ------------------------------------------------
    print("\n[1] Recepción normal:")
    print("   ->", receptor(paquete))

    # --- Caso 2: atacante altera el VALOR cifrado ----------------------------
    p2 = dict(paquete)
    ct = bytearray(paquete["ciphertext"])
    ct[0] ^= 0x80
    p2["ciphertext"] = bytes(ct)
    print("\n[2] Atacante modifica el contenido cifrado:")
    print("   ->", receptor(p2), "(rechazado)")

    # --- Caso 3: atacante altera la CABECERA en claro ------------------------
    # Intenta hacer pasar la lectura como si viniera de otro dispositivo.
    p3 = dict(paquete)
    p3["cabecera"] = paquete["cabecera"].replace(b"glucometro-07", b"glucometro-99")
    print("\n[3] Atacante falsifica el device_id de la cabecera:")
    print("   ->", receptor(p3), "(rechazado)")
    print("\n   La cabecera iba EN CLARO, pero como era associated data,")
    print("   tocarla también rompe la verificación. Eso es lo valioso de AD.")


if __name__ == "__main__":
    main()
