"""
Bloque 3 — El footgun principal: reutilizar el nonce
====================================================

Ascon es seguro, pero su seguridad DEPENDE de una regla:
    nunca uses el mismo (clave, nonce) para cifrar dos mensajes distintos.

"Nonce" = number used once. Si lo repites, Ascon (como todo cifrado de flujo
AEAD) genera el MISMO keystream, y eso filtra información aunque el atacante
no tenga la clave. Vamos a romperlo en vivo y después a arreglarlo.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def demo_A_mismo_mensaje():
    print("=" * 64)
    print("[A] Reutilizar nonce con el MISMO mensaje -> fuga de patrones")
    print("=" * 64)
    clave = os.urandom(16)
    nonce = os.urandom(16)  # el error: lo vamos a reusar
    lectura = b"GLUCOSA=120"

    c1 = ascon.ascon_encrypt(clave, nonce, b"", lectura)
    c2 = ascon.ascon_encrypt(clave, nonce, b"", lectura)
    print(f"  ciphertext #1: {c1.hex()}")
    print(f"  ciphertext #2: {c2.hex()}")
    print(f"  ¿idénticos?   {c1 == c2}")
    print("  -> Un espía ni siquiera descifra: ve cuándo se repite una lectura.")
    print("     (el primo lejano del 'pingüino' de AES-ECB)\n")


def demo_B_recuperar_sin_clave():
    print("=" * 64)
    print("[B] Reutilizar nonce con mensajes DISTINTOS -> recuperación total")
    print("=" * 64)
    clave = os.urandom(16)
    nonce = os.urandom(16)  # el mismo nonce para dos mensajes: catastrófico

    # Dos lecturas de igual longitud (<=16 bytes -> un solo bloque).
    p_conocido  = b"GLUCOSA=082"   # el atacante CONOCE esta (p. ej. valor de calibración)
    p_secreto   = b"GLUCOSA=350"   # esta la quiere averiguar

    c_conocido = ascon.ascon_encrypt(clave, nonce, b"", p_conocido)
    c_secreto  = ascon.ascon_encrypt(clave, nonce, b"", p_secreto)

    # El atacante SOLO ve los dos ciphertext (y conoce p_conocido). No tiene la clave.
    # Como el keystream se repitió:  c1 ^ c2 == p1 ^ p2
    # => p_secreto = (c_conocido ^ c_secreto) ^ p_conocido
    #    (usamos solo la parte de datos: los primeros len(p) bytes, sin el tag)
    n = len(p_conocido)
    recuperado = xor(xor(c_conocido[:n], c_secreto[:n]), p_conocido)

    print(f"  lectura conocida por el atacante : {p_conocido!r}")
    print(f"  lectura SECRETA                  : {p_secreto!r}")
    print(f"  recuperada SIN la clave          : {recuperado!r}")
    print(f"  ¿ataque exitoso?                 : {recuperado == p_secreto}")
    print("  -> Con el nonce repetido, el XOR de ciphertexts revela el XOR de plaintexts.\n")


# --- El arreglo -------------------------------------------------------------
def cifrar_mal(clave, lectura, _nonce_fijo=b"\x00" * 16):
    """MAL: nonce fijo. Todos los mensajes comparten (clave, nonce)."""
    nonce = _nonce_fijo
    return nonce, ascon.ascon_encrypt(clave, nonce, b"", lectura)


def cifrar_bien(clave, lectura):
    """BIEN: nonce aleatorio fresco por mensaje, transmitido junto al ciphertext."""
    nonce = os.urandom(16)
    return nonce, ascon.ascon_encrypt(clave, nonce, b"", lectura)


def demo_C_el_arreglo():
    print("=" * 64)
    print("[C] El arreglo: un nonce fresco por mensaje")
    print("=" * 64)
    clave = os.urandom(16)
    lectura = b"GLUCOSA=120"

    n1, _ = cifrar_mal(clave, lectura)
    n2, _ = cifrar_mal(clave, lectura)
    print(f"  cifrar_mal  -> nonce #1 == nonce #2 ? {n1 == n2}   (siempre se repite: mal)")

    n3, _ = cifrar_bien(clave, lectura)
    n4, _ = cifrar_bien(clave, lectura)
    print(f"  cifrar_bien -> nonce #3 == nonce #4 ? {n3 == n4}   (nunca se repite: bien)")
    print("  Regla de oro: os.urandom(16) por cada mensaje y manda el nonce con el paquete.\n")


def demo_D_hash_integridad():
    print("=" * 64)
    print("[D] Bonus: Ascon-Hash256 para integridad de datos en reposo")
    print("=" * 64)
    firmware = b"firmware-v2.3-para-glucometro"
    huella = ascon.ascon_hash(firmware, variant="Ascon-Hash256")  # 32 bytes
    print(f"  huella Ascon-Hash256 ({len(huella)} bytes): {huella.hex()}")
    # Al cargar el firmware, recalculas la huella y comparas.
    print("  Verificación con firmware intacto :",
          ascon.ascon_hash(firmware) == huella)
    print("  Verificación con firmware alterado:",
          ascon.ascon_hash(firmware + b"!") == huella)
    print("  (Para autenticar con secreto, Ascon también ofrece Ascon-Mac/PRF.)")


def main():
    demo_A_mismo_mensaje()
    demo_B_recuperar_sin_clave()
    demo_C_el_arreglo()
    demo_D_hash_integridad()


if __name__ == "__main__":
    main()
