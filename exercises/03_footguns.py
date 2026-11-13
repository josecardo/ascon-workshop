"""
Bloque 3 — El footgun principal: reutilizar el nonce   [VERSIÓN PARTICIPANTE]
============================================================================

Regla de oro de Ascon (y de todo AEAD de flujo):
    nunca uses el mismo (clave, nonce) para dos mensajes distintos.

Si lo repites, el keystream se repite y se filtra información SIN la clave.
En este bloque vas a (B) completar el ataque que lo demuestra y (C) escribir
el arreglo. Las partes A y D ya están resueltas para que las leas y corras.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon


def __TODO__(msg):
    raise NotImplementedError("TODO: " + msg)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def demo_A_mismo_mensaje():
    print("[A] Reutilizar nonce con el MISMO mensaje -> fuga de patrones")
    clave = os.urandom(16); nonce = os.urandom(16)
    lectura = b"GLUCOSA=120"
    c1 = ascon.ascon_encrypt(clave, nonce, b"", lectura)
    c2 = ascon.ascon_encrypt(clave, nonce, b"", lectura)
    print(f"  ¿ciphertexts idénticos? {c1 == c2}  -> un espía ve lecturas repetidas.\n")


def demo_B_recuperar_sin_clave():
    print("[B] Reutilizar nonce con mensajes DISTINTOS -> recuperación total")
    clave = os.urandom(16); nonce = os.urandom(16)   # el MISMO nonce para ambos

    p_conocido = b"GLUCOSA=082"   # el atacante la conoce (<=16 bytes -> 1 bloque)
    p_secreto  = b"GLUCOSA=350"   # esta la quiere averiguar

    c_conocido = ascon.ascon_encrypt(clave, nonce, b"", p_conocido)
    c_secreto  = ascon.ascon_encrypt(clave, nonce, b"", p_secreto)
    n = len(p_conocido)

    # El atacante solo tiene: c_conocido, c_secreto y p_conocido. NO tiene la clave.
    # Pista: con nonce repetido  ->  c1 ^ c2 == p1 ^ p2
    # TODO B: despeja p_secreto usando la función xor() y los primeros n bytes.
    recuperado = __TODO__("recupera p_secreto: xor(xor(c_conocido[:n], c_secreto[:n]), p_conocido)")

    print(f"  secreta real      : {p_secreto!r}")
    print(f"  recuperada (sin clave): {recuperado!r}")
    print(f"  ¿ataque exitoso?  : {recuperado == p_secreto}\n")


def cifrar_mal(clave, lectura, _nonce_fijo=b"\x00" * 16):
    """MAL: nonce fijo -> todos los mensajes comparten (clave, nonce)."""
    return _nonce_fijo, ascon.ascon_encrypt(clave, _nonce_fijo, b"", lectura)


def cifrar_bien(clave, lectura):
    """BIEN: nonce fresco por mensaje, devuelto junto al ciphertext."""
    # TODO C (mini-reto): genera un nonce aleatorio de 16 bytes y cifra con él.
    #   Devuelve (nonce, ciphertext).
    __TODO__("usa os.urandom(16) como nonce y devuelve (nonce, ascon.ascon_encrypt(clave, nonce, b'', lectura))")


def demo_C_el_arreglo():
    print("[C] El arreglo: un nonce fresco por mensaje")
    clave = os.urandom(16); lectura = b"GLUCOSA=120"
    n1, _ = cifrar_mal(clave, lectura); n2, _ = cifrar_mal(clave, lectura)
    print(f"  cifrar_mal  -> nonces iguales? {n1 == n2}  (siempre: mal)")
    n3, _ = cifrar_bien(clave, lectura); n4, _ = cifrar_bien(clave, lectura)
    print(f"  cifrar_bien -> nonces iguales? {n3 == n4}  (nunca: bien)\n")


def demo_D_hash_integridad():
    print("[D] Bonus: Ascon-Hash256 para integridad en reposo")
    fw = b"firmware-v2.3-para-glucometro"
    huella = ascon.ascon_hash(fw, variant="Ascon-Hash256")
    print(f"  intacto : {ascon.ascon_hash(fw) == huella}")
    print(f"  alterado: {ascon.ascon_hash(fw + b'!') == huella}")


def main():
    demo_A_mismo_mensaje()
    demo_B_recuperar_sin_clave()
    demo_C_el_arreglo()
    demo_D_hash_integridad()


if __name__ == "__main__":
    main()
