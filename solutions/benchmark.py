"""
Benchmark — Ascon-AEAD128  vs  AES-128-GCM
==========================================

Comparamos la primitiva nueva (Ascon, SP 800-232) con el caballo de batalla
actual (AES-GCM) en dos ejes: OVERHEAD de tamaño y VELOCIDAD.

================  LEE ESTO ANTES DE SACAR CONCLUSIONES  ========================
La comparación de VELOCIDAD en Python es ENGAÑOSA y hay que decirlo en voz alta:

  - `ascon.py` es una implementación de REFERENCIA en Python PURO, escrita para
    ser legible, no rápida.
  - AES-GCM de `cryptography` corre sobre OpenSSL en C, y además la mayoría de
    las CPUs tienen instrucciones AES por hardware (AES-NI).

=> En un PC, AES-GCM va a ganar por órdenes de magnitud. Eso NO dice nada sobre
   el caso que a Ascon le importa: microcontroladores pequeños SIN acelerador
   AES, donde se mide energía, RAM y área de silicio (gate count), no throughput
   en CPython. Ahí es donde Ascon fue diseñado para brillar.

Moraleja para el taller: este benchmark sirve para comparar OVERHEAD y para
entender la API; para rendimiento real hay que medir en el dispositivo objetivo
con una implementación optimizada (C/ensamblador o hardware).
===============================================================================
"""

import os
import sys
import timeit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MENSAJE = b"GLUCOSA=126 mg/dL;ts=2026-10-10T08:15:00Z"
N = 2000


def overhead():
    clave = os.urandom(16)
    nonce = os.urandom(16)

    ct_ascon = ascon.ascon_encrypt(clave, nonce, b"", MENSAJE)
    ct_aes = AESGCM(clave).encrypt(nonce[:12], MENSAJE, None)  # AES-GCM usa nonce de 12 bytes

    print("OVERHEAD DE TAMAÑO (plaintext =", len(MENSAJE), "bytes)")
    print(f"  Ascon-AEAD128 : {len(ct_ascon)} bytes  (+{len(ct_ascon) - len(MENSAJE)} de tag)")
    print(f"  AES-128-GCM   : {len(ct_aes)} bytes  (+{len(ct_aes) - len(MENSAJE)} de tag)")
    print("  -> Ambos agregan un tag de 16 bytes. Empate: el overhead por mensaje es idéntico.\n")


def velocidad():
    clave = os.urandom(16)
    nonce = os.urandom(16)
    aesgcm = AESGCM(clave)

    t_ascon = timeit.timeit(lambda: ascon.ascon_encrypt(clave, nonce, b"", MENSAJE), number=N)
    t_aes = timeit.timeit(lambda: aesgcm.encrypt(nonce[:12], MENSAJE, None), number=N)

    print(f"VELOCIDAD ({N} cifrados en este PC)")
    print(f"  Ascon-AEAD128 (Python puro)   : {t_ascon*1e3:8.1f} ms  "
          f"({t_ascon/N*1e6:7.1f} us/op)")
    print(f"  AES-128-GCM   (OpenSSL/AES-NI) : {t_aes*1e3:8.1f} ms  "
          f"({t_aes/N*1e6:7.1f} us/op)")
    print(f"  Factor         : AES-GCM ~{t_ascon/t_aes:,.0f}x más rápido AQUÍ.")
    print("  (!) Comparación de manzanas con naranjas: Python puro vs C+hardware.")
    print("      En un MCU sin AES-NI el panorama cambia por completo. Ver cabecera.\n")


def tabla_conceptual():
    print("POR QUÉ ASCON EN DISPOSITIVOS RESTRINGIDOS (lo que el benchmark NO mide)")
    filas = [
        ("Estado interno",        "320 bits (5 palabras de 64)", "128 bits + tablas"),
        ("Primitiva",             "1 permutación para todo",     "cifrado por bloques + GHASH"),
        ("¿Necesita HW dedicado?", "no, eficiente en SW",         "ideal con AES-NI; costoso sin él"),
        ("Resistencia side-channel","diseñada con enmascaramiento barato", "requiere contramedidas extra"),
    ]
    ancho = max(len(f[0]) for f in filas)
    print(f"  {'':<{ancho}} | {'Ascon-AEAD128':<32} | AES-128-GCM")
    print(f"  {'-'*ancho}-+-{'-'*32}-+-{'-'*28}")
    for a, b, c in filas:
        print(f"  {a:<{ancho}} | {b:<32} | {c}")


def main():
    overhead()
    velocidad()
    tabla_conceptual()


if __name__ == "__main__":
    main()
