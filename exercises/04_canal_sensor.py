"""
Bloque 4 — Todo junto: un canal sensor -> servidor con Ascon   [VERSIÓN PARTICIPANTE]
====================================================================================

  [glucómetro]  --- socket TCP (localhost) --->  [servidor clínico]

Cada mensaje en el cable:  longitud(2) | nonce(16) | ciphertext+tag
  - clave PRE-COMPARTIDA, nonce fresco por mensaje (viaja en claro),
    AD = identificador del dispositivo.

La parte de sockets ya está lista. Tú completas las 2 líneas de criptografía.
"""

import os
import sys
import socket
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon


def __TODO__(msg):
    raise NotImplementedError("TODO: " + msg)


CLAVE_PRECOMPARTIDA = os.urandom(16)
DEVICE_ID = b"glucometro-07"
HOST = "127.0.0.1"


def enviar_frame(sock, payload):
    sock.sendall(len(payload).to_bytes(2, "big") + payload)


def recibir_exacto(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recibir_frame(sock):
    cab = recibir_exacto(sock, 2)
    if cab is None:
        return None
    return recibir_exacto(sock, int.from_bytes(cab, "big"))


def servidor(sock_servidor):
    conn, _ = sock_servidor.accept()
    with conn:
        while True:
            frame = recibir_frame(conn)
            if frame is None:
                break
            nonce, ciphertext = frame[:16], frame[16:]
            # TODO 1: descifra y verifica. AD = DEVICE_ID. Devuelve bytes o None.
            lectura = __TODO__("ascon.ascon_decrypt(CLAVE_PRECOMPARTIDA, nonce, DEVICE_ID, ciphertext)")
            if lectura is None:
                print("  [servidor] RECHAZADO: tag inválido (manipulado o corrupto)")
            else:
                print(f"  [servidor] ACEPTADO de {DEVICE_ID.decode()}: {lectura.decode()}")


def cifrar_lectura(valor: bytes):
    # TODO 2: nonce fresco + cifrado con AD=DEVICE_ID. Devuelve nonce + ciphertext.
    __TODO__("nonce = os.urandom(16); return nonce + ascon.ascon_encrypt(CLAVE_PRECOMPARTIDA, nonce, DEVICE_ID, valor)")


def sensor(puerto):
    with socket.create_connection((HOST, puerto)) as sock:
        for valor in (b"GLUCOSA=118", b"GLUCOSA=126", b"GLUCOSA=134"):
            enviar_frame(sock, cifrar_lectura(valor))
        # Atacante en el cable: voltea un byte del ciphertext.
        print("  [atacante] intercepta un mensaje y le altera un byte...")
        frame = bytearray(cifrar_lectura(b"GLUCOSA=999")); frame[20] ^= 0x01
        enviar_frame(sock, bytes(frame))


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, 0)); s.listen(1)
    puerto = s.getsockname()[1]
    hilo = threading.Thread(target=servidor, args=(s,)); hilo.start()
    print(f"Canal abierto en {HOST}:{puerto}\n")
    sensor(puerto)
    hilo.join(); s.close()
    print("\nLos 3 legítimos pasan; el manipulado se rechaza solo.")


if __name__ == "__main__":
    main()
