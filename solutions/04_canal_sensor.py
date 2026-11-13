"""
Bloque 4 — Todo junto: un canal sensor -> servidor con Ascon
============================================================

Juntamos todo lo anterior en un mini-sistema realista:

  [glucómetro]  --- socket TCP (localhost) --->  [servidor clínico]

Cada mensaje que viaja por el cable es:
      longitud (2 bytes) | nonce (16 bytes) | ciphertext+tag

  - La clave es PRE-COMPARTIDA (simulamos que se provisionó en el dispositivo).
  - El nonce es fresco por mensaje (aprendimos por qué en el bloque 3) y viaja en claro.
  - El AD autentica el identificador del dispositivo.
  - El servidor descifra; si el tag no cuadra, RECHAZA el mensaje.

Todo corre en localhost con hilos -> cero dependencias, funciona sin WiFi.
"""

import os
import sys
import socket
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vendor"))
import ascon

CLAVE_PRECOMPARTIDA = os.urandom(16)   # dispositivo <-> servidor
DEVICE_ID = b"glucometro-07"           # va como associated data (autenticado, en claro)
HOST = "127.0.0.1"


# --- utilidades de framing (longitud + datos) -------------------------------
def enviar_frame(sock: socket.socket, payload: bytes):
    sock.sendall(len(payload).to_bytes(2, "big") + payload)


def recibir_exacto(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recibir_frame(sock: socket.socket):
    cabecera = recibir_exacto(sock, 2)
    if cabecera is None:
        return None
    longitud = int.from_bytes(cabecera, "big")
    return recibir_exacto(sock, longitud)


# --- servidor ---------------------------------------------------------------
def servidor(sock_servidor: socket.socket):
    conn, _ = sock_servidor.accept()
    with conn:
        while True:
            frame = recibir_frame(conn)
            if frame is None:
                break
            nonce, ciphertext = frame[:16], frame[16:]
            lectura = ascon.ascon_decrypt(CLAVE_PRECOMPARTIDA, nonce, DEVICE_ID,
                                          ciphertext, variant="Ascon-AEAD128")
            if lectura is None:
                print(f"  [servidor] RECHAZADO: tag inválido (mensaje manipulado o corrupto)")
            else:
                print(f"  [servidor] ACEPTADO de {DEVICE_ID.decode()}: {lectura.decode()}")


# --- sensor (cliente) -------------------------------------------------------
def cifrar_lectura(valor: bytes):
    nonce = os.urandom(16)  # fresco por mensaje
    ciphertext = ascon.ascon_encrypt(CLAVE_PRECOMPARTIDA, nonce, DEVICE_ID,
                                     valor, variant="Ascon-AEAD128")
    return nonce + ciphertext


def sensor(puerto: int):
    with socket.create_connection((HOST, puerto)) as sock:
        lecturas = [b"GLUCOSA=118", b"GLUCOSA=126", b"GLUCOSA=134"]
        for valor in lecturas:
            enviar_frame(sock, cifrar_lectura(valor))

        # --- Simulamos un atacante en el cable (MITM) --------------------
        # Toma un mensaje legítimo y le voltea un byte del ciphertext.
        print("  [atacante] intercepta un mensaje y le altera un byte...")
        frame = bytearray(cifrar_lectura(b"GLUCOSA=999"))
        frame[20] ^= 0x01   # un bit dentro del ciphertext
        enviar_frame(sock, bytes(frame))


def main():
    sock_servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_servidor.bind((HOST, 0))          # puerto efímero libre
    sock_servidor.listen(1)
    puerto = sock_servidor.getsockname()[1]

    hilo = threading.Thread(target=servidor, args=(sock_servidor,))
    hilo.start()

    print(f"Canal abierto en {HOST}:{puerto}\n")
    sensor(puerto)

    hilo.join()
    sock_servidor.close()
    print("\nLos 3 mensajes legítimos pasaron; el manipulado fue rechazado automáticamente.")


if __name__ == "__main__":
    main()
