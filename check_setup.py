"""
Verificación de entorno — córrelo ANTES del taller.
    python3 check_setup.py

Si ves "TODO LISTO", estás preparado para la jornada.
"""

import sys
import os

MIN = (3, 10)


def fallo(msg):
    print("  [X] " + msg)


def main():
    ok = True
    print("Comprobando entorno para el taller de Ascon...\n")

    # 1) Versión de Python ----------------------------------------------------
    v = sys.version_info
    if (v.major, v.minor) >= MIN:
        print(f"  [OK] Python {v.major}.{v.minor}.{v.micro}")
    else:
        ok = False
        fallo(f"Python {v.major}.{v.minor} detectado; se requiere {MIN[0]}.{MIN[1]}+. "
              "Instala una versión más nueva o crea el venv con ella.")
        print("\nNo puedo seguir sin Python 3.10+. Corrige esto y vuelve a correr.")
        return

    # 2) cryptography (solo para el benchmark vs AES-GCM) ---------------------
    try:
        import cryptography  # noqa: F401
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        print(f"  [OK] cryptography {cryptography.__version__}")
    except Exception:
        ok = False
        fallo("falta 'cryptography'. Instálalo con:  pip install -r requirements.txt")

    # 3) Implementación de Ascon vendorizada ----------------------------------
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))
    try:
        import ascon
        k = os.urandom(16); n = os.urandom(16)
        pt = b"GLUCOSA=126"
        ct = ascon.ascon_encrypt(k, n, b"", pt, variant="Ascon-AEAD128")
        assert ascon.ascon_decrypt(k, n, b"", ct, variant="Ascon-AEAD128") == pt
        print("  [OK] Ascon-AEAD128 cifra y descifra correctamente")
    except Exception as e:
        ok = False
        fallo(f"no pude usar la implementación de Ascon en vendor/: {e!r}")

    print()
    if ok:
        print("TODO LISTO. Nos vemos en el taller.")
    else:
        print("Faltan cosas por resolver (revisa las líneas con [X] de arriba).")
        sys.exit(1)


if __name__ == "__main__":
    main()
