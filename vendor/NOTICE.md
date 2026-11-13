# Implementación de Ascon (vendorizada)

El archivo `ascon.py` es la **implementación de referencia en Python** de Ascon,
escrita por Maria Eichlseder (una de las autoras del diseño Ascon), tomada de:

    https://github.com/meichlseder/pyascon

Licencia: **CC0 1.0 Universal** (dominio público). Ver `LICENSE`.

Implementa las primitivas estandarizadas en **NIST SP 800-232**:
Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 y Ascon-CXOF128.

Es una implementación de referencia en Python puro, pensada para ser *legible*
y didáctica, no para rendimiento. Justo lo que queremos para el taller.
