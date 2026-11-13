# Cifra como un marcapasos: AEAD ligero con Ascon en Python

Taller práctico (90 min) — **PyCon Chile 2026**

Aprende a cifrar la telemetría de un dispositivo médico simulado con **Ascon**,
el estándar de criptografía ligera de NIST (**SP 800-232**, finalizado en agosto
de 2025). De la operación básica de cifrado autenticado (AEAD) a un canal
sensor → servidor completo, pasando por los errores que hacen inseguro a
cualquier AEAD.

> **No necesitas saber criptografía para empezar.** Sí necesitas Python básico.

---

## Antes de llegar (setup de ~10 min)

Requisito: **Python 3.10 o superior**.

```bash
# 1. Entra a la carpeta del taller y crea un entorno virtual
python3 -m venv .venv
source .venv/bin/activate        # en Windows:  .venv\Scripts\activate

# 2. Instala la única dependencia externa (para el benchmark vs AES-GCM)
pip install -r requirements.txt

# 3. Verifica que todo esté listo
python3 check_setup.py
```

Si ves `TODO LISTO`, estás preparado. **Todo corre offline**: no hace falta WiFi
durante el taller.

---

## Cómo trabajamos

- Tú escribes en **`exercises/`**: cada archivo tiene unos pocos `# TODO` con la
  pista al lado. Al correr un ejercicio sin completar, el programa te lleva
  exactamente a la línea que falta.
- Si te atascas o quieres comparar, la versión completa está en **`solutions/`**.

```
ascon-workshop/
├── check_setup.py          # verifica tu entorno
├── requirements.txt        # cryptography (solo para el benchmark)
├── vendor/
│   ├── ascon.py            # implementación de referencia de Ascon (ver NOTICE.md)
│   ├── NOTICE.md
│   └── LICENSE             # CC0 1.0
├── exercises/              # <-- tú trabajas aquí (con TODOs)
│   ├── 01_primeros_pasos.py
│   ├── 02_datos_asociados.py
│   ├── 03_footguns.py
│   └── 04_canal_sensor.py
└── solutions/              # versiones completas + benchmark
    ├── 01_primeros_pasos.py
    ├── 02_datos_asociados.py
    ├── 03_footguns.py
    ├── 04_canal_sensor.py
    └── benchmark.py
```

---

## Ruta del taller (90 min)

| Bloque | Tiempo | Archivo | Qué haces |
|-------|--------|---------|-----------|
| 1. Primeros pasos | ~15' | `01_primeros_pasos.py` | Cifrar/descifrar una lectura con Ascon-AEAD128; ver el tag y la detección de cambios |
| 2. Datos asociados | ~15' | `02_datos_asociados.py` | Autenticar la cabecera en claro (AD) y comprobar que queda protegida |
| 3. Footguns | ~15' | `03_footguns.py` | Romper el cifrado reutilizando el nonce y luego arreglarlo (mini-reto) |
| 4. Canal completo | ~15' | `04_canal_sensor.py` | Un canal sensor → servidor por sockets que rechaza mensajes manipulados |
| + Benchmark | — | `solutions/benchmark.py` | Ascon vs AES-GCM: overhead, velocidad y el matiz importante |

Los ~15 minutos iniciales son setup/contexto y los finales, cierre y preguntas.

Para correr un bloque:

```bash
python3 exercises/01_primeros_pasos.py      # tu versión
python3 solutions/01_primeros_pasos.py      # la solución
python3 solutions/benchmark.py              # el benchmark (listo para correr)
```

---

## Sobre la implementación de Ascon

`vendor/ascon.py` es la **implementación de referencia en Python** de Ascon,
de Maria Eichlseder (coautora del diseño): <https://github.com/meichlseder/pyascon>.
Licencia **CC0 1.0** (dominio público). Es Python puro, pensada para ser legible
—ideal para aprender—, **no para rendimiento**.

Por eso el benchmark incluye una advertencia explícita: comparar la velocidad de
Python puro contra el AES-GCM de OpenSSL (C + hardware) no refleja el caso real
de Ascon, que son microcontroladores pequeños sin acelerador AES. La ventaja de
Ascon se mide en energía, memoria y área de silicio en el dispositivo objetivo,
no en throughput de CPython.

## Para seguir después

- NIST SP 800-232 (el estándar): <https://csrc.nist.gov/pubs/sp/800/232/final>
- Página del proyecto Ascon: <https://ascon.iaik.tugraz.at/>
