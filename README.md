# Criptografía UFV — Prácticas Python

Este repositorio contiene las prácticas de criptografía con Python de la asignatura de Criptografía de la Universidad Francisco de Vitoria.

## Ramas

| Rama | Contenido |
|------|-----------|
| `master` | **Práctica 2 completa — SecureBox**: cifrado híbrido (RSA-OAEP + AES-256-GCM y X25519 + HKDF + AES-256-GCM), firmas digitales (Ed25519 / RSA-PSS), canal seguro con handshake y autenticación mutua, 21 tests con pytest. |
| `mini-rsa` | **Práctica RSA básica**: script independiente que implementa generación de claves RSA, serialización PEM y cifrado/descifrado asimétrico con RSA-OAEP. |

---

## Rama actual: `mini-rsa`

Práctica individual sobre el uso de la librería `cryptography` para RSA.

### Contenido

- `main.py` — script con las funciones implementadas y demo ejecutable

### Funciones implementadas

- `gen_priv_key()` — genera clave privada RSA (2048 bits, exponente 65537)
- `gen_pub_key(private_key)` — obtiene la clave pública
- `pem_serialize_pub_key(pk)` — serializa clave pública a PEM
- `pem_serialize_enc_priv_key(sk, pwd)` — serializa y cifra clave privada a PEM
- `pem_load_pub_key(pem_bytes)` — carga clave pública desde PEM
- `pem_load_priv_key(pem_bytes, pwd)` — carga clave privada cifrada desde PEM
- `rsa_encrypt(public_key, plaintext_bytes)` — cifrado RSA-OAEP (SHA-256)
- `rsa_decrypt(private_key, ciphertext)` — descifrado RSA-OAEP (SHA-256)

### Requisitos

```bash
pip install cryptography
```

### Ejecución

```bash
python main.py
```

El script genera las claves, las serializa, cifra un mensaje de ejemplo y lo descifra, imprimiendo todos los valores relevantes por pantalla.

---

> Para ver la práctica completa de SecureBox, cambia a la rama `master`.