# SecureBox — Guía de uso

## Instalación

```bash
git clone https://github.com/tuusuario/securebox.git
cd securebox
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

---

## Comandos

Todos los comandos se ejecutan desde la raíz del proyecto con:

```bash
python3 securebox/cli.py <comando> [opciones]
```

---

### 1. Crear claves

**Clave RSA** (para cifrado Modo A):
```bash
python3 securebox/cli.py keygen --type rsa --out keys/receptor --password pass123
# Genera: keys/receptor.pub.pem y keys/receptor.priv.pem
```

**Clave X25519** (para cifrado Modo B):
```bash
python3 securebox/cli.py keygen --type ecdh --out keys/receptor_ecc --password pass123
# Genera: keys/receptor_ecc.pub.pem y keys/receptor_ecc.priv.pem
```

**Clave Ed25519** (para firmas):
```bash
python3 securebox/cli.py keygen --type sign --out keys/firmante --password pass123
# Genera: keys/firmante.pub.pem y keys/firmante.priv.pem
```

---

### 2. Cifrar un archivo

**Modo A — RSA-OAEP + AES-256-GCM:**
```bash
python3 securebox/cli.py encrypt \
  --input archivo.txt \
  --output archivo.sbox \
  --mode rsa \
  --recipient-pub keys/receptor.pub.pem
```

**Modo B — X25519 + HKDF + AES-256-GCM:**
```bash
python3 securebox/cli.py encrypt \
  --input archivo.txt \
  --output archivo.sbox \
  --mode ecc \
  --recipient-pub keys/receptor_ecc.pub.pem
```

---

### 3. Descifrar un archivo

El modo se detecta automáticamente a partir del contenedor `.sbox`.

**Modo A:**
```bash
python3 securebox/cli.py decrypt \
  --input archivo.sbox \
  --output archivo_recuperado.txt \
  --priv-key keys/receptor.priv.pem \
  --password pass123
```

**Modo B:**
```bash
python3 securebox/cli.py decrypt \
  --input archivo.sbox \
  --output archivo_recuperado.txt \
  --priv-key keys/receptor_ecc.priv.pem \
  --password pass123
```

---

### 4. Firmar un contenedor

```bash
python3 securebox/cli.py sign \
  --input archivo.sbox \
  --priv-key keys/firmante.priv.pem \
  --password pass123
```

La firma se guarda dentro del propio archivo `.sbox`.

---

### 5. Verificar una firma

```bash
python3 securebox/cli.py verify \
  --input archivo.sbox \
  --pub-key keys/firmante.pub.pem
```

---

### 6. Inspeccionar un contenedor

Muestra los metadatos del `.sbox` sin revelar información secreta:

```bash
python3 securebox/cli.py inspect archivo.sbox
```

Ejemplo de salida:
```
Versión:           sbox-1
Modo:              rsa_oaep
AEAD:              aes_256_gcm
KEM:               rsa_oaep_sha256
Receptor (key_id): 32a1b5a9...
Nonce (base64):    zFZ7wI5g2p859Quo
Tamaño ciphertext: 57 bytes
Wrapped key:       256 bytes
Firma algoritmo:   ed25519
Firmante (key_id): 7a55a065...
Firma (base64):    MEKB5...
```

---

### 7. Demo del canal seguro

Ejecuta una simulación completa del handshake entre Alice y Bob en local:

```bash
python3 securebox/cli.py handshake-demo
```

---

## Ejecutar los tests

```bash
python3 -m pytest tests/ -v
```

Resultado esperado: **21 passed**.

---

## Flujo completo de ejemplo

```bash
# 1. Crear claves
python3 securebox/cli.py keygen --type rsa  --out keys/bob   --password pass123
python3 securebox/cli.py keygen --type sign --out keys/alice --password pass123

# 2. Cifrar
python3 securebox/cli.py encrypt \
  --input secreto.txt --output secreto.sbox \
  --mode rsa --recipient-pub keys/bob.pub.pem

# 3. Firmar
python3 securebox/cli.py sign \
  --input secreto.sbox \
  --priv-key keys/alice.priv.pem --password pass123

# 4. Inspeccionar
python3 securebox/cli.py inspect secreto.sbox

# 5. Verificar
python3 securebox/cli.py verify \
  --input secreto.sbox --pub-key keys/alice.pub.pem

# 6. Descifrar
python3 securebox/cli.py decrypt \
  --input secreto.sbox --output secreto_recuperado.txt \
  --priv-key keys/bob.priv.pem --password pass123
```