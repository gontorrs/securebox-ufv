# SecureBox

Herramienta CLI en Python para cifrado híbrido, firmas digitales y canal seguro. Soporta RSA-OAEP, X25519+HKDF, firmas Ed25519 y un protocolo de handshake con protección anti-MITM y anti-replay.

## Requisitos

```bash
pip install -r requirements.txt
```

## Comandos

### Generar claves

```bash
python securebox/cli.py keygen --type rsa  --out keys/receptor     --password <pass>
python securebox/cli.py keygen --type ecdh --out keys/receptor_ecc  --password <pass>
python securebox/cli.py keygen --type sign --out keys/firmante      --password <pass>
```

Tipos disponibles: `rsa` (RSA-2048/3072), `ecdh` (X25519), `sign` (Ed25519).

### Cifrar

```bash
# Modo A — RSA-OAEP + AES-256-GCM
python securebox/cli.py encrypt --input archivo.txt --output archivo.sbox --mode rsa --recipient-pub keys/receptor.pub.pem

# Modo B — X25519 + HKDF + AES-256-GCM
python securebox/cli.py encrypt --input archivo.txt --output archivo.sbox --mode ecc --recipient-pub keys/receptor_ecc.pub.pem
```

### Descifrar

```bash
python securebox/cli.py decrypt --input archivo.sbox --output recuperado.txt --priv-key keys/receptor.priv.pem --password <pass>
```

### Firmar y verificar

```bash
python securebox/cli.py sign   --input archivo.sbox --priv-key keys/firmante.priv.pem --password <pass>
python securebox/cli.py verify --input archivo.sbox --pub-key  keys/firmante.pub.pem
```

### Inspeccionar contenedor

```bash
python securebox/cli.py inspect archivo.sbox
```

Muestra metadatos (versión, modo, algoritmos, key_ids, estado de firma) sin revelar información secreta.

### Demo de canal seguro

```bash
python securebox/cli.py handshake-demo
```

Simula un handshake completo entre Alice y Bob: intercambio efímero X25519, derivación HKDF, autenticación del transcript Ed25519 y mensajes cifrados con AES-256-GCM.

### Ejecutar tests

```bash
pytest tests/
```

## Estructura del proyecto

```
securebox/
├── cli.py
├── keys.py
├── crypto/
│   ├── aead.py
│   ├── formats.py
│   ├── handshake.ipynb
│   ├── hybrid.py
│   ├── kdf.py
│   └── signatures.py
└── utils/
    ├── encoding.py
    └── io.py
tests/
├── test_keys.py
├── test_hybrid.py
├── test_signatures.py
```

## Algoritmos

| Componente | Algoritmo |
|---|---|
| Cifrado simétrico | AES-256-GCM |
| KEM Modo A | RSA-OAEP (SHA-256) |
| KEM Modo B | X25519 + HKDF-SHA256 |
| Firma digital | Ed25519 |
| Huella de clave | SHA-256 |
