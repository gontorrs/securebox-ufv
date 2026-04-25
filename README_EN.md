# SecureBox
A Python CLI tool for hybrid encryption, digital signatures, and secure channel communication. Supports RSA-OAEP, X25519+HKDF, Ed25519 signatures, and a handshake protocol with anti-MITM and anti-replay protection.

## Requirements
```bash
pip install -r requirements.txt
```

## Commands

### Generate keys
```bash
python securebox/cli.py keygen --type rsa  --out keys/receptor     --password <pass>
python securebox/cli.py keygen --type ecdh --out keys/receptor_ecc  --password <pass>
python securebox/cli.py keygen --type sign --out keys/signer        --password <pass>
```
Available types: `rsa` (RSA-2048/3072), `ecdh` (X25519), `sign` (Ed25519).

### Encrypt
```bash
# Mode A — RSA-OAEP + AES-256-GCM
python securebox/cli.py encrypt --input file.txt --output file.sbox --mode rsa --recipient-pub keys/receptor.pub.pem

# Mode B — X25519 + HKDF + AES-256-GCM
python securebox/cli.py encrypt --input file.txt --output file.sbox --mode ecc --recipient-pub keys/receptor_ecc.pub.pem
```

### Decrypt
```bash
python securebox/cli.py decrypt --input file.sbox --output recovered.txt --priv-key keys/receptor.priv.pem --password <pass>
```

### Sign and verify
```bash
python securebox/cli.py sign   --input file.sbox --priv-key keys/signer.priv.pem --password <pass>
python securebox/cli.py verify --input file.sbox --pub-key  keys/signer.pub.pem
```

### Inspect container
```bash
python securebox/cli.py inspect file.sbox
```
Displays metadata (version, mode, algorithms, key_ids, signature status) without revealing any secret information.

### Secure channel demo
```bash
python securebox/cli.py handshake-demo
```
Simulates a full handshake between Alice and Bob: ephemeral X25519 exchange, HKDF derivation, Ed25519 transcript authentication, and AES-256-GCM encrypted messages.

### Run tests
```bash
pytest tests/
```

## Project structure
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
└── test_signatures.py
```

## Algorithms

| Component        | Algorithm           |
|------------------|---------------------|
| Symmetric cipher | AES-256-GCM         |
| KEM Mode A       | RSA-OAEP (SHA-256)  |
| KEM Mode B       | X25519 + HKDF-SHA256|
| Digital signature| Ed25519             |
| Key fingerprint  | SHA-256             |
