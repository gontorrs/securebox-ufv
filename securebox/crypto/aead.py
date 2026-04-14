import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Tamaño del nonce para AES-GCM: 12 bytes.
NONCE_SIZE = 12

def aead_encrypt(key_bytes, plaintext):
    """
    Cifra datos con AES-256-GCM con un nonce aleatorio de 12 bytes.
    """
    validate_key(key_bytes)

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key_bytes)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return nonce, ciphertext_with_tag

def aead_decrypt(key_bytes, nonce, ciphertext_with_tag):
    """
    Descifra y verifica datos con AES-256-GCM, en caso de que el ciphertext haya sido modificado o el tag no coincida, lanza una excepción.
    """
    validate_key(key_bytes)

    aesgcm = AESGCM(key_bytes)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    except Exception:
        raise ValueError("Fallo de autenticación AEAD: el ciphertext fue modificado o la clave/nonce son incorrectos.")

    return plaintext

def validate_key(key_bytes):
    """Verifica que la clave tenga exactamente 32 bytes (AES-256)."""
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise ValueError("La clave AEAD debe ser de 32 bytes (AES-256).")