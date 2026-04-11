"""
test_hybrid.py — Pruebas para hybrid.py, aead.py y kdf.py (5 pruebas)

Unitarias (4):
  - AEAD cifrado/descifrado correcto
  - AEAD fallo con ciphertext modificado
  - KDF determinista con mismos parámetros
  - KDF produce claves distintas con distinto info

Integración (1):
  - Modo A: encrypt → decrypt ida y vuelta
"""

import pytest
import sys
import os
import base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'securebox'))

from securebox.keys import gen_rsa_private_key, gen_ecdh_keypair
from securebox.crypto.aead import aead_encrypt, aead_decrypt
from securebox.crypto.kdf import hkdf_derive_key
from securebox.crypto.hybrid import encrypt_mode_a, decrypt_mode_a

PLAINTEXT = b"Mensaje secreto de prueba para SecureBox."


# Unitarias

def test_aead_encrypt_decrypt():
    key = os.urandom(32)
    nonce, ciphertext = aead_encrypt(key, PLAINTEXT)
    assert aead_decrypt(key, nonce, ciphertext) == PLAINTEXT


def test_aead_modified_ciphertext_fails():
    key = os.urandom(32)
    nonce, ciphertext = aead_encrypt(key, PLAINTEXT)
    with pytest.raises(ValueError):
        aead_decrypt(key, nonce, b"\x00" * len(ciphertext))


def test_hkdf_is_deterministic():
    secret = os.urandom(32)
    salt = os.urandom(32)
    assert hkdf_derive_key(secret, salt, b"info") == hkdf_derive_key(secret, salt, b"info")


def test_hkdf_different_info_different_keys():
    secret = os.urandom(32)
    salt = os.urandom(32)
    assert hkdf_derive_key(secret, salt, b"contexto-a") != hkdf_derive_key(secret, salt, b"contexto-b")


# Integración

def test_mode_a_roundtrip():
    rsa_priv = gen_rsa_private_key(2048)
    container = encrypt_mode_a(PLAINTEXT, rsa_priv.public_key())
    assert decrypt_mode_a(container, rsa_priv) == PLAINTEXT