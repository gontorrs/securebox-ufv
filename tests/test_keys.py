import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'securebox'))

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, x25519

from securebox.keys import (
    gen_rsa_private_key,
    gen_ecdh_keypair,
    gen_sign_keypair,
    pem_serialize_public_key,
    pem_serialize_encrypted_private_key,
    pem_load_public_key,
    pem_load_private_key,
)

PASSWORD = b"ufv_2026"

# Unitarias

def test_gen_rsa_2048():
    key = gen_rsa_private_key(key_size=2048)
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_gen_ecdh_keypair():
    priv, pub = gen_ecdh_keypair()
    assert isinstance(priv, x25519.X25519PrivateKey)
    assert isinstance(pub, x25519.X25519PublicKey)


def test_gen_sign_keypair():
    priv, pub = gen_sign_keypair()
    assert isinstance(priv, ed25519.Ed25519PrivateKey)
    assert isinstance(pub, ed25519.Ed25519PublicKey)


def test_serialize_load_rsa_public_key():
    key = gen_rsa_private_key()
    pem = pem_serialize_public_key(key.public_key())
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    loaded = pem_load_public_key(pem)
    assert isinstance(loaded, rsa.RSAPublicKey)


def test_private_key_encrypted_on_disk():
    key = gen_rsa_private_key()
    pem = pem_serialize_encrypted_private_key(key, PASSWORD)
    assert b"ENCRYPTED" in pem


def test_load_private_key_correct_password():
    key = gen_rsa_private_key()
    pem = pem_serialize_encrypted_private_key(key, PASSWORD)
    loaded = pem_load_private_key(pem, PASSWORD)
    assert isinstance(loaded, rsa.RSAPrivateKey)


# Negativas

def test_load_private_key_wrong_password():
    key = gen_rsa_private_key()
    pem = pem_serialize_encrypted_private_key(key, PASSWORD)
    with pytest.raises(ValueError):
        pem_load_private_key(pem, b"contrasena_incorrecta")