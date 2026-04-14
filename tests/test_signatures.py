import pytest
import sys
import os
import base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'securebox'))

from securebox.keys import gen_rsa_private_key, gen_ecdh_keypair, gen_sign_keypair
from securebox.crypto.hybrid import encrypt_mode_a, encrypt_mode_b
from securebox.crypto.signatures import sign_container, verify_container

PLAINTEXT = b"Esto es lo que hay que firmar en SecureBox."


# Integración

def test_ed25519_sign_verify():
    rsa_priv = gen_rsa_private_key(2048)
    ed_priv, ed_pub = gen_sign_keypair()
    container = encrypt_mode_a(PLAINTEXT, rsa_priv.public_key())
    sign_container(container, ed_priv)
    assert verify_container(container, ed_pub) is True


def test_rsa_pss_sign_verify():
    x_priv, x_pub = gen_ecdh_keypair()
    rsa_sign_priv = gen_rsa_private_key(2048)
    container = encrypt_mode_b(PLAINTEXT, x_pub)
    sign_container(container, rsa_sign_priv)
    assert verify_container(container, rsa_sign_priv.public_key()) is True


# Negativas

def test_verify_wrong_public_key_fails():
    rsa_priv = gen_rsa_private_key(2048)
    ed_priv, _ = gen_sign_keypair()
    _, ed_pub_wrong = gen_sign_keypair()
    container = encrypt_mode_a(PLAINTEXT, rsa_priv.public_key())
    sign_container(container, ed_priv)
    with pytest.raises(ValueError):
        verify_container(container, ed_pub_wrong)


def test_verify_modified_ciphertext_fails():
    rsa_priv = gen_rsa_private_key(2048)
    ed_priv, ed_pub = gen_sign_keypair()
    container = encrypt_mode_a(PLAINTEXT, rsa_priv.public_key())
    sign_container(container, ed_priv)
    container["ciphertext"] = base64.b64encode(b"manipulado").decode()
    with pytest.raises(ValueError):
        verify_container(container, ed_pub)


def test_verify_no_signature_fails():
    rsa_priv = gen_rsa_private_key(2048)
    _, ed_pub = gen_sign_keypair()
    container = encrypt_mode_a(PLAINTEXT, rsa_priv.public_key())
    with pytest.raises(ValueError, match="no contiene firma"):
        verify_container(container, ed_pub)