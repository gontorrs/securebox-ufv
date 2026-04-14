from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

def gen_rsa_private_key(key_size=2048):
    """
    Generamos una clave privada RSA, no validamos el tamaño porque cryptography lo hace internamente.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

def gen_ecdh_keypair():
    """
    Generamos un par de claves X25519 para ECDH (intercambio de clave).
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def gen_sign_keypair():
    """
    Generamos un par de claves Ed25519 para firmas digitales.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def pem_serialize_public_key(public_key):
    """
    Serializamos una clave pública a bytes PEM, acepta claves RSA, X25519 y Ed25519.
    """

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def pem_serialize_encrypted_private_key(private_key, password_bytes):
    """
    Serializamos una clave privada a bytes PEM, cifrada con contraseña.
    Usamos BestAvailableEncryption (scrypt + AES).
    """

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes),
    )

def pem_load_public_key(pem_bytes):
    """
    Carga una clave pública desde bytes PEM.
    Acepta RSA, X25519 y Ed25519. Valida que sea un tipo reconocido.
    """
    public_key = load_pem_public_key(pem_bytes)
    return public_key

def pem_load_private_key(pem_bytes, password_bytes):
    """
    Carga una clave privada cifrada desde bytes PEM.
    """
    private_key = load_pem_private_key(pem_bytes, password=password_bytes)
    return private_key