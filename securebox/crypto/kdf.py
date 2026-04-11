import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Longitud de la clave derivada: 32 bytes = AES-256
KEY_LENGTH = 32

# Longitud del salt recomendada
SALT_SIZE = 32


def hkdf_derive_key(shared_secret, salt, info):
    """
    Deriva una clave AES-256 a partir de un shared_secret usando HKDF-SHA256.
    """
    if not isinstance(shared_secret, bytes) or len(shared_secret) == 0:
        raise ValueError("shared_secret debe ser bytes no vacíos")

    if not isinstance(salt, bytes) or len(salt) == 0:
        raise ValueError("salt debe ser bytes no vacíos")

    if not isinstance(info, bytes):
        raise ValueError("info debe ser bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        info=info,
    )

    return hkdf.derive(shared_secret)


def generate_salt():
    """
    Genera un salt aleatorio de 32 bytes.
    """
    return os.urandom(SALT_SIZE)