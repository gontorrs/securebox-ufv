from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, x25519
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Generación de claves
# ---------------------------------------------------------------------------

def gen_rsa_private_key(key_size=2048):
    """
    Generamos una clave privada RSA.
    """
    if key_size not in (2048, 3072):
        raise ValueError(f"key_size debe ser 2048 o 3072, recibido: {key_size}")

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


# ---------------------------------------------------------------------------
# Serialización
# ---------------------------------------------------------------------------

def pem_serialize_public_key(public_key):
    """
    Serializamos una clave pública a bytes PEM, acepta claves RSA, X25519 y Ed25519.
    """
    _validate_public_key(public_key)

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pem_serialize_encrypted_private_key(private_key, password_bytes):
    """
    Serializamos una clave privada a bytes PEM, cifrada con contraseña.
    Usamos BestAvailableEncryption (scrypt + AES).
    """
    _validate_private_key(private_key)

    if not isinstance(password_bytes, bytes):
        raise TypeError("password_bytes debe ser de tipo bytes")

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes),
    )


# ---------------------------------------------------------------------------
# Carga desde disco
# ---------------------------------------------------------------------------

def pem_load_public_key(pem_bytes):
    """
    Carga una clave pública desde bytes PEM.
    Acepta RSA, X25519 y Ed25519. Valida que sea un tipo reconocido.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    public_key = load_pem_public_key(pem_bytes)
    _validate_public_key(public_key)
    return public_key


def pem_load_private_key(pem_bytes, password_bytes):
    """
    Carga una clave privada cifrada desde bytes PEM.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if not isinstance(password_bytes, bytes):
        raise TypeError("password_bytes debe ser de tipo bytes")

    try:
        private_key = load_pem_private_key(pem_bytes, password=password_bytes)
    except (ValueError, TypeError) as e:
        raise ValueError(f"No se pudo cargar la clave privada: {e}")

    _validate_private_key(private_key)
    return private_key


# ---------------------------------------------------------------------------
# Utilidades internas de validación
# ---------------------------------------------------------------------------

# Tipos de clave pública aceptados
_VALID_PUBLIC_KEY_TYPES = (
    rsa.RSAPublicKey,
    x25519.X25519PublicKey,
    ed25519.Ed25519PublicKey,
)

# Tipos de clave privada aceptados
_VALID_PRIVATE_KEY_TYPES = (
    rsa.RSAPrivateKey,
    x25519.X25519PrivateKey,
    ed25519.Ed25519PrivateKey,
)


def _validate_public_key(public_key):
    """Lanza ValueError si la clave pública no es de un tipo aceptado."""
    if not isinstance(public_key, _VALID_PUBLIC_KEY_TYPES):
        raise ValueError(
            f"Tipo de clave pública no soportado: {type(public_key).__name__}. "
            f"Se aceptan: RSA, X25519, Ed25519."
        )


def _validate_private_key(private_key):
    """Lanza ValueError si la clave privada no es de un tipo aceptado."""
    if not isinstance(private_key, _VALID_PRIVATE_KEY_TYPES):
        raise ValueError(
            f"Tipo de clave privada no soportado: {type(private_key).__name__}. "
            f"Se aceptan: RSA, X25519, Ed25519."
        )