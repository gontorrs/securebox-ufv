from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .formats import build_manifest, add_signature, get_signature_bytes, key_fingerprint
from keys import pem_serialize_public_key

def sign_container(container, signer_private_key):
    """
    Firma el manifest del contenedor y añade la firma al propio contenedor.

    Soporta claves Ed25519 y RSA (con PSS).
    El manifest es un JSON ordenado con los campos críticos del contenedor.
    """
    # Construir el manifest que se va a firmar
    manifest_bytes = build_manifest(container)

    # Firmar según el tipo de clave
    if isinstance(signer_private_key, ed25519.Ed25519PrivateKey):
        algorithm_name = "ed25519"
        signature_bytes = _sign_ed25519(signer_private_key, manifest_bytes)

    elif isinstance(signer_private_key, rsa.RSAPrivateKey):
        algorithm_name = "rsa_pss_sha256"
        signature_bytes = _sign_rsa_pss(signer_private_key, manifest_bytes)

    else:
        raise ValueError(
            f"Tipo de clave de firma no soportado: {type(signer_private_key).__name__}. "
            f"Se aceptan: Ed25519, RSA."
        )

    # Calcular el key_id del firmante
    signer_pub_pem = pem_serialize_public_key(signer_private_key.public_key())
    signer_key_id = key_fingerprint(signer_pub_pem)

    # Añadir la firma al contenedor
    add_signature(container, algorithm_name, signer_key_id, signature_bytes)

    return container

def verify_container(container, signer_public_key):
    """
    Verifica la firma del contenedor .sbox.

    Reconstruye el manifest y comprueba que la firma sea válida.
    Falla si el contenedor no tiene firma, si fue modificado,
    o si la clave pública no corresponde al firmante.
    """
    if "signature" not in container:
        raise ValueError("El contenedor no contiene firma.")

    algorithm_name = container["signature"].get("algorithm")
    signature_bytes = get_signature_bytes(container)

    # Reconstruir el manifest (sin el campo 'signature')
    manifest_bytes = build_manifest(container)

    # Verificar según el algoritmo indicado en el contenedor
    if algorithm_name == "ed25519":
        if not isinstance(signer_public_key, ed25519.Ed25519PublicKey):
            raise ValueError(
                "El contenedor fue firmado con Ed25519 pero la clave "
                "proporcionada no es Ed25519."
            )
        _verify_ed25519(signer_public_key, manifest_bytes, signature_bytes)

    elif algorithm_name == "rsa_pss_sha256":
        if not isinstance(signer_public_key, rsa.RSAPublicKey):
            raise ValueError(
                "El contenedor fue firmado con RSA-PSS pero la clave "
                "proporcionada no es RSA."
            )
        _verify_rsa_pss(signer_public_key, manifest_bytes, signature_bytes)

    else:
        raise ValueError(
            f"Algoritmo de firma desconocido en el contenedor: '{algorithm_name}'."
        )

    return True

#Funciones helpers para firmar y verificar con Ed25519 y RSA-PSS, respectivamente.

def _sign_ed25519(private_key, data):
    """
    Firma datos con Ed25519.
    """
    return private_key.sign(data)


def _verify_ed25519(public_key, data, signature):
    """
    Verifica una firma Ed25519.
    """
    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        raise ValueError(
            "Firma Ed25519 inválida. El contenedor fue modificado "
            "o la clave pública no corresponde al firmante."
        )

def _sign_rsa_pss(private_key, data):
    """
    Firma datos con RSA-PSS (SHA-256).

    Usa salt_length=PSS.MAX_LENGTH para máxima seguridad.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _verify_rsa_pss(public_key, data, signature):
    """
    Verifica una firma RSA-PSS (SHA-256).
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise ValueError(
            "Firma RSA-PSS inválida. El contenedor fue modificado "
            "o la clave pública no corresponde al firmante."
        )