
import os

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .aead import aead_encrypt, aead_decrypt
from .kdf import hkdf_derive_key, generate_salt
from .formats import build_container, save_container, load_container, get_nonce, get_ciphertext, get_kem_field, key_fingerprint
from keys import pem_serialize_public_key

#Contexto HKDF para Modo B
HKDF_INFO_MODE_B = b"securebox-v1-mode-b"

def encrypt_mode_a(plaintext, recipient_rsa_public_key):
    """
    Cifra con Modo A.
    """
    # Paso 1: generar clave AES-256 aleatoria
    aes_key = os.urandom(32)

    # Paso 2: cifrar los datos con AES-256-GCM
    nonce, ciphertext = aead_encrypt(aes_key, plaintext)

    # Paso 3: cifrar la clave AES con RSA-OAEP
    wrapped_key = recipient_rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Paso 4: calcular el key_id del receptor
    recipient_pub_pem = pem_serialize_public_key(recipient_rsa_public_key)
    recipient_key_id = key_fingerprint(recipient_pub_pem)

    # Paso 5: empaquetar en contenedor .sbox
    container = build_container(
        mode="rsa_oaep",
        aead_algorithm="aes_256_gcm",
        kem_algorithm="rsa_oaep_sha256",
        recipient_key_id=recipient_key_id,
        nonce=nonce,
        ciphertext=ciphertext,
        kem_data={"wrapped_key": wrapped_key},
    )

    return container


def decrypt_mode_a(container, recipient_rsa_private_key):
    """
    Descifra un contenedor .sbox cifrado en Modo A.
    """
    if container.get("mode") != "rsa_oaep":
        raise ValueError(
            f"Este contenedor es modo '{container.get('mode')}', no 'rsa_oaep'."
        )

    # Paso 1: recuperar la clave AES descifrando wrapped_key con RSA-OAEP
    wrapped_key = get_kem_field(container, "wrapped_key")
    try:
        aes_key = recipient_rsa_private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        raise ValueError(
            "No se pudo descifrar la clave envuelta (wrapped_key). "
            "¿Es correcta la clave privada RSA del receptor?"
        )

    # Paso 2: descifrar los datos con AES-256-GCM
    nonce = get_nonce(container)
    ciphertext = get_ciphertext(container)
    plaintext = aead_decrypt(aes_key, nonce, ciphertext)

    return plaintext

def encrypt_mode_b(plaintext, recipient_x25519_public_key):
    """
    Cifra datos con Modo B.
    """
    # Paso 1: generar par X25519 efímero (solo para este mensaje)
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    # Paso 2: calcular shared_secret con la clave pública del receptor
    shared_secret = ephemeral_private.exchange(recipient_x25519_public_key)

    # Paso 3: derivar clave AES-256 con HKDF
    salt = generate_salt()
    aes_key = hkdf_derive_key(shared_secret, salt, HKDF_INFO_MODE_B)

    # Paso 4: cifrar los datos con AES-256-GCM
    nonce, ciphertext = aead_encrypt(aes_key, plaintext)

    # Paso 5: serializar la clave efímera pública para incluirla en el contenedor
    ephemeral_pub_bytes = ephemeral_public.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # Paso 6: calcular el key_id del receptor
    recipient_pub_pem = pem_serialize_public_key(recipient_x25519_public_key)
    recipient_key_id = key_fingerprint(recipient_pub_pem)

    # Paso 7: empaquetar en contenedor .sbox
    container = build_container(
        mode="ecc_hkdf",
        aead_algorithm="aes_256_gcm",
        kem_algorithm="x25519_hkdf_sha256",
        recipient_key_id=recipient_key_id,
        nonce=nonce,
        ciphertext=ciphertext,
        kem_data={
            "ephemeral_pubkey": ephemeral_pub_bytes,
            "salt": salt,
        },
    )

    return container


def decrypt_mode_b(container, recipient_x25519_private_key):
    """
    Descifra un contenedor .sbox cifrado en Modo B (ECC KEM/DEM).
    """
    if container.get("mode") != "ecc_hkdf":
        raise ValueError(
            f"Este contenedor es modo '{container.get('mode')}', no 'ecc_hkdf'."
        )

    # Paso 1: recuperar la clave efímera pública del emisor
    ephemeral_pub_bytes = get_kem_field(container, "ephemeral_pubkey")
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

    # Paso 2: calcular el mismo shared_secret que calculó el emisor
    shared_secret = recipient_x25519_private_key.exchange(ephemeral_public)

    # Paso 3: derivar la misma clave AES-256 con HKDF
    salt = get_kem_field(container, "salt")
    aes_key = hkdf_derive_key(shared_secret, salt, HKDF_INFO_MODE_B)

    # Paso 4: descifrar los datos con AES-256-GCM
    nonce = get_nonce(container)
    ciphertext = get_ciphertext(container)
    plaintext = aead_decrypt(aes_key, nonce, ciphertext)

    return plaintext

# Uso helpers para ciffrar y descifrar archivos completos con Modo A y Modo B, respectivamente.

def encrypt_file_mode_a(input_path, output_path, recipient_rsa_public_key):
    """Lee un archivo, lo cifra en Modo A y guarda el .sbox."""
    with open(input_path, "rb") as f:
        plaintext = f.read()

    container = encrypt_mode_a(plaintext, recipient_rsa_public_key)
    save_container(container, output_path)


def decrypt_file_mode_a(input_path, output_path, recipient_rsa_private_key):
    """Lee un .sbox, lo descifra en Modo A y guarda el archivo original."""
    container = load_container(input_path)
    plaintext = decrypt_mode_a(container, recipient_rsa_private_key)

    with open(output_path, "wb") as f:
        f.write(plaintext)


def encrypt_file_mode_b(input_path, output_path, recipient_x25519_public_key):
    """Lee un archivo, lo cifra en Modo B y guarda el .sbox."""
    with open(input_path, "rb") as f:
        plaintext = f.read()

    container = encrypt_mode_b(plaintext, recipient_x25519_public_key)
    save_container(container, output_path)


def decrypt_file_mode_b(input_path, output_path, recipient_x25519_private_key):
    """Lee un .sbox, lo descifra en Modo B y guarda el archivo original."""
    container = load_container(input_path)
    plaintext = decrypt_mode_b(container, recipient_x25519_private_key)

    with open(output_path, "wb") as f:
        f.write(plaintext)