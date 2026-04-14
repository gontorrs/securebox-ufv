"""
El formato .sbox es un JSON con valores binarios en Base64 y contiene todo lo necesario para descifrar y verificar el archvio, salvo la calve privada del receptor.

Estructura del contenedor:
{
    "version":          "sbox-1",
    "mode":             "rsa_oaep" | "ecc_hkdf",
    "algorithms": {
        "aead":         "aes_256_gcm",
        "kem":          "rsa_oaep_sha256" | "x25519_hkdf_sha256"
    },
    "recipient_key_id": "<hex SHA-256 de la clave pública del receptor>",
    "nonce":            "<base64>",
    "ciphertext":       "<base64>",
    "kem_data": {
        // Modo A (RSA):
        "wrapped_key":      "<base64>",
        // Modo B (ECC):
        "ephemeral_pubkey": "<base64>",
        "salt":             "<base64>"
    },
    "signature": {                          //esto se añade al firmar.
        "algorithm":    "ed25519",
        "signer_key_id":"<hex SHA-256 de la clave pública del firmante>",
        "value":        "<base64>"
    }
}
"""

import json
import base64
import hashlib
from pathlib import Path

#Versión actual del formato del contendor
SBOX_VERSION = "sbox-1"

def build_container(mode, aead_algorithm, kem_algorithm, recipient_key_id, nonce, ciphertext, kem_data):
    """
    Construimos el contenedor .sbox, con los valores dichos anteriorimente.
    """
    #Usar en Base64
    encoded_kem_data = {
        key: _b64encode(value)
        for key, value in kem_data.items()
    }

    container = {
        "version": SBOX_VERSION,
        "mode": mode,
        "algorithms": {
            "aead": aead_algorithm,
            "kem": kem_algorithm,
        },
        "recipient_key_id": recipient_key_id,
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "kem_data": encoded_kem_data,
    }

    return container


def add_signature(container, algorithm, signer_key_id, signature_bytes):
    """
    Una vez el contenedor ya está construido, podemos añadir la firma al contenedor.
    """
    container["signature"] = {
        "algorithm": algorithm,
        "signer_key_id": signer_key_id,
        "value": _b64encode(signature_bytes),
    }
    return container

def save_container(container, output_path):
    """
    Guardamos el contenedor como un archivo .sbox (JSON) en disco.
    """
    path = Path(output_path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)


def load_container(input_path):
    """
    Cargamos el contenedor.
    """
    path = Path(input_path)
    with path.open("r", encoding="utf-8") as f:
        container = json.load(f)

    _validate_container(container)
    return container

#Devuelve campos del contenedor en bytes.

def get_nonce(container):
    """Devuelve el nonce como bytes."""
    return _b64decode(container["nonce"])


def get_ciphertext(container):
    """Devuelve el ciphertext como bytes."""
    return _b64decode(container["ciphertext"])


def get_kem_field(container, field_name):
    """
    Devuelve un campo de kem_data como bytes.
    """
    return _b64decode(container["kem_data"][field_name])


def get_signature_bytes(container):
    """Devuelve el valor de la firma como bytes, o None si no hay firma."""
    if "signature" not in container:
        return None
    return _b64decode(container["signature"]["value"])

def build_manifest(container):
    """
    Construimos el manifest canonicalizado que se firma.

    Incluye todos los campos críticos del contenedor excepto 'signature'.
    Se serializa como JSON con claves ordenadas (sort_keys=True) para que
    el resultado sea siempre el mismo independientemente del orden de inserción.
    """
    #Campos críticos que se incluyen en el manifest
    manifest = {
        "version":          container["version"],
        "mode":             container["mode"],
        "algorithms":       container["algorithms"],
        "recipient_key_id": container["recipient_key_id"],
        "nonce":            container["nonce"],
        "ciphertext":       container["ciphertext"],
        "kem_data":         container["kem_data"],
    }

    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")

def key_fingerprint(public_key_pem_bytes):
    """
    Calcula la huella SHA-256 de una clave pública en PEM.
    Se usa como recipient_key_id y signer_key_id en el contenedor.
    """
    return hashlib.sha256(public_key_pem_bytes).hexdigest()

def inspect_container(container):
    """
    Devuelve un resumen legible del contenedor, SIN revelar información importante.
    """
    lines = [
        f"Versión:           {container.get('version', 'desconocida')}",
        f"Modo:              {container.get('mode', 'desconocido')}",
        f"AEAD:              {container.get('algorithms', {}).get('aead', '?')}",
        f"KEM:               {container.get('algorithms', {}).get('kem', '?')}",
        f"Receptor (key_id): {container.get('recipient_key_id', '?')}",
        f"Nonce (base64):    {container.get('nonce', '?')}",
        f"Tamaño ciphertext: {len(_b64decode(container['ciphertext']))} bytes",
    ]

    #Campos del KEM según el modo
    kem_data = container.get("kem_data", {})
    if "wrapped_key" in kem_data:
        lines.append(f"Wrapped key:       {len(_b64decode(kem_data['wrapped_key']))} bytes")
    if "ephemeral_pubkey" in kem_data:
        lines.append(f"Ephemeral pubkey:  {len(_b64decode(kem_data['ephemeral_pubkey']))} bytes")
    if "salt" in kem_data:
        lines.append(f"Salt:              {len(_b64decode(kem_data['salt']))} bytes")

    # Firma
    if "signature" in container:
        sig = container["signature"]
        lines.append(f"Firma algoritmo:   {sig.get('algorithm', '?')}")
        lines.append(f"Firmante (key_id): {sig.get('signer_key_id', '?')}")
        lines.append(f"Firma (base64):    {sig.get('value', '?')[:40]}...")
    else:
        lines.append("Firma: no presente")

    return "\n".join(lines)

def _validate_container(container):
    """
    Valida que el contenedor tenga los campos obligatorios y la versión correcta.
    """
    if container.get("version") != SBOX_VERSION:
        raise ValueError(
            f"Versión de contenedor no compatible: {container.get('version')}. "
            f"Se esperaba: {SBOX_VERSION}"
        )

    required_fields = ["mode", "algorithms", "recipient_key_id",
                       "nonce", "ciphertext", "kem_data"]
    for field in required_fields:
        if field not in container:
            raise ValueError(f"Campo obligatorio ausente en el contenedor: '{field}'")


#Helpers de codificación Base64.

def _b64encode(data_bytes):
    """Codifica bytes a string Base64."""
    return base64.b64encode(data_bytes).decode("ascii")


def _b64decode(data_str):
    """Decodifica string Base64 a bytes."""
    return base64.b64decode(data_str)