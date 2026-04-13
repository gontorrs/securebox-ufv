from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048


def gen_priv_key():
    """
    Genera una clave privada RSA con exponente público 65537 y tamaño 2048 bits.
    """
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    return private_key


def gen_pub_key(private_key):
    """
    Obtiene la clave pública a partir de la clave privada RSA.
    """
    return private_key.public_key()

def pem_serialize_pub_key(pk):
    """
    Serializa una clave pública RSA a formato PEM (SubjectPublicKeyInfo).
    """
    return pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pem_serialize_enc_priv_key(sk, pwd):
    """
    Serializa y cifra una clave privada RSA a formato PEM (TraditionalOpenSSL).
    La clave privada se cifra con la contraseña proporcionada usando BestAvailableEncryption.
    """
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(pwd),
    )


def pem_load_pub_key(pem_bytes):
    """
    Carga una clave pública RSA desde bytes PEM.
    """
    return load_pem_public_key(pem_bytes)


def pem_load_priv_key(pem_bytes, pwd):
    """
    Carga una clave privada RSA cifrada desde bytes PEM.
    """
    return load_pem_private_key(pem_bytes, password=pwd)


def rsa_encrypt(public_key, plaintext_bytes):
    """
    Cifra un mensaje con RSA-OAEP (SHA-256).
    """
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    """
    Descifra un mensaje cifrado con RSA-OAEP (SHA-256).
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


if __name__ == "__main__":
    PASSWORD = b"ufv_2026"
    MENSAJE   = "Espero tener buena nota en el examen de criptografía."

    print("=" * 60)
    print("  PRÁCTICA RSA — Gonzalo Torras Serrano")
    print("=" * 60)

    print("\n[1] GENERACIÓN DE CLAVES")
    private_key = gen_priv_key()
    public_key  = gen_pub_key(private_key)
    print(f"  Algoritmo : RSA")
    print(f"  Tamaño    : {KEY_SIZE} bits")
    print(f"  Exponente : {PUBLIC_EXPONENT}")

    print("\n[2] SERIALIZACIÓN DE CLAVES")

    pub_pem  = pem_serialize_pub_key(public_key)
    priv_pem = pem_serialize_enc_priv_key(private_key, PASSWORD)

    print("\n  Clave pública (PEM):")
    print(pub_pem.decode())

    print("  Clave privada cifrada (PEM, primeras 3 líneas):")
    for line in priv_pem.decode().splitlines()[:3]:
        print(f"    {line}")
    print("    ...")

    # Verificamos que la carga funciona
    pub_loaded  = pem_load_pub_key(pub_pem)
    priv_loaded = pem_load_priv_key(priv_pem, PASSWORD)
    print("\n  Carga desde PEM: OK")

    print("\n[3] CIFRADO Y DESCIFRADO RSA-OAEP")
    print(f"\n  Plaintext original : \"{MENSAJE}\"")

    plaintext_bytes = MENSAJE.encode("utf-8")
    ciphertext      = rsa_encrypt(pub_loaded, plaintext_bytes)

    print(f"\n  Ciphertext (hex)   :")
    print(f"    {ciphertext.hex()}")
    print(f"  Longitud ciphertext: {len(ciphertext)} bytes")

    recovered_bytes = rsa_decrypt(priv_loaded, ciphertext)
    recovered_text  = recovered_bytes.decode("utf-8")

    print(f"\n  Plaintext recuperado: \"{recovered_text}\"")
    print(f"\n  Verificación: {'✓ CORRECTO — textos coinciden' if recovered_text == MENSAJE else '✗ ERROR — textos no coinciden'}")

    print("\n" + "=" * 60)