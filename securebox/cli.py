import argparse
import sys
from pathlib import Path

from keys import (
    gen_rsa_private_key,
    gen_ecdh_keypair,
    gen_sign_keypair,
    pem_serialize_public_key,
    pem_serialize_encrypted_private_key,
    pem_load_public_key,
    pem_load_private_key,
)
from crypto.hybrid import encrypt_file_mode_a, decrypt_file_mode_a, encrypt_file_mode_b, decrypt_file_mode_b
from crypto.signatures import sign_container, verify_container
from crypto.formats import load_container, save_container, inspect_container
from crypto.handshake import run_handshake_demo

# Metavar reutilizado en varios comandos de la CLI
SBOX_METAVAR = "ARCHIVO.sbox"
PASSWORD_METAVAR = "CONTRASEÑA"


# ---------------------------------------------------------------------------
# Entrada principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="securebox",
        description="SecureBox — Cifrado híbrido, firmas y canal seguro.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMANDO")
    subparsers.required = True

    _add_keygen_parser(subparsers)
    _add_encrypt_parser(subparsers)
    _add_decrypt_parser(subparsers)
    _add_sign_parser(subparsers)
    _add_verify_parser(subparsers)
    _add_handshake_parser(subparsers)
    _add_inspect_parser(subparsers)

    args = parser.parse_args()
    args.func(args)


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

def _add_keygen_parser(subparsers):
    p = subparsers.add_parser(
        "keygen",
        help="Genera un par de claves y las guarda en disco.",
        description=(
            "Genera claves criptográficas y las guarda en disco.\n\n"
            "Tipos disponibles:\n"
            "  rsa      — RSA 2048/3072 (para cifrado Modo A)\n"
            "  ecdh     — X25519        (para cifrado Modo B y handshake)\n"
            "  sign     — Ed25519       (para firmas digitales)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--type", required=True, choices=["rsa", "ecdh", "sign"],
        help="Tipo de clave a generar.",
    )
    p.add_argument(
        "--out", required=True, metavar="PREFIJO",
        help="Prefijo de los archivos de salida. Se crean <prefijo>.pub.pem y <prefijo>.priv.pem",
    )
    p.add_argument(
        "--password", required=True, metavar=PASSWORD_METAVAR,
        help="Contraseña para cifrar la clave privada.",
    )
    p.add_argument(
        "--rsa-size", type=int, default=2048, choices=[2048, 3072],
        help="Tamaño de clave RSA en bits (default: 2048). Solo aplica con --type rsa.",
    )
    p.set_defaults(func=_cmd_keygen)


def _cmd_keygen(args):
    password = args.password.encode("utf-8")
    prefix = args.out

    if args.type == "rsa":
        private_key = gen_rsa_private_key(key_size=args.rsa_size)
        public_key = private_key.public_key()
        tipo_desc = f"RSA-{args.rsa_size}"

    elif args.type == "ecdh":
        private_key, public_key = gen_ecdh_keypair()
        tipo_desc = "X25519"

    elif args.type == "sign":
        private_key, public_key = gen_sign_keypair()
        tipo_desc = "Ed25519"

    # Serializar
    pub_pem  = pem_serialize_public_key(public_key)
    priv_pem = pem_serialize_encrypted_private_key(private_key, password)

    # Guardar en disco
    pub_path  = Path(f"{prefix}.pub.pem")
    priv_path = Path(f"{prefix}.priv.pem")

    pub_path.write_bytes(pub_pem)
    priv_path.write_bytes(priv_pem)

    print(f"[OK] Claves {tipo_desc} generadas:")
    print(f"     Pública:  {pub_path}")
    print(f"     Privada:  {priv_path} (cifrada con contraseña)")


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------

def _add_encrypt_parser(subparsers):
    p = subparsers.add_parser(
        "encrypt",
        help="Cifra un archivo y genera un contenedor .sbox.",
        description=(
            "Cifra un archivo usando cifrado híbrido.\n\n"
            "Modos disponibles:\n"
            "  rsa — RSA-OAEP + AES-256-GCM  (Modo A)\n"
            "  ecc — X25519 + HKDF + AES-256-GCM  (Modo B)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--input",  required=True, metavar="ARCHIVO",    help="Archivo a cifrar.")
    p.add_argument("--output", required=True, metavar=SBOX_METAVAR, help="Archivo de salida .sbox.")
    p.add_argument("--mode",   required=True, choices=["rsa", "ecc"], help="Modo de cifrado.")
    p.add_argument("--recipient-pub", required=True, metavar="PUB.PEM",
                   help="Clave pública del receptor (RSA para --mode rsa, X25519 para --mode ecc).")
    p.set_defaults(func=_cmd_encrypt)


def _cmd_encrypt(args):
    _check_file_exists(args.input)
    _check_file_exists(args.recipient_pub)

    pub_pem = Path(args.recipient_pub).read_bytes()
    public_key = pem_load_public_key(pub_pem)

    if args.mode == "rsa":
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        if not isinstance(public_key, RSAPublicKey):
            _error("El modo 'rsa' requiere una clave pública RSA (--recipient-pub).")
        encrypt_file_mode_a(args.input, args.output, public_key)
        print("[OK] Archivo cifrado en Modo A (RSA-OAEP + AES-256-GCM).")

    elif args.mode == "ecc":
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        if not isinstance(public_key, X25519PublicKey):
            _error("El modo 'ecc' requiere una clave pública X25519 (--recipient-pub).")
        encrypt_file_mode_b(args.input, args.output, public_key)
        print("[OK] Archivo cifrado en Modo B (X25519 + HKDF + AES-256-GCM).")

    print(f"     Salida: {args.output}")


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

def _add_decrypt_parser(subparsers):
    p = subparsers.add_parser(
        "decrypt",
        help="Descifra un contenedor .sbox.",
        description="Descifra un archivo .sbox usando la clave privada del receptor.",
    )
    p.add_argument("--input",    required=True, metavar=SBOX_METAVAR, help="Archivo .sbox a descifrar.")
    p.add_argument("--output",   required=True, metavar="ARCHIVO",      help="Archivo de salida descifrado.")
    p.add_argument("--priv-key", required=True, metavar="PRIV.PEM",     help="Clave privada del receptor.")
    p.add_argument("--password", required=True, metavar=PASSWORD_METAVAR,   help="Contraseña de la clave privada.")
    p.set_defaults(func=_cmd_decrypt)


def _cmd_decrypt(args):
    _check_file_exists(args.input)
    _check_file_exists(args.priv_key)

    priv_pem = Path(args.priv_key).read_bytes()
    password = args.password.encode("utf-8")

    try:
        private_key = pem_load_private_key(priv_pem, password)
    except ValueError as e:
        _error(f"No se pudo cargar la clave privada: {e}")

    # Cargar el contenedor para saber el modo
    container = load_container(args.input)
    mode = container.get("mode")

    if mode == "rsa_oaep":
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        if not isinstance(private_key, RSAPrivateKey):
            _error("Este contenedor requiere una clave privada RSA.")
        decrypt_file_mode_a(args.input, args.output, private_key)

    elif mode == "ecc_hkdf":
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        if not isinstance(private_key, X25519PrivateKey):
            _error("Este contenedor requiere una clave privada X25519.")
        decrypt_file_mode_b(args.input, args.output, private_key)

    else:
        _error(f"Modo de cifrado desconocido en el contenedor: '{mode}'.")

    print("[OK] Archivo descifrado correctamente.")
    print(f"     Salida: {args.output}")


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

def _add_sign_parser(subparsers):
    p = subparsers.add_parser(
        "sign",
        help="Firma un contenedor .sbox.",
        description=(
            "Firma el manifest del contenedor .sbox con una clave Ed25519 o RSA.\n"
            "La firma se guarda dentro del propio archivo .sbox."
        ),
    )
    p.add_argument("--input",    required=True, metavar=SBOX_METAVAR, help="Contenedor .sbox a firmar.")
    p.add_argument("--priv-key", required=True, metavar="PRIV.PEM",     help="Clave privada del firmante.")
    p.add_argument("--password", required=True, metavar=PASSWORD_METAVAR,   help="Contraseña de la clave privada.")
    p.set_defaults(func=_cmd_sign)


def _cmd_sign(args):
    _check_file_exists(args.input)
    _check_file_exists(args.priv_key)

    priv_pem = Path(args.priv_key).read_bytes()
    password = args.password.encode("utf-8")

    try:
        private_key = pem_load_private_key(priv_pem, password)
    except ValueError as e:
        _error(f"No se pudo cargar la clave privada: {e}")

    container = load_container(args.input)
    sign_container(container, private_key)
    save_container(container, args.input)

    algo = container["signature"]["algorithm"]
    print(f"[OK] Contenedor firmado con {algo}.")
    print(f"     Firmante key_id: {container['signature']['signer_key_id']}")
    print(f"     Guardado en: {args.input}")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def _add_verify_parser(subparsers):
    p = subparsers.add_parser(
        "verify",
        help="Verifica la firma de un contenedor .sbox.",
        description="Verifica que el contenedor .sbox no ha sido modificado y la firma es válida.",
    )
    p.add_argument("--input",   required=True, metavar=SBOX_METAVAR, help="Contenedor .sbox a verificar.")
    p.add_argument("--pub-key", required=True, metavar="PUB.PEM",      help="Clave pública del firmante.")
    p.set_defaults(func=_cmd_verify)


def _cmd_verify(args):
    _check_file_exists(args.input)
    _check_file_exists(args.pub_key)

    pub_pem = Path(args.pub_key).read_bytes()
    public_key = pem_load_public_key(pub_pem)
    container = load_container(args.input)

    try:
        verify_container(container, public_key)
        print("[OK] Firma válida. El contenedor no ha sido modificado.")
        print(f"     Algoritmo: {container['signature']['algorithm']}")
        print(f"     Firmante key_id: {container['signature']['signer_key_id']}")
    except ValueError as e:
        _error(f"Verificación fallida: {e}")


# ---------------------------------------------------------------------------
# handshake-demo
# ---------------------------------------------------------------------------

def _add_handshake_parser(subparsers):
    p = subparsers.add_parser(
        "handshake-demo",
        help="Ejecuta la demo del canal seguro (simulación local).",
        description=(
            "Simula un handshake completo entre Alice y Bob en local:\n"
            "  1. Intercambio efímero X25519\n"
            "  2. Derivación de claves con HKDF\n"
            "  3. Autenticación del transcript con Ed25519 (anti-MITM)\n"
            "  4. Intercambio de mensajes cifrados con AES-256-GCM\n"
            "  5. Detección de modificación y replay\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.set_defaults(func=_cmd_handshake_demo)


def _cmd_handshake_demo(args):
    run_handshake_demo()


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------

def _add_inspect_parser(subparsers):
    p = subparsers.add_parser(
        "inspect",
        help="Muestra los metadatos de un contenedor .sbox.",
        description=(
            "Muestra un resumen legible del contenedor .sbox:\n"
            "versión, modo, algoritmos, tamaños, key_ids y estado de la firma.\n"
            "Nunca revela información secreta."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("archivo", metavar=SBOX_METAVAR, help="Contenedor .sbox a inspeccionar.")
    p.set_defaults(func=_cmd_inspect)


def _cmd_inspect(args):
    _check_file_exists(args.archivo)
    container = load_container(args.archivo)
    print(inspect_container(container))


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _check_file_exists(path):
    """Termina con error claro si el archivo no existe."""
    if not Path(path).exists():
        _error(f"Archivo no encontrado: '{path}'")


def _error(message):
    """Imprime un mensaje de error y termina el programa."""
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    main()