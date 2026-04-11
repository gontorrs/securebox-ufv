from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .kdf import hkdf_derive_key
from .aead import aead_encrypt, aead_decrypt
from .signatures import _sign_ed25519, _verify_ed25519
from keys import gen_sign_keypair

# Contextos HKDF para separar a Alice y Bob
HKDF_INFO_ALICE_TO_BOB = b"securebox-v1-handshake-alice-to-bob"
HKDF_INFO_BOB_TO_ALICE = b"securebox-v1-handshake-bob-to-alice"



class HandshakeParty:
    """
    Representa una de las dos partes del handshake (Alice o Bob).

    Cada instancia gestiona su propio estado del handshake, incluyendo:
  - Clave de firma de identidad (Ed25519).
  - Clave efímera X25519 generada para este handshake.
  - Claves de sesión derivadas con HKDF.
  - Contadores para mensajes enviados y recibidos.
  - Funciones para generar la clave efímera, finalizar el handshake, enviar y recibir mensajes cifrados.
    """

    def __init__(self, name, sign_private_key, sign_public_key, peer_sign_public_key):
        self.name = name
        self.sign_private_key = sign_private_key
        self.sign_public_key = sign_public_key
        self.peer_sign_public_key = peer_sign_public_key

        self._eph_private = None       # X25519 efímero privado (solo esta parte)
        self._eph_public_bytes = None  # X25519 efímero público (se comparte)
        self._send_key = None          # clave AES para cifrar mensajes salientes
        self._recv_key = None          # clave AES para descifrar mensajes entrantes
        self._send_counter = 0         # contador de mensajes enviados
        self._recv_counter = 0         # contador de mensajes recibidos

        self._ready = False            # True después de finalize()

    def generate_ephemeral(self):
        """
        Paso 1: generar clave efímera X25519.
        """
        self._eph_private = x25519.X25519PrivateKey.generate()
        self._eph_public_bytes = self._eph_private.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return self._eph_public_bytes

    def finalize(self, peer_eph_public_bytes):
        """
        Paso 2 + 3: finalizar handshake (derivar claves + autenticar transcript).
        """
        if self._eph_private is None:
            raise RuntimeError("Llama a generate_ephemeral() antes de finalize().")

        # Reconstruir la clave pública del otro como objeto X25519
        peer_eph_public = x25519.X25519PublicKey.from_public_bytes(peer_eph_public_bytes)

        # Calcular shared_secret
        shared_secret = self._eph_private.exchange(peer_eph_public)

        # Construir el transcript: alice_eph_pub || bob_eph_pub
        # Necesitamos saber quién es quién para que ambos construyan el mismo transcript.
        # Convenio: el transcript siempre se ordena como menor || mayor (comparación de bytes).
        my_pub = self._eph_public_bytes
        peer_pub = peer_eph_public_bytes
        if my_pub < peer_pub:
            transcript = my_pub + peer_pub
        else:
            transcript = peer_pub + my_pub

        # Derivar las dos claves de sesión con HKDF
        # Usamos el transcript como salt para que las claves dependan del intercambio completo
        # salt = hash del transcript completo, o transcript completo si hkdf_derive_key lo admite
        self._send_key = hkdf_derive_key(shared_secret, transcript, HKDF_INFO_ALICE_TO_BOB)
        self._recv_key = hkdf_derive_key(shared_secret, transcript, HKDF_INFO_BOB_TO_ALICE)

        # Si soy "Bob" (mi pub > peer pub), mis roles de send/recv se invierten
        # Alice cifra con alice_to_bob y Bob descifra con alice_to_bob
        if my_pub > peer_pub:
            self._send_key, self._recv_key = self._recv_key, self._send_key

        # Firmar el transcript para autenticación anti-MITM
        transcript_signature = _sign_ed25519(self.sign_private_key, transcript)

        self._ready = True
        return transcript_signature

    def verify_peer_transcript(self, peer_eph_public_bytes, peer_transcript_signature):
        """
        Verifica la firma del transcript del otro lado para así evitar ataques MITM.
        """
        my_pub = self._eph_public_bytes
        peer_pub = peer_eph_public_bytes

        # Reconstruir el mismo transcript con el mismo convenio de orden
        if my_pub < peer_pub:
            transcript = my_pub + peer_pub
        else:
            transcript = peer_pub + my_pub

        _verify_ed25519(self.peer_sign_public_key, transcript, peer_transcript_signature)

    def send(self, message):
        """
        Paso 4: Cifra un mensaje para enviarlo al otro lado.

        El nonce se construye como nonce_base XOR contador (4 bytes en la parte final).
        Esto garantiza nonces únicos sin necesitar almacenar cada nonce.
        """
        self._check_ready()

        if isinstance(message, str):
            message = message.encode("utf-8")

        # Construir nonce único: nonce_base XOR contador en los últimos 4 bytes
        nonce = self._send_counter.to_bytes(12, byteorder='big')

        # Cifrar con AES-256-GCM
        aesgcm_key = self._send_key
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(aesgcm_key)
        ciphertext = aesgcm.encrypt(nonce, message, associated_data=None)

        packet = {
            "counter": self._send_counter,
            "ciphertext": ciphertext,
        }

        self._send_counter += 1
        return packet

    def receive(self, packet):
        """
        Descifra y verifica un mensaje recibido del otro lado.

        Detecta:
          - Mensajes modificados (fallo de autenticación AES-GCM).
          - Replays simples: el contador debe ser exactamente el esperado.

        Args:
            packet: dict — paquete devuelto por send() del otro lado

        Returns:
            str — mensaje descifrado

        Raises:
            ValueError si el mensaje fue modificado o es un replay.
        """
        self._check_ready()

        counter = packet["counter"]
        ciphertext = packet["ciphertext"]

        # Detección de replay: el contador debe ser el siguiente esperado
        if counter != self._recv_counter:
            raise ValueError(
                f"Replay o mensaje fuera de orden detectado. "
                f"Esperado: {self._recv_counter}, recibido: {counter}."
            )
        
        nonce = counter.to_bytes(12, byteorder='big')

        # Descifrar con AES-256-GCM
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(self._recv_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except Exception:
            raise ValueError(
                "Fallo de autenticación: el mensaje fue modificado en tránsito."
            )

        self._recv_counter += 1
        return plaintext.decode("utf-8")

    # -----------------------------------------------------------------------
    # Helper interno
    # -----------------------------------------------------------------------

    def _check_ready(self):
        """Lanza RuntimeError si el handshake no ha sido completado."""
        if not self._ready:
            raise RuntimeError(
                f"{self.name}: el handshake no está completo. "
                "Llama a generate_ephemeral() y finalize() primero."
            )

# ---------------------------------------------------------------------------
# Demo completa del handshake (simulación local sin sockets)
# ---------------------------------------------------------------------------

def run_handshake_demo():
    """
    Ejecuta una demo completa del handshake entre Alice y Bob en local.

    Muestra cada paso del protocolo con mensajes explicativos.
    """

    print("=" * 60)
    print("  DEMO: Canal seguro SecureBox (ECDHE + HKDF + AEAD)")
    print("=" * 60)

    # --- Claves de identidad (long-term) ---
    alice_sign_priv, alice_sign_pub = gen_sign_keypair()
    bob_sign_priv,   bob_sign_pub   = gen_sign_keypair()
    print("\n[Setup] Claves de identidad Ed25519 generadas para Alice y Bob.")

    # --- Crear las partes ---
    alice = HandshakeParty("Alice", alice_sign_priv, alice_sign_pub, bob_sign_pub)
    bob   = HandshakeParty("Bob",   bob_sign_priv,   bob_sign_pub,   alice_sign_pub)

    # --- Paso 1: intercambio efímero ---
    print("\n[Paso 1] Intercambio de claves efímeras X25519...")
    alice_eph_pub = alice.generate_ephemeral()
    bob_eph_pub   = bob.generate_ephemeral()
    print(f"  Alice ephemeral pub: {alice_eph_pub.hex()[:20]}...")
    print(f"  Bob   ephemeral pub: {bob_eph_pub.hex()[:20]}...")

    # --- Paso 2 + 3: derivación de claves y firma del transcript ---
    print("\n[Paso 2+3] Derivación de claves HKDF y firma del transcript...")
    alice_sig = alice.finalize(bob_eph_pub)
    bob_sig   = bob.finalize(alice_eph_pub)

    # Verificación cruzada del transcript (anti-MITM)
    alice.verify_peer_transcript(bob_eph_pub, bob_sig)
    bob.verify_peer_transcript(alice_eph_pub, alice_sig)
    print("  Transcript firmado y verificado por ambas partes. Sin MITM.")

    # --- Paso 4: mensajes cifrados ---
    print("\n[Paso 4] Intercambio de mensajes cifrados con AEAD...\n")

    conversacion = [
        ("Alice", alice, bob,   "Hola Bob, ¿me recibes?"),
        ("Bob",   bob,   alice, "Sí Alice, canal seguro establecido."),
        ("Alice", alice, bob,   "Perfecto. Aquí va un secreto: clave=42."),
        ("Bob",   bob,   alice, "Recibido. Guardado de forma segura."),
        ("Alice", alice, bob,   "Cerrando canal. Hasta pronto."),
    ]

    for sender_name, sender, receiver, texto in conversacion:
        packet = sender.send(texto)
        recibido = receiver.receive(packet)
        print(f"  {sender_name} → [{packet['counter']}] cifrado: {packet['ciphertext'].hex()[:20]}...")
        print(f"  {'Bob' if sender_name == 'Alice' else 'Alice'} descifra: \"{recibido}\"")
        print()

    # --- Prueba de detección de modificación ---
    print("[Seguridad] Prueba: modificación de mensaje en tránsito...")
    packet = alice.send("Mensaje que será modificado")
    packet["ciphertext"] = b"\x00" * len(packet["ciphertext"])
    try:
        bob.receive(packet)
        print("  ERROR: no se detectó la modificación")
    except ValueError as e:
        print(f"  Modificación detectada correctamente: {e}")

    # --- Prueba de detección de replay ---
    # Usamos un canal fresco para no depender del estado anterior
    print("\n[Seguridad] Prueba: replay de un mensaje anterior...")
    alice2_sign_priv, alice2_sign_pub = gen_sign_keypair()
    bob2_sign_priv,   bob2_sign_pub   = gen_sign_keypair()
    alice2 = HandshakeParty("Alice2", alice2_sign_priv, alice2_sign_pub, bob2_sign_pub)
    bob2   = HandshakeParty("Bob2",   bob2_sign_priv,   bob2_sign_pub,   alice2_sign_pub)
    a2_eph = alice2.generate_ephemeral()
    b2_eph = bob2.generate_ephemeral()
    alice2.finalize(b2_eph)
    bob2.finalize(a2_eph)

    packet_original = alice2.send("Mensaje normal")
    bob2.receive(packet_original)

    # Intentar reenviar el mismo paquete
    try:
        bob2.receive(packet_original)
        print("  ERROR: no se detectó el replay")
    except ValueError as e:
        print(f"  Replay detectado correctamente: {e}")

    print("\n" + "=" * 60)
    print("  Demo completada con éxito.")
    print("=" * 60)


if __name__ == "__main__":
    run_handshake_demo()