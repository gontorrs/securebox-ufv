"""
test_handshake.py — Pruebas para handshake.py (4 pruebas)

Integración (2):
  - Handshake completo sin errores
  - 5 mensajes consecutivos cifrados correctamente

Negativas (2):
  - Mensaje modificado en tránsito
  - Replay de paquete detectado
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'securebox'))

from securebox.keys import gen_sign_keypair
from securebox.crypto.handshake import HandshakeParty


def _make_handshake():
    """Helper: crea y completa un handshake entre Alice y Bob."""
    alice_sign_priv, alice_sign_pub = gen_sign_keypair()
    bob_sign_priv,   bob_sign_pub   = gen_sign_keypair()

    alice = HandshakeParty("Alice", alice_sign_priv, alice_sign_pub, bob_sign_pub)
    bob   = HandshakeParty("Bob",   bob_sign_priv,   bob_sign_pub,   alice_sign_pub)
    
    alice_eph = alice.generate_ephemeral()
    bob_eph   = bob.generate_ephemeral()

    alice_sig = alice.finalize(bob_eph)
    bob_sig   = bob.finalize(alice_eph)

    alice.verify_peer_transcript(bob_eph, bob_sig)
    bob.verify_peer_transcript(alice_eph, alice_sig)

    return alice, bob


# Integración

def test_handshake_five_messages():
    """Intercambio de 5 mensajes consecutivos sin errores."""
    alice, bob = _make_handshake()
    messages = ["Uno", "Dos", "Tres", "Cuatro", "Cinco"]
    for msg in messages:
        assert bob.receive(alice.send(msg)) == msg


def test_handshake_bidirectional():
    """Mensajes en ambas direcciones sin interferencia."""
    alice, bob = _make_handshake()
    assert bob.receive(alice.send("Alice habla")) == "Alice habla"
    assert alice.receive(bob.send("Bob habla")) == "Bob habla"


# Negativas

def test_modified_message_detected():
    """Mensaje modificado en tránsito lanza ValueError."""
    alice, bob = _make_handshake()
    packet = alice.send("Mensaje original")
    packet["ciphertext"] = b"\x00" * len(packet["ciphertext"])
    with pytest.raises(ValueError, match="modificado"):
        bob.receive(packet)


def test_replay_detected():
    """Replay de un paquete ya recibido lanza ValueError."""
    alice, bob = _make_handshake()
    packet = alice.send("Mensaje normal")
    bob.receive(packet)
    with pytest.raises(ValueError, match="[Rr]eplay"):
        bob.receive(packet)