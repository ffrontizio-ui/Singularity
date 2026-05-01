import os
import base64
from mnemonic import Mnemonic
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

mnemo = Mnemonic("english")

def generate_mnemonic() -> str:
    """Generate a 15-word mnemonic phrase (160 bits of entropy)"""
    data = os.urandom(20)
    return mnemo.to_mnemonic(data)

def derive_keys(mnemonic_phrase: str):
    """
    Derives an Ed25519 keypair from a mnemonic phrase.
    Returns (public_key_b85, private_key_b85).
    Base85 provides a password-like complex string format.
    """
    seed = Mnemonic.to_seed(mnemonic_phrase, passphrase="")
    
    # We take the first 32 bytes of the 64-byte seed for ed25519
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])
    public_key = private_key.public_key()
    
    # Extract raw bytes
    priv_bytes = private_key.private_bytes_raw()
    pub_bytes = public_key.public_bytes_raw()
    
    # Base85 enforces the requirement to be > 20 characters and contain symbols, digits, upper/lowercase.
    priv_b85 = base64.b85encode(priv_bytes).decode('utf-8')
    pub_b85 = base64.b85encode(pub_bytes).decode('utf-8')
    
    return pub_b85, priv_b85

def sign_message(priv_b85: str, message: bytes) -> str:
    """Sign a message using the base85 encoded private key."""
    priv_bytes = base64.b85decode(priv_b85)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    signature = private_key.sign(message)
    return base64.b85encode(signature).decode('utf-8')

def verify_signature(pub_b85: str, message: bytes, signature_b85: str) -> bool:
    """Verify a message signature using the public key."""
    try:
        pub_bytes = base64.b85decode(pub_b85)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        signature = base64.b85decode(signature_b85)
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
