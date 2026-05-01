import base58
import hashlib
import bech32
from bip32 import BIP32

def zpub_to_xpub(zpub: str) -> str:
    """
    Converts a Zpub (BIP84) to a standard xpub (BIP32) prefix.
    """
    data = base58.b58decode_check(zpub)
    # xpub mainnet prefix is 0x0488b21e
    xpub_data = b'\x04\x88\xb2\x1e' + data[4:]
    return base58.b58encode_check(xpub_data).decode('ascii')

def pubkey_to_segwit_address(pubkey_bytes: bytes) -> str:
    """
    Converts a compressed public key to a Native Segwit (P2WPKH - bc1q) address.
    """
    # Hash pubkey: ripemd160(sha256(pubkey))
    sha = hashlib.sha256(pubkey_bytes).digest()
    h = hashlib.new('ripemd160', sha).digest()
    # Convert bits from 8 to 5 for bech32 encoding
    converted = bech32.convertbits(h, 8, 5)
    if converted is None:
        return ""
    return bech32.bech32_encode('bc', [0] + converted)

def generate_receive_address(zpub_str: str, index: int) -> str:
    """
    Derives a Native Segwit (bc1q) address from a Zpub and index.
    Derivation path: m/0/index (External/Receive chain)
    """
    # If it starts with Zpub, convert to xpub for bip32 library compatibility
    if zpub_str.startswith('Zpub'):
        xpub = zpub_to_xpub(zpub_str)
    else:
        xpub = zpub_str
        
    bip32_ctx = BIP32.from_xpub(xpub)
    
    # Derivation path: m/0/index (relative to the account pubkey)
    # BIP32.get_pubkey_from_path handles the derivation
    derived_pubkey = bip32_ctx.get_pubkey_from_path(f"m/0/{index}")
    
    return pubkey_to_segwit_address(derived_pubkey)
