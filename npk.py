import os
import hashlib
from math import gcd
from collections import namedtuple
from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Simple elliptic curve parameters for KCDSA
Curve = namedtuple("Curve", ["p", "a", "b", "g", "n"])
Point = namedtuple("Point", ["x", "y"])

# Contoh curve (gunakan curve Mikrotik asli jika ada)
curve = Curve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    g=Point(
        x=55066263022277343669578718895168534326250603453777594175500187360389116729240,
        y=32670510020758816978083085130507043184471273380659243275938904335757337461424
    ),
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)

class PrivateKey:
    def __init__(self, scalar):
        self.scalar = scalar

class PublicKey:
    def __init__(self, point):
        self.point = point

def load_private_key(path):
    """Load private key from PEM or binary file, ensure it's valid"""
    if not os.path.exists(path):
        print(f"[mikro] Key {path} not found, generating new key...")
        return generate_valid_private_key(path)

    try:
        with open(path, "rb") as f:
            data = f.read()

        # Try PEM format
        try:
            key = serialization.load_pem_private_key(data, password=None, backend=default_backend())
            scalar = key.private_numbers().private_value
        except ValueError:
            # Assume binary
            scalar = int.from_bytes(data, "big")

        if gcd(scalar, curve.n) != 1 or scalar <= 0 or scalar >= curve.n:
            print("[mikro] Invalid KCDSA key detected, regenerating...")
            return generate_valid_private_key(path)

        return PrivateKey(scalar)
    except Exception as e:
        print(f"[mikro] Error loading key: {e}, regenerating...")
        return generate_valid_private_key(path)

def generate_valid_private_key(path):
    """Generate a valid private key (invertible modulo curve.n)"""
    import secrets
    while True:
        scalar = secrets.randbelow(curve.n - 1) + 1
        if gcd(scalar, curve.n) == 1:
            break
    priv = PrivateKey(scalar)
    with open(path, "wb") as f:
        f.write(scalar.to_bytes(32, "big"))
    print(f"[mikro] New valid private key saved to {path}")
    return priv

def mikro_kcdsa_sign(data_hash, private_key):
    """Sign using KCDSA-like algorithm"""
    if isinstance(data_hash, bytes):
        data_hash = int.from_bytes(data_hash, "big")
    if gcd(private_key.scalar, curve.n) != 1:
        raise ValueError("Private key scalar is not invertible modulo curve.n")

    import secrets
    while True:
        nonce = secrets.randbelow(curve.n - 1) + 1
        if gcd(nonce, curve.n) == 1:
            break

    # r = (g^nonce).x mod n
    r = pow(curve.g.x, nonce, curve.n)
    s = (pow(private_key.scalar, -1, curve.n) * (nonce - data_hash)) % curve.n

    return (r, s)

def mikro_kcdsa_verify(data_hash, signature, public_key):
    """Verify a KCDSA signature"""
    r, s = signature
    if isinstance(data_hash, bytes):
        data_hash = int.from_bytes(data_hash, "big")

    w = pow(s, -1, curve.n)
    u1 = (data_hash * w) % curve.n
    u2 = (r * w) % curve.n

    # This is a simplified verify, adjust if Mikrotik uses custom EC math
    x = (pow(curve.g.x, u1, curve.n) * pow(public_key.point.x, u2, curve.n)) % curve.n
    return x == r
