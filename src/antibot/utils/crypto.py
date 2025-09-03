"""Cryptographic helpers for sensor data generation."""

import hashlib
import hmac
import random
import string
import struct
import time


def md5_hash(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()


def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def random_hex(length: int = 32) -> str:
    return "".join(random.choices("0123456789abcdef", k=length))


def random_string(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def timestamp_ms() -> int:
    return int(time.time() * 1000)


def encode_float_array(values: list[float]) -> bytes:
    """Pack float array into bytes (used by some sensor data formats)."""
    return struct.pack(f">{len(values)}f", *values)


def xor_encode(data: bytes, key: bytes) -> bytes:
    """Simple XOR encoding used in some obfuscation schemes."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def canvas_fingerprint_hash(width: int = 300, height: int = 150) -> str:
    """Generate a plausible canvas fingerprint hash.

    In a real implementation, this would render specific drawing
    operations and hash the pixel data. Here we generate a
    deterministic hash based on system parameters.
    """
    import platform

    seed = f"{platform.system()}-{platform.machine()}-{width}x{height}"
    return sha256_hash(seed)[:32]


def webgl_fingerprint_hash(vendor: str, renderer: str) -> str:
    """Generate a WebGL fingerprint hash from GPU info."""
    return sha256_hash(f"{vendor}|{renderer}")[:32]
