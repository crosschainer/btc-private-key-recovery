#!/usr/bin/env python3
"""Reference implementation of explicit minstd seed recipes and BIP32 derivation.

Uses integer/HMAC arithmetic and OpenSSL-backed secp256k1 public-key operations.
Parameters describe mathematical constructions and synthetic observations."""

from dataclasses import dataclass
import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 1 << 31
ENGINE_MODULUS = 2147483647
ENGINES = {"minstd_rand0": 16807, "minstd_rand": 48271}


def seed_bytes(engine_state, size, engine="minstd_rand0"):
    """bx 2.0's engine() % 255 bytes, using the pinned C++ engine mapping.

    The input denotes the value passed to the C++ engine constructor, before
    its modulo/zero normalization.  Effective nonzero engine states are
    1 through 2**31-2.  The scanner may enumerate that canonical range directly.
    """
    if (engine not in ENGINES or type(engine_state) is not int
            or not 0 <= engine_state < (1 << 64)):
        raise ValueError("Unknown engine or unsigned seed out of range")
    if type(size) is not int or size < 16:
        raise ValueError("Historical bx requires at least 128 output bits")
    state = engine_state % ENGINE_MODULUS or 1
    result = bytearray()
    for _ in range(size):
        state = state * ENGINES[engine] % ENGINE_MODULUS
        result.append(state % 255)  # Historical code uses uint8_t::max(), not 256.
    return bytes(result)


def compressed_public(secret):
    if type(secret) is not int or not 1 <= secret < ORDER:
        raise ValueError("Invalid secp256k1 private scalar")
    return ec.derive_private_key(secret, ec.SECP256K1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


@dataclass(frozen=True)
class Node:
    secret: int
    chain: bytes

    def __post_init__(self):
        if (type(self.secret) is not int or not 1 <= self.secret < ORDER
                or not isinstance(self.chain, bytes) or len(self.chain) != 32):
            raise ValueError("Invalid BIP32 private node")


def digest(key, message):
    return hmac.digest(key, message, "sha512")


def master(seed):
    result = digest(b"Bitcoin seed", seed)
    return Node(int.from_bytes(result[:32], "big"), result[32:])


def derive(node, index):
    if type(index) is not int or not 0 <= index < (1 << 32):
        raise ValueError("Child index outside uint32")
    data = (b"\0" + node.secret.to_bytes(32, "big") if index & HARDENED
            else compressed_public(node.secret))
    result = digest(node.chain, data + index.to_bytes(4, "big"))
    tweak = int.from_bytes(result[:32], "big")
    if tweak >= ORDER:
        raise ValueError("Invalid BIP32 tweak; no silent index change")
    return Node((node.secret + tweak) % ORDER, result[32:])


def derive_path(node, indices):
    for index in indices:
        node = derive(node, index)
    return node


def parse_path(path):
    if not isinstance(path, str) or not path or path.split("/")[0] != "m":
        raise ValueError("Expected an absolute BIP32 path beginning with m")
    indices = []
    for component in path.split("/")[1:]:
        hard = component.endswith(("'", "h", "H"))
        digits = component[:-1] if hard else component
        if not digits.isascii() or not digits.isdecimal() or int(digits) >= HARDENED:
            raise ValueError("Invalid BIP32 path component")
        indices.append(int(digits) | (HARDENED if hard else 0))
    return indices


def masked_scalar(secret, observation, mask="low"):
    if (type(observation) is not int or not 1 <= observation <= 256
            or type(secret) is not int or not 1 <= secret < ORDER):
        raise ValueError("Invalid scalar or observation number")
    width = observation - 1
    if mask == "low":
        residue = secret % (1 << width)
    elif mask == "high":
        residue = secret >> (256 - width)
    else:
        raise ValueError("Unknown mask")
    candidate = (1 << width) | residue
    if candidate >= ORDER:
        raise ValueError("Masked scalar is outside the curve order")
    return candidate


def observations(seed, path, start, hardened, observation_numbers, mask="low"):
    """Generate sibling-derived masks; missing observations still advance the index."""
    if type(start) is not int or not 0 <= start < HARDENED:
        raise ValueError("Invalid initial child index")
    if type(hardened) is not bool:
        raise ValueError("Hardened flag must be boolean")
    parent = derive_path(master(seed), parse_path(path))
    output = {}
    for observation in observation_numbers:
        if type(observation) is not int or not 1 <= observation <= 256 or observation in output:
            raise ValueError("Invalid or duplicate observation number")
        index = start + observation - 1
        if not 0 <= index < HARDENED:
            raise ValueError("Child index crosses the hardened boundary")
        child = derive(parent, index | (HARDENED if hardened else 0))
        output[observation] = masked_scalar(child.secret, observation, mask)
    return output


def base58check_decode(encoded):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = 0
    for character in encoded:
        value = 58 * value + alphabet.index(character)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(encoded) - len(encoded.lstrip("1"))) + raw
    checksum = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
    if len(raw) < 5 or checksum != raw[-4:]:
        raise ValueError("Invalid Base58Check checksum")
    return raw[:-4]


def decode_vector_private(encoded):
    payload = base58check_decode(encoded)
    if len(payload) != 78 or payload[:4] != bytes.fromhex("0488ade4") or payload[45] != 0:
        raise ValueError("Expected mainnet extended private key")
    return Node(int.from_bytes(payload[46:], "big"), payload[13:45])
