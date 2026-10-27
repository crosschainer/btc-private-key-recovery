#!/usr/bin/env python3
"""V8 multiply-with-carry, entropy-pool mixing, ARC4, and March 2014 HD semantics.

Offline reference functions for controlled synthetic inputs. The HD serializer
reproduces the source-specific hardened-field behavior; see README.md."""
from dataclasses import dataclass
from functools import cached_property
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 1 << 31
MULTIPLIERS = (18273, 18030)


class UnsupportedScalar(ValueError):
    """An exceptional historical scalar needs separate analysis, not skipping."""


def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def next_state(state, multiplier):
    integer(state, 0, 2**32 - 1, "state")
    if multiplier not in MULTIPLIERS or type(multiplier) is not int:
        raise ValueError("Unknown V8 multiplier")
    return multiplier * (state & 65535) + (state >> 16)


def pool_for_state(variant, state, times_ms, extra_seed_ints=(), *, boundary="before"):
    """times: load, optional events, first use; extra ints precede first use.

    The explicit events are a model extension, not default wallet behavior.
    An after-call state emits its low halfword before its next update.
    """
    next_state(state, variant)  # Validate even when boundary is 'after'.
    if boundary not in ("before", "after"):
        raise ValueError("State boundary must be before or after")
    if len(times_ms) < 2:
        raise ValueError("Need load and first-use timestamps")
    mixes = list(times_ms[:-1]) + list(extra_seed_ints) + [times_ms[-1]]
    for value in mixes:
        integer(value, -(2**53 - 1), 2**53 - 1, "JS seed integer")
    pool = bytearray()
    if boundary == "before":
        state = next_state(state, variant)
    for _ in range(128):
        pool.extend((state & 65535).to_bytes(2, "big"))
        state = next_state(state, variant)
    pointer = 0
    for value in mixes:
        for byte in (value & 0xffffffff).to_bytes(4, "little"):
            pool[pointer] ^= byte
            pointer = (pointer + 1) & 255
    return bytes(pool)


class ARC4:
    def __init__(self, key):
        if not isinstance(key, bytes) or not key:
            raise ValueError("ARC4 key must be nonempty bytes")
        self.s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.s[i] + key[i % len(key)]) & 255
            self.s[i], self.s[j] = self.s[j], self.s[i]
        self.i = self.j = 0

    def read(self, length):
        integer(length, 0, 1_000_000, "ARC4 output length")
        output = bytearray()
        s, i, j = self.s, self.i, self.j
        for _ in range(length):
            i = (i + 1) & 255
            j = (j + s[i]) & 255
            s[i], s[j] = s[j], s[i]
            output.append(s[(s[i] + s[j]) & 255])
        self.i, self.j = i, j
        return bytes(output)


def seed_for_state(variant, state, times_ms, extra_seed_ints=(), *,
                   boundary="before", stream_offset=0):
    integer(stream_offset, 0, 1_000_000 - 32, "stream offset")
    stream = ARC4(pool_for_state(variant, state, times_ms, extra_seed_ints, boundary=boundary))
    stream.read(stream_offset)
    return stream.read(32)


@dataclass(frozen=True)
class HDNode:
    scalar: int
    chaincode: bytes

    def __post_init__(self):
        if type(self.scalar) is not int or not 1 <= self.scalar < ORDER:
            raise UnsupportedScalar("Zero or out-of-order scalar; no modern retry/substitution")
        if not isinstance(self.chaincode, bytes) or len(self.chaincode) != 32:
            raise ValueError("Chain code must be 32 bytes")

    @cached_property
    def public_key(self):
        return ec.derive_private_key(self.scalar, ec.SECP256K1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def master(seed):
    if not isinstance(seed, bytes) or not seed:
        raise ValueError("Seed must be nonempty raw bytes")
    result = hmac.digest(b"Bitcoin seed", seed, "sha512")
    return HDNode(int.from_bytes(result[:32], "big"), result[32:])


def hardened_field(scalar):
    integer(scalar, 1, ORDER - 1, "private scalar")
    # Exact ECKey.toBytes().slice(0,32): compressed suffix can enter the field.
    return (scalar.to_bytes((scalar.bit_length() + 7) // 8, "big") + b"\x01")[:32]


def derive(node, index):
    integer(index, 0, 2**32 - 1, "child index")
    data = b"\0" + hardened_field(node.scalar) if index & HARDENED else node.public_key
    result = hmac.digest(node.chaincode, data + index.to_bytes(4, "big"), "sha512")
    # Historical ECKey.add reduces the sum, and does NOT reject IL >= n.
    return HDNode((node.scalar + int.from_bytes(result[:32], "big")) % ORDER, result[32:])


def wallet_branch(seed, branch=0):
    integer(branch, 0, 1, "wallet branch")
    return derive(derive(master(seed), HARDENED), branch)


def mask_scalar(scalar, width, mode="low"):
    integer(scalar, 1, ORDER - 1, "private scalar")
    integer(width, 1, 256, "observation width")
    if mode == "low":
        residue = scalar & ((1 << (width - 1)) - 1)
    elif mode == "high":
        residue = scalar >> (257 - width)
    else:
        raise ValueError("Mask must be low or high")
    result = (1 << (width - 1)) | residue
    if result >= ORDER:
        raise UnsupportedScalar("Masked scalar exceeds curve order")
    return result


def observations(seed, indices, branch=0, start_index=0, mask="low"):
    """Sibling i = start_index + observation_number - 1, preserving skipped indices."""
    integer(start_index, 0, HARDENED - 1, "starting child index")
    parent = wallet_branch(seed, branch)
    output = {}
    for number in indices:
        integer(number, 1, 256, "observation number")
        child_index = integer(start_index + number - 1, 0, HARDENED - 1, "mapped child index")
        if number in output:
            raise ValueError("Duplicate observation number")
        output[number] = mask_scalar(derive(parent, child_index).scalar, number, mask)
    return output
