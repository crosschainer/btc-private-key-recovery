"""Offline secp256k1 affine arithmetic and hashing for synthetic research.

Variable-time reference implementation; no network access or data loading."""
import hashlib
import subprocess

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def hash160(data):
    sha = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except ValueError:
        return subprocess.run(["openssl", "dgst", "-provider", "legacy", "-ripemd160", "-binary"],
                              input=sha, capture_output=True, check=True).stdout


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def point_multiply(scalar, point):
    if scalar < 0:
        raise ValueError("Negative scalar")
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def parse_public_key(serialized):
    if len(serialized) == 33 and serialized[0] in (2, 3):
        x = int.from_bytes(serialized[1:], "big")
        if x >= P:
            raise ValueError("Invalid public-key x coordinate")
        y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
        if y % 2 != serialized[0] % 2:
            y = P - y
    elif len(serialized) == 65 and serialized[0] == 4:
        x = int.from_bytes(serialized[1:33], "big")
        y = int.from_bytes(serialized[33:], "big")
    else:
        raise ValueError("Unsupported public-key encoding")
    if not (0 <= x < P and 0 <= y < P and (y * y - x * x * x - 7) % P == 0):
        raise ValueError("Public key is not on secp256k1")
    return x, y


def verify(public_point, digest, r, s):
    if not 0 < r < N or not 0 < s < N:
        return False
    inverse = pow(s, -1, N)
    candidate = point_add(point_multiply(int.from_bytes(digest, "big") * inverse % N, G),
                          point_multiply(r * inverse % N, public_point))
    return candidate is not None and candidate[0] % N == r


ORDER = N

def decode_point(encoded):
    return parse_public_key(bytes.fromhex(encoded) if isinstance(encoded, str) else encoded)

def encode_point(point):
    if point is None:
        raise ValueError("Cannot encode the point at infinity")
    x, y = point
    encoded = bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
    if parse_public_key(encoded) != point:
        raise ValueError("Point is not on secp256k1")
    return encoded
