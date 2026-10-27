"""Finite hash-feedback rule enumeration and exact masked-chain replay."""
from functools import lru_cache
import hashlib
import itertools
import subprocess
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def ripemd_fallback():
    def digest(data):
        return subprocess.run(["openssl", "dgst", "-provider", "legacy", "-ripemd160", "-binary"], input=data, capture_output=True, check=True).stdout
    return digest

ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


ENCODINGS = ["bytes32_be", "bytes32_le", "minimal_be", "minimal_le",
             "hex64_lower", "hex64_upper", "hex_lower", "hex_upper",
             "hex_even_lower", "hex_0x_lower", "decimal",
             "wif_compressed", "wif_uncompressed", "sec_compressed", "sec_uncompressed"]


DIGESTS = ["sha256", "sha256d", "sha256_hex_sha256",
           "sha512_first32", "sha512_last32", "hash160"]


COUNTERS = ["none"] + [f"{which}_{encoding}_{side}"
    for which in ("source", "target")
    for encoding in ("decimal", "u32be", "u32le", "u8")
    for side in ("prefix", "suffix")]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def configurations():
    states = [(encoding, state) for encoding in ENCODINGS
              for state in ("full", "residue")
              if state == "full" or not encoding.startswith("sec_")]
    for (encoding, state), digest, byte_order, counter, update, direction in itertools.product(
            states, DIGESTS, ("big", "little"), COUNTERS,
            ("replace", "add_mod_order", "multiply_mod_order"), (1, -1)):
        yield {"encoding": encoding, "state": state, "digest": digest,
               "digest_byte_order": byte_order, "counter": counter,
               "update": update, "direction": direction}


def config_id(config):
    return "/".join(str(config[key]) for key in (
        "encoding", "state", "digest", "digest_byte_order", "counter", "update", "direction"))


def sha(data):
    return hashlib.sha256(data).digest()


def base58check(payload):
    raw = payload + sha(sha(payload))[:4]
    number, result = int.from_bytes(raw, "big"), ""
    while number:
        number, rem = divmod(number, 58)
        result = ALPHABET[rem] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


@lru_cache(maxsize=65536)
def encode(value, name):
    if name.startswith("bytes32_"):
        return value.to_bytes(32, "big" if name.endswith("be") else "little")
    if name.startswith("minimal_"):
        return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big" if name.endswith("be") else "little")
    if name == "hex64_lower":
        return f"{value:064x}".encode()
    if name == "hex64_upper":
        return f"{value:064X}".encode()
    if name == "hex_lower":
        return f"{value:x}".encode()
    if name == "hex_upper":
        return f"{value:X}".encode()
    if name == "hex_even_lower":
        text = f"{value:x}"
        return ("0" * (len(text) % 2) + text).encode()
    if name == "hex_0x_lower":
        return hex(value).encode()
    if name == "decimal":
        return str(value).encode()
    if name.startswith("wif_"):
        return base58check(b"\x80" + value.to_bytes(32, "big") +
                          (b"\x01" if name == "wif_compressed" else b"")).encode()
    if name.startswith("sec_"):
        form = serialization.PublicFormat.CompressedPoint if name == "sec_compressed" else serialization.PublicFormat.UncompressedPoint
        return ec.derive_private_key(value, ec.SECP256K1()).public_key().public_bytes(serialization.Encoding.X962, form)
    raise ValueError(name)


def message_bytes(value, source, target, config):
    data = encode(value, config["encoding"])
    if config["counter"] == "none":
        return data
    which, kind, side = config["counter"].split("_")
    index = source if which == "source" else target
    if kind == "decimal":
        counter = str(index).encode()
        return counter + b":" + data if side == "prefix" else data + b":" + counter
    counter = index.to_bytes(1 if kind == "u8" else 4, "little" if kind == "u32le" else "big")
    return counter + data if side == "prefix" else data + counter


def digest_bytes(data, name):
    if name == "sha256":
        return sha(data)
    if name == "sha256d":
        return sha(sha(data))
    if name == "sha256_hex_sha256":
        return sha(sha(data).hex().encode())
    if name == "sha512_first32":
        return hashlib.sha512(data).digest()[:32]
    if name == "sha512_last32":
        return hashlib.sha512(data).digest()[32:]
    if name == "hash160":
        hashed = sha(data)
        try:
            return hashlib.new("ripemd160", hashed).digest()
        except ValueError:
            return ripemd_fallback()(hashed)
    raise ValueError(name)


def step(key, source, target, config):
    require(target == source + config["direction"] and 1 <= target <= 255, "Invalid transition")
    state = key if config["state"] == "full" else key - (1 << (source - 1))
    raw = int.from_bytes(digest_bytes(message_bytes(state, source, target, config), config["digest"]), config["digest_byte_order"])
    if config["update"] == "add_mod_order":
        raw = (key + raw) % ORDER
    elif config["update"] == "multiply_mod_order":
        raw = (key * raw) % ORDER
    boundary = 1 << (target - 1)
    return boundary | (raw & (boundary - 1))


def traverse(key, source, target, config):
    require((target - source) * config["direction"] > 0, "Wrong traversal direction")
    for index in range(source, target, config["direction"]):
        key = step(key, index, index + config["direction"], config)
    return key


def compare(values, config, adjacent_only=False):
    indices = sorted(values, reverse=config["direction"] == -1)
    tested, informative, matched, first = 0, 0, [], None
    for source, target in zip(indices, indices[1:]):
        if adjacent_only and abs(target - source) != 1:
            continue
        predicted = traverse(values[source], source, target, config)
        tested += 1
        informative += target > 1
        if predicted == values[target]:
            matched.append([source, target])
        elif first is None:
            first = {"source": source, "target": target, "expected_hex": hex(values[target]),
                     "predicted_hex": hex(predicted), "source_hex": hex(values[source])}
    return {"compatible": tested > 0 and first is None, "tested_transitions": tested,
            "informative_transitions": informative, "matched_transitions": matched,
            "first_counterexample": first}


def continuous(values, config):
    indices = sorted(values, reverse=config["direction"] == -1)
    key, source = values[indices[0]], indices[0]
    for target in indices[1:]:
        key = traverse(key, source, target, config)
        if key != values[target]:
            return False
        source = target
    return True


def controls(config):
    indices = list(range(32, 38))
    if config["direction"] == -1:
        indices.reverse()
    values = {indices[0]: (1 << (indices[0] - 1)) + 0x12345}
    for source, target in zip(indices, indices[1:]):
        values[target] = step(values[source], source, target, config)
    require(compare(values, config, True)["compatible"], "Full synthetic control failed")
    gapped = {index: values[index] for index in (32, 33, 36, 37)}
    require(compare(gapped, config)["compatible"] and continuous(gapped, config), "Gapped synthetic control failed")
    gapped[indices[-1]] ^= 1
    require(not compare(gapped, config)["compatible"] and not continuous(gapped, config), "Corruption not detected")
