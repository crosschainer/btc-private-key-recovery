"""Bounded chain-code recovery for a custom masked feedback construction."""
from functools import lru_cache
import hashlib
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MODES = ("uncompressed", "compressed")
LIMITS = {"max_states": 250000, "max_extensions": 10000000, "seconds": 300}

def require(condition, message):
    if not condition:
        raise AssertionError(message)


@lru_cache(maxsize=256)
def public_hash(key, mode="uncompressed"):
    require(mode in MODES, "Unknown SEC encoding")
    fmt = (serialization.PublicFormat.UncompressedPoint if mode == "uncompressed"
           else serialization.PublicFormat.CompressedPoint)
    raw = ec.derive_private_key(key, ec.SECP256K1()).public_key().public_bytes(
        serialization.Encoding.X962, fmt)
    return int.from_bytes(hashlib.sha256(hashlib.sha256(raw).digest()).digest(), "big")


def edge_mask(depth, width):
    """Bits known after extending the prefix and suffix to depth each."""
    require(0 <= depth <= width, "Invalid depth")
    low = (1 << depth) - 1
    return low | (low << (width - depth))


def extend(value, old_mask, new_mask):
    require(value & ~old_mask == 0 and old_mask & ~new_mask == 0, "Invalid partial state")
    added = new_mask ^ old_mask
    subset = added
    while True:
        yield value | subset
        if subset == 0:
            return
        subset = (subset - 1) & added


def possible_nexts(key, hashed, code_value, depth, width=256, order=ORDER):
    """Exact one-transition image of a prefix/suffix chain-code box.

    The unknown middle makes X=C xor hashed an arithmetic progression. Enumerate
    every attainable modular quotient, then compute its retained low residue.
    Past constraints are not propagated as middle-bit intervals; complete codes
    MUST be replayed before they are accepted as solutions.
    """
    require(0 < key < order and 0 < depth < width, "Invalid key/depth")
    full = (1 << width) - 1
    known = edge_mask(depth, width)
    require(0 <= hashed <= full and code_value & ~known == 0, "Invalid box")
    xmin = (code_value ^ hashed) & known
    xmax = xmin | (full ^ known)
    low_mask = (1 << depth) - 1
    stride = 1 << depth
    first_q, last_q = key * xmin // order, key * xmax // order
    candidates = set()
    tried = 0
    for quotient in range(first_q, last_q + 1):
        tried += 1
        left = max(xmin, (quotient * order + key - 1) // key)
        right = min(xmax, ((quotient + 1) * order - 1) // key)
        if known == full:
            attainable = left <= xmin <= right
        else:
            first = xmin + max(0, (left - xmin + stride - 1) // stride) * stride
            attainable = first <= right
        if attainable:
            residue = (key * (xmin & low_mask) - quotient * order) & low_mask
            result = stride | residue
            if result < order:
                candidates.add(result)
    return candidates, tried


def generate(code, last, mode="uncompressed", width=256, order=ORDER, hash_fn=None):
    require(0 <= code < 1 << width and 1 <= last < width, "Invalid chain request")
    hash_fn = hash_fn or (lambda key: public_hash(key, mode))
    values = {1: 1}
    for source in range(1, last):
        key = values[source]
        raw = key * (code ^ hash_fn(key)) % order
        values[source + 1] = (1 << source) | (raw & ((1 << source) - 1))
        require(values[source + 1] < order, "Masked result outside scalar range")
    return values


def replay(code, observations, hash_fn, order=ORDER):
    """Check a complete code directly, stopping at its first disagreement."""
    key = 1
    for source in range(1, max(observations)):
        raw = key * (code ^ hash_fn(key)) % order
        key = (1 << source) | (raw & ((1 << source) - 1))
        if key >= order or (source + 1 in observations and key != observations[source + 1]):
            return False
    return True


def solve(observations, mode="uncompressed", width=256, order=ORDER, hash_fn=None,
          limits=None):
    """Sound exclusion over all width-bit codes, or exact full-code recovery.

    Limits produce 'inconclusive', never 'excluded'. A surviving partial box is
    not an asserted solution. Unknown observation widths are explicitly traversed.
    """
    require(observations.get(1) == 1 and len(observations) >= 2, "Need observation 1 and later observations")
    require(1 < order < 1 << width, "Invalid order")
    for index, key in observations.items():
        require(1 <= index < width and 1 << (index - 1) <= key < min(1 << index, order), "Invalid observation")
    limits = dict(LIMITS if limits is None else limits)
    hash_fn = hash_fn or (lambda key: public_hash(key, mode))
    started = time.monotonic()
    states = {(0, 1)}
    old_mask = 0
    trace, extensions, replays = [], 0, 0
    last = max(observations)

    def finish(status, **extra):
        return {"status": status, "mode": mode, "width": width, "order_hex": hex(order),
                "observation_indices": sorted(observations), "trace": trace,
                "extensions": extensions, "exact_replays": replays,
                "elapsed_seconds": round(time.monotonic() - started, 6), **extra}

    for source in range(1, last):
        known = edge_mask(source, width)
        following = set()
        row = {"source": source, "target": source + 1, "observed_target": source + 1 in observations,
               "known_code_bits": known.bit_count(), "incoming_states": len(states),
               "extensions": 0, "quotients_examined": 0}
        for value, key in sorted(states):
            hashed = hash_fn(key)
            for refined in extend(value, old_mask, known):
                extensions += 1
                row["extensions"] += 1
                if (extensions > limits["max_extensions"] or
                        time.monotonic() - started > limits["seconds"]):
                    row["outgoing_states"] = len(following)
                    row["incomplete"] = True
                    trace.append(row)
                    return finish("inconclusive", reason="extension or time limit", limits=limits)
                nexts, count = possible_nexts(key, hashed, refined, source, width, order)
                row["quotients_examined"] += count
                expected = observations.get(source + 1)
                for next_key in nexts:
                    if expected is None or next_key == expected:
                        following.add((refined, next_key))
                if len(following) > limits["max_states"]:
                    row["outgoing_states"] = len(following)
                    row["incomplete"] = True
                    trace.append(row)
                    return finish("inconclusive", reason="state limit", limits=limits)
        row["outgoing_states"] = len(following)
        trace.append(row)
        if not following:
            return finish("excluded", eliminated_at=source + 1,
                          coverage="all chain codes; empty necessary-condition superset")
        if known == (1 << width) - 1:
            solutions = []
            for code in sorted({code for code, _ in following}):
                if time.monotonic() - started > limits["seconds"]:
                    return finish("inconclusive", reason="time limit during full-code replay", limits=limits)
                replays += 1
                if replay(code, observations, hash_fn, order):
                    solutions.append(hex(code))
            return finish("recovered" if solutions else "excluded", chain_codes=solutions,
                          coverage="all chain codes with exact replay of complete survivors")
        states, old_mask = following, known
    return finish("partial", surviving_boxes=len(states), known_code_bits=old_mask.bit_count(),
                  boxes=[{"value_hex": hex(value), "current_key_hex": hex(key)} for value, key in sorted(states)],
                  coverage="necessary-condition superset only; middle bits unresolved")
