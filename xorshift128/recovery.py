"""Exact GF(2) state reconstruction for the Marsaglia xor128 recurrence."""
import itertools

MASK32 = (1 << 32) - 1


LAYOUTS = [
    {"id": "fixed256_words_le", "unit_bits": 32, "count": 8, "order": "little", "extract": "raw"},
    {"id": "fixed256_words_be", "unit_bits": 32, "count": 8, "order": "big", "extract": "raw"},
    {"id": "fixed256_words_le_bswap", "unit_bits": 32, "count": 8, "order": "little", "extract": "bswap"},
    {"id": "fixed256_words_be_bswap", "unit_bits": 32, "count": 8, "order": "big", "extract": "bswap"},
    {"id": "variable_words_le", "unit_bits": 32, "count": "ceil(n/32)", "order": "little", "extract": "raw"},
    {"id": "variable_words_be", "unit_bits": 32, "count": "ceil(n/32)", "order": "big", "extract": "raw"},
    {"id": "fixed256_lowbytes_le", "unit_bits": 8, "count": 32, "order": "little", "extract": "low8"},
    {"id": "fixed256_lowbytes_be", "unit_bits": 8, "count": 32, "order": "big", "extract": "low8"},
    {"id": "fixed256_highbytes_le", "unit_bits": 8, "count": 32, "order": "little", "extract": "high8"},
    {"id": "fixed256_highbytes_be", "unit_bits": 8, "count": 32, "order": "big", "extract": "high8"},
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def configs():
    return [dict(id=f"{mask}/{layout['id']}/skip{skip}", mask=mask,
                 layout=dict(layout), skip_after_each_key=skip)
            for mask, layout, skip in itertools.product(("low", "high"), LAYOUTS, (0, 1, 8))
            if mask == "low" or isinstance(layout["count"], int)]


def numeric_step(state):
    x, y, z, w = state
    t = (x ^ (x << 11)) & MASK32
    new_w = (w ^ (w >> 19) ^ t ^ (t >> 8)) & MASK32
    return (y, z, w, new_w), new_w


def symbolic_step(state):
    # Each list entry is a 128-bit coefficient vector for one output bit.
    x, y, z, w = state
    t = [x[b] ^ (x[b - 11] if b >= 11 else 0) for b in range(32)]
    new_w = [w[b] ^ (w[b + 19] if b + 19 < 32 else 0) ^ t[b]
             ^ (t[b + 8] if b + 8 < 32 else 0) for b in range(32)]
    return (y, z, w, new_w), new_w


def count_units(n, layout):
    return (n + 31) // 32 if isinstance(layout["count"], str) else layout["count"]


def selected_raw_bit(unit_bit, extract):
    if extract == "bswap":
        return (3 - unit_bit // 8) * 8 + unit_bit % 8
    return unit_bit + (24 if extract == "high8" else 0)


def check_indices(indices):
    result = sorted(set(indices))
    require(result and all(isinstance(n, int) and 1 <= n <= 256 for n in result),
            "Indices must be nonempty and between 1 and 256")
    return result


def predict(state, indices, config):
    indices = check_indices(indices)
    wanted = set(indices)
    require(0 <= state < 1 << 128, "State must fit 128 bits")
    state = tuple((state >> (32 * j)) & MASK32 for j in range(4))
    layout = config["layout"]
    result = {}
    for n in range(1, indices[-1] + 1):
        count = count_units(n, layout)
        raw = 0
        for j in range(count):
            state, word = numeric_step(state)
            if layout["extract"] == "bswap":
                unit = int.from_bytes(word.to_bytes(4, "little"), "big")
            elif layout["extract"] == "low8":
                unit = word & 255
            elif layout["extract"] == "high8":
                unit = word >> 24
            else:
                unit = word
            position = j if layout["order"] == "little" else count - 1 - j
            raw |= unit << (position * layout["unit_bits"])
        for _ in range(config["skip_after_each_key"]):
            state, _ = numeric_step(state)
        if n in wanted:
            retained = raw & ((1 << (n - 1)) - 1) if config["mask"] == "low" else raw >> (257 - n)
            result[n] = (1 << (n - 1)) | retained
    return result


def coefficient_rows(indices, config):
    indices = check_indices(indices)
    wanted = set(indices)
    state = tuple([1 << (32 * word + bit) for bit in range(32)] for word in range(4))
    layout = config["layout"]
    for n in range(1, indices[-1] + 1):
        count = count_units(n, layout)
        words = []
        for _ in range(count):
            state, word = symbolic_step(state)
            words.append(word)
        for _ in range(config["skip_after_each_key"]):
            state, _ = symbolic_step(state)
        if n not in wanted:
            continue
        for bit in range(n - 1):
            source_bit = bit if config["mask"] == "low" else bit + 257 - n
            unit, unit_bit = divmod(source_bit, layout["unit_bits"])
            draw = unit if layout["order"] == "little" else count - 1 - unit
            require(0 <= draw < count, "Observed bit outside raw source")
            yield {"observation_index": n, "retained_bit": bit, "source_bit": source_bit,
                   "coefficients": words[draw][selected_raw_bit(unit_bit, layout["extract"])]}


def solve(values, config):
    for n, value in values.items():
        require(1 << (n - 1) <= value < 1 << n, "Malformed masked observation")
    basis, observations = {}, []
    rank_128_at = None
    zero_satisfies = True
    for info in coefficient_rows(values, config):
        equation = len(observations)
        observations.append({"observation_index": info["observation_index"], "retained_bit": info["retained_bit"]})
        row = info["coefficients"]
        rhs = (values[info["observation_index"]] >> info["retained_bit"]) & 1
        zero_satisfies &= rhs == 0
        witness = 1 << equation
        while row:
            pivot = row.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (row, rhs, witness)
                if len(basis) == 128 and rank_128_at is None:
                    rank_128_at = observations[-1]
                break
            other, answer, certificate = basis[pivot]
            row ^= other
            rhs ^= answer
            witness ^= certificate
        else:
            if rhs:
                certificate = [obs for j, obs in enumerate(observations) if witness >> j & 1]
                return {"compatible": False, "rank": len(basis), "equations_added": equation + 1,
                        "initial_state_hex": None, "surviving_states": 0, "rank_128_at": rank_128_at,
                        "first_conflict": {**observations[-1], "certificate": certificate,
                                           "meaning": "These rows XOR to coefficients 0 and RHS 1."}}
    state = None
    if len(basis) == 128:
        state = 0
        for pivot in range(128):
            row, rhs, _ = basis[pivot]
            state |= (rhs ^ ((row & state).bit_count() & 1)) << pivot
        require(predict(state, values, config) == values, "Recovered state failed numerical replay")
    survivors = (1 << (128 - len(basis))) - int(zero_satisfies)
    return {"compatible": survivors > 0, "rank": len(basis), "equations_added": len(observations),
            "initial_state_hex": f"{state:032x}" if state is not None else None,
            "surviving_states": survivors, "rank_128_at": rank_128_at, "first_conflict": None,
            "zero_state_excluded": bool(zero_satisfies)}


def mismatch(predicted, observed):
    for n in sorted(observed):
        difference = predicted[n] ^ observed[n]
        if difference:
            return {"observation_index": n, "retained_bit": (difference & -difference).bit_length() - 1}
    return None
