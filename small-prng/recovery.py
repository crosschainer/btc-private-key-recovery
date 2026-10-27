"""Linear xorshift recovery, projected LCG recovery, and bounded Python seed checks."""
import random

MASK32 = (1 << 32) - 1


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def xorshift(state, shifts, orientation):
    for amount, direction in zip(shifts, orientation):
        state ^= (state << amount) & MASK32 if direction == "L" else state >> amount
    return state & MASK32


def reverse32(value):
    return int.from_bytes(value.to_bytes(4, "little"), "big")


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


def draw_xorshift(state, n, config):
    layout = config["layout"]
    count = (n + 31) // 32 if isinstance(layout["count"], str) else layout["count"]
    value = 0
    for j in range(count):
        state = xorshift(state, config["shifts"], config["orientation"])
        unit = state
        if layout["extract"] == "bswap":
            unit = reverse32(unit)
        elif layout["extract"] == "low8":
            unit &= 255
        elif layout["extract"] == "high8":
            unit >>= 24
        offset = j if layout["order"] == "little" else count - 1 - j
        value |= unit << (layout["unit_bits"] * offset)
    for _ in range(config["skip_after_each_key"]):
        state = xorshift(state, config["shifts"], config["orientation"])
    return state, value


def xorshift_values(state, indices, config):
    values = {}
    for n in range(1, max(indices) + 1):
        state, raw = draw_xorshift(state, n, config)
        if n in indices:
            values[n] = (1 << (n - 1)) | (raw & ((1 << (n - 1)) - 1))
    return values


def scalar_mismatch(actual, expected):
    for n in sorted(expected):
        if actual[n] != expected[n]:
            differing = actual[n] ^ expected[n]
            return {"observation_index": n, "retained_bit": (differing & -differing).bit_length() - 1}
    return None


def solve_xorshift(values, config):
    # Columns carry each initial-state basis bit through the numeric generator.
    # Each observed source bit gives one exact linear equation over GF(2).
    states = [1 << j for j in range(32)]
    basis = {}
    constraints = 0
    for n in range(1, max(values) + 1):
        draws = [draw_xorshift(s, n, config) for s in states]
        states = [s for s, _ in draws]
        if n not in values:
            continue
        for bit in range(n - 1):
            coefficients = sum(((raw >> bit) & 1) << j for j, (_, raw) in enumerate(draws))
            rhs = (values[n] >> bit) & 1
            constraints += 1
            while coefficients:
                pivot = coefficients.bit_length() - 1
                if pivot not in basis:
                    basis[pivot] = (coefficients, rhs)
                    break
                row, result = basis[pivot]
                coefficients ^= row
                rhs ^= result
            else:
                if rhs:
                    return {"compatible": False, "rank": len(basis), "equations_added": constraints,
                            "first_conflict": {"observation_index": n, "retained_bit": bit}, "surviving_states": 0}
            if len(basis) == 32:
                state = 0
                for pivot in range(32):
                    row, result = basis[pivot]
                    result ^= (row & state).bit_count() & 1
                    state |= result << pivot
                predicted = xorshift_values(state, set(values), config)
                mismatch = scalar_mismatch(predicted, values)
                return {"compatible": mismatch is None, "rank": 32, "equations_added": constraints,
                        "first_conflict": mismatch, "surviving_states": int(mismatch is None),
                        "_state": state if mismatch is None else None}
    return {"compatible": True, "rank": len(basis), "equations_added": constraints,
            "first_conflict": None, "surviving_states": 1 << (32 - len(basis))}


LCGS = [
    {"id": "recipe_1103515245_12345_mod31_out15", "a": 1103515245, "c": 12345, "state_bits": 31, "shift": 16, "output_bits": 15},
    {"id": "recipe_1103515245_12345_mod32_out15", "a": 1103515245, "c": 12345, "state_bits": 32, "shift": 16, "output_bits": 15},
    {"id": "wine_msvcrt_mod32_out15", "a": 214013, "c": 2531011, "state_bits": 32, "shift": 16, "output_bits": 15},
    {"id": "java_random_next32", "a": 0x5DEECE66D, "c": 11, "state_bits": 48, "shift": 16, "output_bits": 32},
    {"id": "java_random_next31", "a": 0x5DEECE66D, "c": 11, "state_bits": 48, "shift": 17, "output_bits": 31},
]


def affine_jump(config, stride):
    mask = (1 << config["state_bits"]) - 1
    a, c = 1, 0
    for _ in range(stride):
        a, c = a * config["a"] & mask, (config["a"] * c + config["c"]) & mask
    return a, c


def lcg_output(state, config):
    return (state >> config["shift"]) & ((1 << config["output_bits"]) - 1)


def solve_lcg_projection(observed, config, stride):
    # Condition exactly on the first complete projected output, then enumerate
    # every hidden state bit. This covers all states, not just small seeds.
    first = min(observed)
    bits, shift = config["output_bits"], config["shift"]
    missing_top = config["state_bits"] - bits - shift
    candidates = [(top << (bits + shift)) | (observed[first] << shift) | low
                  for top in range(1 << missing_top) for low in range(1 << shift)]
    initial_count = len(candidates)
    trace = [{"observation_index": first, "states_remaining": initial_count}]
    mask = (1 << config["state_bits"]) - 1
    outmask = (1 << bits) - 1
    previous = first
    for n in sorted(observed):
        if n == first:
            continue
        a, c = affine_jump(config, stride * (n - previous))
        candidates = [next_state for state in candidates
                      if ((next_state := (a * state + c) & mask) >> shift) & outmask == observed[n]]
        trace.append({"observation_index": n, "states_remaining": len(candidates)})
        previous = n
        if not candidates:
            break
    return {"compatible": bool(candidates), "conditioned_states_enumerated": initial_count,
            "surviving_states": len(candidates), "trace": trace, "_terminal_states": candidates}


def python_draw(generator, n, config):
    mode = config["mode"]
    if mode == "getrandbits256":
        raw = generator.getrandbits(256)
    elif mode == "getrandbits256_reverse_bytes":
        raw = int.from_bytes(generator.getrandbits(256).to_bytes(32, "little"), "big")
    elif mode == "getrandbits_n":
        raw = generator.getrandbits(n)
    elif mode == "getrandbits_n_minus_1":
        # Avoid getrandbits(0) for compatibility with historical Python versions:
        # observation 1 consumes zero words in this recipe.
        raw = generator.getrandbits(n - 1) if n > 1 else 0
    else:
        raise ValueError(mode)
    for _ in range(config["skip_after_each_key"]):
        generator.getrandbits(32)
    return (1 << (n - 1)) | (raw & ((1 << (n - 1)) - 1))


def python_generator(seed, config):
    generator = random.Random(seed)
    for _ in range(config["initial_raw32_draws"]):
        generator.getrandbits(32)
    return generator


def python_mismatch(seed, values, config):
    generator = python_generator(seed, config)
    for n in range(1, max(values) + 1):
        candidate = python_draw(generator, n, config)
        if n in values and candidate != values[n]:
            return n
    return None
