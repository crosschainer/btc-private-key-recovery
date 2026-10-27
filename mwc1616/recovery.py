"""MWC1616 exact bit-vector constraints and canonical-state replay."""
import time
import z3

MASK32 = 2**32 - 1
VARIANTS = [
    {"id": "v8_3_29", "multipliers": [18273, 36969], "historical": True},
    {"id": "v8_3_30", "multipliers": [18030, 36969], "historical": True},
    {"id": "blog_illustration", "multipliers": [18030, 30903], "historical": False},
]
LAYOUTS = []
for order in ("big", "little"):
    for projection in ("word32", "bswap32"):
        LAYOUTS.append({"id": f"fixed256_{projection}_{order}", "bits": 32,
                        "projection": projection, "order": order, "width": "fixed256"})
    LAYOUTS.append({"id": f"variable_words_{order}", "bits": 32,
                    "projection": "word32", "order": order, "width": "ceil_n"})
    for projection, bits in (("high16", 16), ("low16", 16),
                             ("high8", 8), ("low8", 8), ("high4", 4)):
        LAYOUTS.append({"id": f"fixed256_{projection}_{order}", "bits": bits,
                        "projection": projection, "order": order, "width": "fixed256"})


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def step(state, multipliers):
    return tuple(a * (x & 65535) + (x >> 16) for x, a in zip(state, multipliers))


def output(state):
    return ((state[0] << 16) | (state[1] & 65535)) & MASK32


def project(word, projection):
    if projection == "word32":
        return word
    if projection == "bswap32":
        return int.from_bytes(word.to_bytes(4, "big"), "little")
    bits = int(projection[4:] if projection.startswith("high") else projection[3:])
    return word >> (32 - bits) if projection.startswith("high") else word & ((1 << bits) - 1)


def count_units(n, layout):
    return (n + layout["bits"] - 1) // layout["bits"] if layout["width"] == "ceil_n" else 256 // layout["bits"]


def offsets(n, layout):
    count = count_units(n, layout)
    return [layout["bits"] * (j if layout["order"] == "little" else count - 1 - j)
            for j in range(count)]


def generate(state, multipliers, layout, last=128, skip=0):
    values = {}
    for n in range(1, last + 1):
        raw = 0
        for offset in offsets(n, layout):
            state = step(state, multipliers)
            raw |= project(output(state), layout["projection"]) << offset
        values[n] = (1 << (n - 1)) | (raw & ((1 << (n - 1)) - 1))
        for _ in range(skip):
            state = step(state, multipliers)
    return values


def observed_units(n, scalar, layout):
    result = []
    for j, offset in enumerate(offsets(n, layout)):
        bits = min(layout["bits"], n - 1 - offset)
        if bits > 0:
            result.append((j, bits, (scalar >> offset) & ((1 << bits) - 1)))
    return result


def active_components(layout):
    projection = layout["projection"]
    return (0,) if projection.startswith("high") else (1,) if projection.startswith("low") else (0, 1)


def symbolic_projection(state, layout):
    word = (state[0] << 16) | (state[1] & 65535)
    projection = layout["projection"]
    if projection == "word32":
        return word
    if projection == "bswap32":
        return z3.Concat(*(z3.Extract(i + 7, i, word) for i in (0, 8, 16, 24)))
    bits = layout["bits"]
    return z3.LShR(word, 32 - bits) if projection.startswith("high") else word & ((1 << bits) - 1)


def make_solver(n, scalar, multipliers, layout, timeout_ms):
    """State variables represent the state AFTER each observed Math.random draw."""
    observations = observed_units(n, scalar, layout)
    require(observations, "Anchor has no retained bits")
    first, last = observations[0][0], observations[-1][0]
    require([o[0] for o in observations] == list(range(first, last + 1)), "Noncontiguous anchor")
    solver = z3.SolverFor("QF_BV")
    solver.set(timeout=timeout_ms, random_seed=0)
    states = [(z3.BitVec(f"s0_{j}", 32), z3.BitVec(f"s1_{j}", 32))
              for j in range(last - first + 1)]
    active = active_components(layout)
    for j, state in enumerate(states):
        if j:
            for component in active:
                before = states[j - 1][component]
                solver.add(state[component] == multipliers[component] * (before & 65535)
                           + z3.LShR(before, 16))
        _, bits, expected = observations[j]
        unit = symbolic_projection(state, layout)
        solver.add(z3.Extract(bits - 1, 0, unit) == expected)
    # No seed bounds or nonzero assumptions. Inactive components never affect a
    # projected output and are assigned a representative zero only at replay.
    return solver, states[0], observations


def check(solver):
    started = time.monotonic()
    status = solver.check()
    return str(status), time.monotonic() - started


def state_from_model(solver, anchor, layout):
    model = solver.model()
    active = active_components(layout)
    return tuple(model.eval(anchor[i], model_completion=True).as_long() if i in active else 0
                 for i in range(2))


def block_state(solver, anchor, state, layout):
    solver.add(z3.Or(*(anchor[i] != state[i] for i in active_components(layout))))


def rewind_canonical(state, multipliers, draws):
    """After two draws every uint32 seed lies in [0, a*65536-1].

    On this interval f(x)=a*x mod p, p=a*65536-1, with 0 and p
    separate fixed points. Its inverse on the interior is x*65536 mod p.
    Canonical representatives therefore reproduce every observed key here:
    observation 1 has zero observations and observation 2 starts at draw >= 2.
    """
    result = []
    for value, a in zip(state, multipliers):
        modulus = a * 65536 - 1
        if not 0 <= value <= modulus:
            return None
        result.append(value if value in (0, modulus)
                      else value * pow(65536, draws, modulus) % modulus)
    return tuple(result)


def anchor_draw(n, first_unit, layout, skip):
    return sum(count_units(i, layout) + skip for i in range(1, n)) + first_unit + 1


def replay_candidate(state, multipliers, layout, n, first_unit, values, skip):
    initial = rewind_canonical(state, multipliers, anchor_draw(n, first_unit, layout, skip))
    if initial is None:
        return {"compatible": False, "reason": "anchor_has_no_canonical_predecessor"}, None
    generated = generate(initial, multipliers, layout, last=max(values), skip=skip)
    mismatches = [i for i, value in sorted(values.items()) if generated[i] != value]
    return {"compatible": not mismatches, "first_mismatch": mismatches[0] if mismatches else None,
            "compared_keys": len(values), "compared_retained_bits": sum(i - 1 for i in values),
            "canonical_initial_state": [hex(x) for x in initial]}, generated
