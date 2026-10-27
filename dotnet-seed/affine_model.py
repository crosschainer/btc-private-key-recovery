"""Four modular-affine branches of the historical System.Random constructor.

For every seed magnitude outside EXCEPTIONAL_SEEDS, branch_for_seed(s) selects
a branch whose output coefficients exactly reproduce the historical stream:
    output[t] = (a[t] * s + b[t]) % MODULUS.

The four exceptional magnitudes must be checked with the historical numeric
reference. Enumerating all four branches overapproximates constructor states;
complete numeric replay decides whether a candidate is an actual seeded
stream. Branch membership is an optional earlier filter. See README.md for
the finite coverage argument.
"""

MODULUS = (1 << 31) - 1
INITIAL_CONSTANT = 161803398
EXCEPTIONAL_SEEDS = (614279151, 1235228408, 1235545220, 1333158113)
BRANCHES = tuple(range(4))


def _sub(left, right):
    return ((left[0] - right[0]) % MODULUS,
            (left[1] - right[1]) % MODULUS)


def _constant_add(value, increment):
    return value[0], (value[1] + increment) % MODULUS


def branch_for_seed(seed_magnitude):
    """Return branch 0..3, or None for a separately replayed exceptional seed.

    The argument is a magnitude in [0, 2**31-1], not a signed Int32 seed.
    Bit 0 selects the -2 update-24 correction; bit 1 selects +2 at update 55.
    """
    if type(seed_magnitude) is not int or not 0 <= seed_magnitude <= MODULUS:
        raise ValueError("Seed magnitude must be an integer in [0, 2**31-1]")
    if seed_magnitude in EXCEPTIONAL_SEEDS:
        return None
    initial24 = (21 * seed_magnitude + 897095970) % MODULUS
    updated31 = (997453707 * seed_magnitude + 890002099) % MODULUS
    difference24 = initial24 - INITIAL_CONSTANT + seed_magnitude
    difference55 = INITIAL_CONSTANT - seed_magnitude - updated31
    overflow24 = difference24 >= MODULUS + 2
    overflow55 = difference55 <= -MODULUS - 3
    return int(overflow24) | (int(overflow55) << 1)


def state_coefficients(branch):
    """Return 55 (a,b) pairs for final constructor slots 1..55.

    Branches are considered as algebraic formulas even where their overflow
    predicates do not hold. This is intentional for conservative enumeration.
    """
    if type(branch) is not int or branch not in BRANCHES:
        raise ValueError("Branch must be an integer from 0 through 3")
    state = [(0, 0)] * 56
    mj = ((-1) % MODULUS, INITIAL_CONSTANT)
    mk = (0, 1)
    state[55] = mj
    for i in range(1, 55):
        position = 21 * i % 55
        state[position] = mk
        mk = _sub(mj, mk)
        mj = state[position]
    for mixing_pass in range(4):
        for i in range(1, 56):
            state[i] = _sub(state[i], state[1 + (i + 30) % 55])
            if mixing_pass == 0 and i == 24 and branch & 1:
                state[i] = _constant_add(state[i], -2)
            if mixing_pass == 0 and i == 55 and branch & 2:
                state[i] = _constant_add(state[i], 2)
    return state[1:]


def output_coefficients(length, branch):
    """Return (a,b) pairs for zero-based outputs t=0..length-1.

    No initial draws are skipped. A declared warm-up of k draws can be modeled
    by requesting length+k outputs and using the suffix beginning at k.
    """
    if type(length) is not int or length < 0:
        raise ValueError("Length must be a nonnegative integer")
    state = [(0, 0)] + state_coefficients(branch)
    i, j = 0, 21
    outputs = []
    for _ in range(length):
        i = i + 1 if i < 55 else 1
        j = j + 1 if j < 55 else 1
        state[i] = _sub(state[i], state[j])
        outputs.append(state[i])
    return outputs
