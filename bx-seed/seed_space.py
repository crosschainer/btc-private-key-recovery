"""Finite output-space injectivity checks for explicit minstd byte recipes."""
import math

def difference_sieve(modulus, multiplier, output_modulus, length):
    if modulus < 3 or output_modulus < 2 or length < 1:
        raise ValueError("Invalid parameters")
    if math.gcd(modulus, output_modulus) != 1 or math.gcd(modulus, multiplier) != 1:
        raise ValueError("Both multipliers must be invertible modulo the state modulus")
    bound = (modulus - 2) // output_modulus
    candidates = range(1, bound + 1)
    counts = [len(candidates)]
    power = 1
    for _ in range(1, length):
        power = power * multiplier % modulus
        candidates = [e for e in candidates
                      if (residue := e * power % modulus) <= bound
                      or residue >= modulus - bound]
        counts.append(len(candidates))
        if not candidates:
            break
    return counts


def toy_controls():
    """Independently group actual streams to check all claimed exclusions."""
    checked = 0
    for modulus in (31, 127, 257):
        for multiplier in (3, 7, 17):
            for output_modulus in (3, 5, 16):
                for length in range(1, 9):
                    counts = difference_sieve(modulus, multiplier, output_modulus, length)
                    groups = {}
                    for initial in range(1, modulus):
                        state = initial
                        output = []
                        for _ in range(length):
                            state = multiplier * state % modulus
                            output.append(state % output_modulus)
                        groups.setdefault(tuple(output), []).append(initial)
                    if counts[-1] == 0:
                        assert len(groups) == modulus - 1
                    # Every concrete colliding pair must satisfy the independent
                    # centered-difference bounds at every emitted byte.
                    bound = (modulus - 2) // output_modulus
                    for group in groups.values():
                        for pos, left in enumerate(group):
                            for right in group[pos + 1:]:
                                x, y = left, right
                                for _ in range(length):
                                    x = multiplier * x % modulus
                                    y = multiplier * y % modulus
                                    assert (x - y) % output_modulus == 0
                                    assert abs((x - y) // output_modulus) <= bound
                    checked += 1
    return checked
