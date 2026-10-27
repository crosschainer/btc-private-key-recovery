"""Independent byte-domain contradiction and fixed-point replay."""
import itertools
FULL=(1<<256)-1

class AuditError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise AuditError(message)


def reconstruct_domains(values, config):
    """Map masked values to draw domains through explicit binary byte strings."""
    values = {int(n): int(value) for n, value in values.items()}
    _require(bool(values) and min(values) >= 1, "positive observation numbers required")
    _require(config["count"] in ("fixed32", "ceil_n", "ceil_n_minus_1"), "unknown byte count")
    _require(config["order"] in ("little", "big"), "unknown byte order")
    _require(config["mask"] in ("low", "high"), "unknown mask")
    _require(config["mask"] != "high" or config["count"] == "fixed32", "high mask needs fixed width")
    _require(isinstance(config["skip"], int) and config["skip"] >= 0, "invalid skip")
    domains = []
    byte_strings = [format(value, "08b") for value in range(256)]
    for n in range(1, max(values) + 1):
        if config["count"] == "fixed32":
            count = 32
        else:
            bits = n if config["count"] == "ceil_n" else n - 1
            count = (bits + 7) // 8
        if n not in values:
            domains.extend([FULL] * count)
        else:
            scalar = values[n]
            _require(2 ** (n - 1) <= scalar < 2 ** n, "scalar outside observation range")
            width = n - 1
            retained = format(scalar - 2 ** width, "0" + str(width) + "b") if width else ""
            _require(width <= count * 8, "observations exceed byte width")
            unknown = "?" * (count * 8 - width)
            pattern = unknown + retained if config["mask"] == "low" else retained + unknown
            chunks = [pattern[i:i + 8] for i in range(0, len(pattern), 8)]
            if config["order"] == "little":
                chunks.reverse()
            for chunk in chunks:
                allowed = 0
                for value, binary in enumerate(byte_strings):
                    if all(want == "?" or want == got for want, got in zip(chunk, binary)):
                        allowed += 2 ** value
                domains.append(allowed)
        if n != max(values):
            domains.extend([FULL] * config["skip"])
    return domains


def _bytes(domain):
    return {value for value in range(256) if domain & (1 << value)}


def enumerated_support(x_domain, a_domain, b_domain):
    """Return supported x,a,b values in x = a - b - c mod256, c in {0,1}."""
    original = (x_domain, a_domain, b_domain)
    if not all(original):
        return (0, 0, 0)
    # With two unconstrained variables every value of all three has support.
    if sum(domain == FULL for domain in original) >= 2:
        return original
    domains = tuple(_bytes(domain) for domain in original)
    pair = min(((0, 1), (0, 2), (1, 2)), key=lambda p: len(domains[p[0]]) * len(domains[p[1]]))
    found = [set(), set(), set()]
    for first, second in itertools.product(domains[pair[0]], domains[pair[1]]):
        for carry in (0, 1):
            if pair == (0, 1):
                x, a = first, second
                b = (a - x - carry) % 256
                if b not in domains[2]:
                    continue
            elif pair == (0, 2):
                x, b = first, second
                a = (x + b + carry) % 256
                if a not in domains[1]:
                    continue
            else:
                a, b = first, second
                x = (a - b - carry) % 256
                if x not in domains[0]:
                    continue
            found[0].add(x)
            found[1].add(a)
            found[2].add(b)
    return tuple(sum(2 ** value for value in values) for values in found)


def audit_result(values, config, result, check_fixed_point=True):
    """Replay every reported refinement, raising AuditError on invalid evidence."""
    domains = reconstruct_domains(values, config)
    initial_observations = sum(domain != FULL for domain in domains)
    trace = result.get("trace", [])
    status = result.get("status")
    _require(status in ("excluded", "survives_necessary_screen", "inconclusive_limit"), "unknown result status")
    saw_empty = False
    for number, step in enumerate(trace):
        _require(not saw_empty, "trace continues after contradiction")
        t = step["t"]
        _require(isinstance(t, int) and 55 <= t < len(domains), "invalid recurrence index")
        labels = ("x", "a", "b")
        _require(step["variable"] in labels, "invalid variable")
        slot = labels.index(step["variable"])
        positions = (t, t - 55, t - 34)
        target = positions[slot]
        before, after = int(step["before"], 16), int(step["after"], 16)
        _require(0 <= before <= FULL and 0 <= after <= FULL, "domain exceeds byte universe")
        _require(before == domains[target], "wrong prior domain at step " + str(number))
        support = enumerated_support(*(domains[position] for position in positions))
        _require(after == support[slot], "unsupported refinement at step " + str(number))
        _require(after != before, "certificate includes a non-refinement")
        domains[target] = after
        if not after:
            saw_empty = True
            _require(result.get("contradiction_draw") == target, "wrong contradiction draw")
    _require((status == "excluded") == saw_empty, "status and certificate disagree")
    _require(result.get("stream_length", len(domains)) == len(domains), "wrong stream length")
    fixed_point = False
    if status == "survives_necessary_screen" and check_fixed_point:
        for t in range(55, len(domains)):
            existing = (domains[t], domains[t - 55], domains[t - 34])
            _require(enumerated_support(*existing) == existing, "surviving trace is not a fixed point")
        fixed_point = True
        if "singleton_domains" in result:
            _require(result["singleton_domains"] == sum(domain.bit_count() == 1 for domain in domains),
                     "wrong singleton count")
    return dict(status=status, refinements_checked=len(trace), stream_length=len(domains),
                initial_observed_draws=initial_observations, fixed_point_checked=fixed_point)
