"""Byte-domain constraints and masked observation mapping for subtractive streams."""
from collections import deque
import itertools
import time

FULL = (1 << 256) - 1


def configs():
    result = []
    for count, order, skip in itertools.product(("fixed32", "ceil_n", "ceil_n_minus_1"),
                                               ("little", "big"), (0, 1, 8)):
        for mask in (("low", "high") if count == "fixed32" else ("low",)):
            result.append(dict(id=f"{mask}/{count}/{order}/skip{skip}", count=count,
                               order=order, skip=skip, mask=mask))
    return result


def byte_count(n, config):
    return 32 if config["count"] == "fixed32" else (n + (7 if config["count"] == "ceil_n" else 6)) // 8


def observations(values, config):
    """Map each retained scalar bit back to one NextBytes output bit."""
    offset, selected = 0, {}
    for n in range(1, max(values) + 1):
        count = byte_count(n, config)
        if n in values:
            if not 1 << (n - 1) <= values[n] < 1 << n:
                raise ValueError("Scalar outside its masked range")
            for bit in range(n - 1):
                source = bit if config["mask"] == "low" else bit + 257 - n
                lane, within = divmod(source, 8)
                position = lane if config["order"] == "little" else count - 1 - lane
                if not 0 <= position < count:
                    raise ValueError("Observed bit outside allocated byte array")
                draw = offset + position
                old_mask, old_value = selected.get(draw, (0, 0))
                selected[draw] = (old_mask | (1 << within),
                                  old_value | (((values[n] >> bit) & 1) << within))
        offset += count + config["skip"]
    return offset - config["skip"], selected


def initial_domains(values, config):
    length, selected = observations(values, config)
    domains = [FULL] * length
    for draw, (mask, value) in selected.items():
        domains[draw] = sum(1 << byte for byte in range(256) if byte & mask == value)
    return domains


def members(domain):
    while domain:
        lowest = domain & -domain
        yield lowest.bit_length() - 1
        domain ^= lowest


def rotate(domain, amount):
    amount %= 256
    return ((domain << amount) | (domain >> (256 - amount))) & FULL


def combine(left, right, subtract=False):
    """Exact sum or difference set modulo 256, using circular bitsets."""
    if not left or not right:
        return 0
    if left == FULL or right == FULL:
        return FULL
    if subtract:
        right = sum(1 << ((-value) % 256) for value in members(right))
    if left.bit_count() > right.bit_count():
        left, right = right, left
    result = 0
    for value in members(left):
        result |= rotate(right, value)
        if result == FULL:
            break
    return result


def solve(values, config, max_visits=2000000):
    started = time.monotonic()
    domains = initial_domains(values, config)
    queue = deque(range(55, len(domains)))
    queued = set(queue)
    trace, visits = [], 0
    while queue:
        if visits >= max_visits:
            return dict(status="inconclusive_limit", visits=visits, trace=trace,
                        seconds=time.monotonic() - started)
        t = queue.popleft()
        queued.remove(t)
        visits += 1
        # x=a-b-c, a=x+b+c, b=a-x-c, all modulo 256; c in {0,1}.
        for variable, target, left, right, subtract, carry in (
                ("x", t, t - 55, t - 34, True, -1),
                ("a", t - 55, t, t - 34, False, 1),
                ("b", t - 34, t - 55, t, True, -1)):
            support = combine(domains[left], domains[right], subtract)
            support |= rotate(support, carry)
            before = domains[target]
            after = before & support
            if before == after:
                continue
            trace.append(dict(t=t, variable=variable, before=hex(before), after=hex(after)))
            domains[target] = after
            if not after:
                return dict(status="excluded", visits=visits, trace=trace,
                            seconds=time.monotonic() - started,
                            contradiction_draw=target, stream_length=len(domains))
            for affected in (target, target + 55, target + 34):
                if 55 <= affected < len(domains) and affected not in queued:
                    queue.append(affected)
                    queued.add(affected)
    return dict(status="survives_necessary_screen", visits=visits, trace=trace,
                seconds=time.monotonic() - started, stream_length=len(domains),
                singleton_domains=sum(d.bit_count() == 1 for d in domains))


def generate(generator, indices, config):
    result = {}
    for n in range(1, max(indices) + 1):
        raw = int.from_bytes(generator.next_bytes(byte_count(n, config)), config["order"])
        generator.next_bytes(config["skip"])
        if n in indices:
            retained = raw & ((1 << (n - 1)) - 1) if config["mask"] == "low" else raw >> (257 - n)
            result[n] = (1 << (n - 1)) | retained
    return result
