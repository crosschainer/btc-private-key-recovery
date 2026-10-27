"""Exact normalized 31-bit state recovery with independent numeric replay."""
import time
import z3
import screen as experiment
from reference import LegacyRandom, MODULUS

def replay(first55, values, config):
    """Replay independently through the historical reference ring implementation."""
    length, _ = experiment.observations(values, config)
    generator = LegacyRandom.from_state(first55, inext=55)
    stream = list(first55)
    stream += [generator.next() for _ in range(max(0, length - 55))]
    offset, predictions = 0, {}
    for n in range(1, max(values) + 1):
        count = (32 if config["count"] == "fixed32" else
                 (n + (7 if config["count"] == "ceil_n" else 6)) // 8)
        raw = int.from_bytes(bytes(x & 255 for x in stream[offset:offset + count]), config["order"])
        offset += count + config["skip"]
        if n in values:
            low = raw & ((1 << (n - 1)) - 1) if config["mask"] == "low" else raw >> (257 - n)
            predictions[n] = (1 << (n - 1)) | low
    return predictions


def solve(values, config, timeout_ms=30000, fixed_first55=None):
    build_started = time.monotonic()
    length, observations = experiment.observations(values, config)
    length = max(55, length)
    words = [z3.BitVec(f"word_{i}", 31) for i in range(length)]
    solver = z3.SolverFor("QF_BV")
    solver.set(timeout=timeout_ms, random_seed=0)
    for word in words:
        solver.add(word != MODULUS)
    for t in range(55, length):
        a, b = words[t - 55], words[t - 34]
        # With width31 arithmetic, adding M=2^31-1 for a negative difference
        # is exactly subtracting 1 from the wrapped difference.
        solver.add(words[t] == a - b - z3.If(z3.ULT(a, b), z3.BitVecVal(1, 31), z3.BitVecVal(0, 31)))
    for t, (mask, value) in observations.items():
        solver.add((words[t] & mask) == value)
    if fixed_first55 is not None:
        if len(fixed_first55) != 55 or any(not 0 <= value < MODULUS for value in fixed_first55):
            raise ValueError("Need exactly55 normalized first output words")
        for word, value in zip(words, fixed_first55):
            solver.add(word == value)
    build_seconds = time.monotonic() - build_started
    started = time.monotonic()
    outcome = solver.check()
    result = dict(solver_result=str(outcome), timeout_ms=timeout_ms, build_seconds=build_seconds,
                  solve_seconds=time.monotonic() - started, stream_words=length,
                  observed_bytes=len(observations), observed_bits=sum(mask.bit_count() for mask, _ in observations.values()),
                  fixed_first55=fixed_first55 is not None)
    if outcome == z3.unsat:
        result["status"] = "excluded"
    elif outcome == z3.unknown:
        result["status"] = "inconclusive_timeout" if "timeout" in solver.reason_unknown() else "inconclusive_unknown"
        result["reason_unknown"] = solver.reason_unknown()
    else:
        first55 = [solver.model().eval(word, model_completion=True).as_long() for word in words[:55]]
        predictions = replay(first55, values, config)
        if predictions != values:
            raise AssertionError("SAT state failed independent numeric replay")
        result.update(status="sat_exact_replay", first55_outputs=first55,
                      replayed_observations=len(values), replay_matches=True)
    return result
