#!/usr/bin/env python3
"""Independent signed-Int32 constructor tracing, fixed fixtures, and observation mapping."""
import argparse
from collections import Counter
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import time

import affine_model as model

HERE = Path(__file__).resolve().parent
BYTE_ROOT = HERE.parent / "dotnet-random"
M = (1 << 31) - 1


def load_screen():
    spec = importlib.util.spec_from_file_location("audit_byte_screen", BYTE_ROOT / "screen.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def numeric_state(seed):
    """Literal signed-Int32 trace; branch flags come from actual overflows."""
    if type(seed) is not int or not -(1 << 31) <= seed <= M:
        raise ValueError("Need an Int32 seed")
    wrap = lambda value: ctypes.c_int32(value).value
    magnitude = M if seed == -(1 << 31) else abs(seed)
    state = [0] * 56
    state[55] = wrap(161803398 - magnitude)
    previous, current = state[55], 1
    for index in range(1, 55):
        position = (21 * index) % 55
        state[position] = current
        current = wrap(previous - current)
        if current < 0:
            current = wrap(current + M)
        previous = state[position]
    events = []
    for mixing in range(4):
        for index in range(1, 56):
            difference = state[index] - state[1 + (index + 30) % 55]
            if not -(1 << 31) <= difference <= M:
                events.append((mixing, index, "positive" if difference > M else "negative"))
            state[index] = wrap(difference)
            if state[index] < 0:
                state[index] = wrap(state[index] + M)
    return state[1:], events


def numeric_words(seed, length):
    state, events = numeric_state(seed)
    # Rotate the ring so its current output slot is always zero. The partner
    # is then slot21; this differs structurally from the production pointers.
    words = []
    for _ in range(length):
        value = ctypes.c_int32(state[0] - state[21]).value
        if value == M:
            value -= 1
        if value < 0:
            value = ctypes.c_int32(value + M).value
        words.append(value)
        state = state[1:] + [value]
    return words, events


def independent_observations(values, config):
    """Map scalar payloads using binary strings, independent of bit arithmetic."""
    if config["count"] != "fixed32":
        raise ValueError("Audit scope is fixed32")
    selected = {}
    for number, scalar in sorted(values.items()):
        if not 1 << (number - 1) <= scalar < 1 << number:
            raise ValueError("Invalid masked scalar")
        width = number - 1
        retained = format(scalar - (1 << width), f"0{width}b") if width else ""
        bits = (retained + "?" * (256 - width) if config["mask"] == "high"
                else "?" * (256 - width) + retained)
        byte_strings = [bits[start:start + 8] for start in range(0, 256, 8)]
        if config["order"] == "little":
            byte_strings.reverse()
        start = (number - 1) * (32 + config["skip"])
        for lane, observed in enumerate(byte_strings):
            mask = int("".join("0" if bit == "?" else "1" for bit in observed), 2)
            value = int(observed.replace("?", "0"), 2)
            if mask:
                selected[start + lane] = (mask, value)
    return max(values) * (32 + config["skip"]) - config["skip"], selected


def independent_generate(seed, indices, config):
    count = max(indices) * (32 + config["skip"])
    words, _ = numeric_words(seed, count)
    values = {}
    for number in sorted(indices):
        start = (number - 1) * (32 + config["skip"])
        source = bytes(word % 256 for word in words[start:start + 32])
        raw = int.from_bytes(source, config["order"])
        bits = format(raw, "0256b")
        width = number - 1
        retained = bits[:width] if config["mask"] == "high" else bits[256 - width:]
        values[number] = (1 << width) + (int(retained, 2) if width else 0)
    return values


def run():
    started = time.monotonic()
    length = 5392
    coefficients = {branch: model.output_coefficients(length, branch) for branch in range(4)}
    seeds = {0, 1, 2, 161803397, 161803398, 161803399, M - 2, M - 1, M}
    seeds.update(seed + delta for seed in model.EXCEPTIONAL_SEEDS for delta in (-2, -1, 0, 1, 2))
    seeds.update(int.from_bytes(hashlib.sha256(f"dotnet-seeded-affine-audit-{i}".encode()).digest(), "big") % (M + 1)
                 for i in range(128))
    branch_counts = Counter()
    checked_words = 0
    for seed in sorted(seeds):
        actual, overflows = numeric_words(seed, length)
        if seed in model.EXCEPTIONAL_SEEDS:
            if model.branch_for_seed(seed) is not None:
                raise AssertionError("Exception incorrectly classified as ordinary")
            continue
        if any((mixing, position) not in ((0, 24), (0, 55)) for mixing, position, _ in overflows):
            raise AssertionError("Unexpected overflow outside proved locations")
        traced_branch = int((0, 24, "positive") in overflows) | (int((0, 55, "negative") in overflows) << 1)
        if traced_branch != model.branch_for_seed(seed):
            raise AssertionError(("branch disagreement", seed))
        expected = [(a * seed + b) % M for a, b in coefficients[traced_branch]]
        if actual != expected:
            raise AssertionError(("affine stream disagreement", seed))
        branch_counts[traced_branch] += 1
        checked_words += length
    if set(branch_counts) != set(range(4)):
        raise AssertionError("Audit failed to cover all four branches")

    fixtures = json.loads((BYTE_ROOT / "fixtures/vectors.json").read_text())
    fixture_count = fixture_words = 0
    for fixture in fixtures:
        if fixture.get("seed") is None:
            continue
        words, _ = numeric_words(fixture["seed"], fixture["samples"])
        digest = hashlib.sha256(b"".join(struct.pack("<I", word) for word in words)).hexdigest()
        if digest != fixture["stream_le32_sha256"] or words[:64] != fixture["prefix64"]:
            raise AssertionError(("historical C# disagreement", fixture["label"]))
        if bytes(word % 256 for word in words[:256]).hex() != fixture["nextbytes256_hex"]:
            raise AssertionError("Historical byte fixture disagreement")
        fixture_count += 1
        fixture_words += len(words)
    exception_fixtures = json.loads((BYTE_ROOT / "fixtures/constructor_vectors.json").read_text())
    if {row["seed"] for row in exception_fixtures} != set(model.EXCEPTIONAL_SEEDS):
        raise AssertionError("Exceptional seed coverage mismatch")
    for fixture in exception_fixtures:
        state, _ = numeric_state(fixture["seed"])
        if state != fixture["state"] or not all(0 <= word < M for word in state):
            raise AssertionError("Exceptional historical state mismatch")

    previous = load_screen()
    indices = set(range(1, 71)) | set(range(75, 136, 5))
    mapping_cases = 0
    for config in previous.configs():
        if config["count"] != "fixed32":
            continue
        values = independent_generate(2000000000, indices, config)
        if independent_observations(values, config) != previous.observations(values, config):
            raise AssertionError(("observation disagreement", config["id"]))
        mapping_cases += 1
    return {
        "passed": True,
        "finite_sample_caveat": "Numeric comparisons validate the implementation; finite samples do not prove coverage.",
        "numeric_seed_magnitudes": len(seeds),
        "ordinary_branch_counts": dict(sorted(branch_counts.items())),
        "ordinary_affine_word_comparisons": checked_words,
        "historical_seeded_csharp_fixtures": fixture_count,
        "historical_seeded_csharp_words": fixture_words,
        "historical_exceptional_constructor_fixtures": len(exception_fixtures),
        "independent_observation_layout_checks": mapping_cases,
        "seconds": time.monotonic() - started,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        if args.output.exists():
            parser.error("refusing to overwrite an existing audit report")
        args.output.write_text(rendered)
    print(rendered, end="")
