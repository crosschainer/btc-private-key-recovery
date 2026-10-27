"""Constructor-constrained affine seed recovery with exact replay."""
from functools import lru_cache
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
BYTE_ROOT=HERE.parent/"dotnet-random"

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec)
    sys.modules[name]=result
    spec.loader.exec_module(result)
    return result
BYTE=module("seed_byte_screen",BYTE_ROOT/"screen.py")
REF=module("seed_numeric_reference",BYTE_ROOT/"reference.py")
MODEL=module("seed_affine_model",HERE/"affine_model.py")
IDS=("low/fixed32/little/skip8","high/fixed32/little/skip8","low/fixed32/big/skip8")

def record(path):
    path = Path(path).resolve()
    return {"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def configurations():
    indexed = {c["id"]: c for c in BYTE.configs()}
    return [indexed[name] for name in IDS]


def numeric_generate(seed, indices, config):
    return BYTE.generate(REF.LegacyRandom(seed), set(indices), config)


@lru_cache(maxsize=16)
def coefficients(length, branch):
    return MODEL.output_coefficients(length, branch)


def build_scanner(output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    binary = output_dir / "scanner"
    command = ["g++", "-O3", "-std=c++17", "-Wall", "-Wextra", "-pedantic",
               str(HERE / "scanner.cpp"), "-o", str(binary)]
    subprocess.run(command, check=True, capture_output=True, text=True)
    compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
    return binary, {"compiler": compiler, "flags": command[1:6],
                    "source": record(HERE / "scanner.cpp"),
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "threads": 1}


def validate_scan(scan):
    """Fail closed on incomplete, missing, or inconsistent coverage records."""
    branches = scan["branches"]
    if [row["branch_id"] for row in branches] != [0, 1, 2, 3]:
        raise ValueError("Missing, duplicate, or reordered affine branches")
    if scan["modulus"] != REF.MODULUS:
        raise ValueError("Unexpected scanner modulus")
    if scan["complete"] != all(row["complete"] for row in branches):
        raise ValueError("Inconsistent overall scan completion")
    union = sorted({seed for row in branches for seed in row["candidate_seeds"]})
    if union != scan["candidate_seeds"] or any(type(s) is not int or not 0 <= s <= REF.MODULUS for s in union):
        raise ValueError("Inconsistent scanner candidate union")
    if scan["tested_anchor_values"] != sum(row["tested_anchor_values"] for row in branches):
        raise ValueError("Inconsistent total anchor coverage")
    for row in branches:
        if row["anchor_values"] not in (8388607, 8388608):
            raise ValueError("Unexpected full-byte anchor domain size")
        if row["candidate_seeds"] != sorted(set(row["candidate_seeds"])):
            raise ValueError("Duplicate or unordered candidate magnitudes")
        if row["complete"]:
            if row["status"] != "complete":
                raise ValueError("Completed branch has invalid status")
            if row["reason"] == "constant_observation_contradiction":
                if row["tested_anchor_values"] or row["candidate_seeds"]:
                    raise ValueError("Inconsistent constant contradiction")
            elif row["reason"] or row["tested_anchor_values"] != row["anchor_values"]:
                raise ValueError("Incomplete anchor enumeration")
        elif row["status"] != "candidate_limit":
            raise ValueError("Unknown incomplete scan status")


def recover(values, config, binary, timeout_seconds=60):
    """Recover all seed magnitudes fitting values; no planted seed is accepted."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    started = time.monotonic()
    length, observations = BYTE.observations(values, config)
    lines = ["4"]
    for branch in range(4):
        stream = coefficients(length, branch)
        lines.append(f"{branch} {len(observations)}")
        for draw, (mask, value) in sorted(observations.items()):
            a, b = stream[draw]
            lines.append(f"{draw} {a} {b} {mask} {value}")
    build_seconds = time.monotonic() - started
    scan_started = time.monotonic()
    try:
        process = subprocess.run([str(binary)], input="\n".join(lines) + "\n",
                                 text=True, capture_output=True, check=True,
                                 timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"status": "inconclusive_timeout", "complete": False,
                "timeout_seconds": timeout_seconds, "build_seconds": build_seconds,
                "seconds": time.monotonic() - started, "candidate_seed_magnitudes": []}
    scan_seconds = time.monotonic() - scan_started
    scan = json.loads(process.stdout)
    validate_scan(scan)
    candidates = sorted(set(scan["candidate_seeds"]) | set(MODEL.EXCEPTIONAL_SEEDS))
    matches = [seed for seed in candidates if numeric_generate(seed, values, config) == values]
    complete = scan["complete"]
    return {"status": ("recovered" if matches else "excluded") if complete else "inconclusive_limit",
            "complete": complete, "candidate_seed_magnitudes": matches,
            "exact_replay_candidates": len(candidates),
            "exceptional_magnitudes_checked": sorted(MODEL.EXCEPTIONAL_SEEDS),
            "build_seconds": build_seconds, "scan_seconds": scan_seconds,
            "seconds": time.monotonic() - started, "timeout_seconds": timeout_seconds,
            "observed_bits": sum(mask.bit_count() for mask, _ in observations.values()),
            "observed_bytes": len(observations), "stream_words": length,
            "scanner": scan}
