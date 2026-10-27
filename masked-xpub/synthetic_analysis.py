#!/usr/bin/env python3
"""Synthetic masked-BIP32 constraint analysis and bounded recovery examples.

Generates deterministic test wallets, counts compatible scalar candidates, and
checks a deliberately small reduced discrete-log interval. Uses no external targets."""

import argparse
from dataclasses import dataclass, replace
import hashlib
import hmac
import importlib.util
import json
import math
from pathlib import Path
import random
import re
import statistics

from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
CURVE_FILE = ROOT / "shared/curve.py"
VECTOR_FILE = ROOT / "shared/bip32_tests.cpp"
spec = importlib.util.spec_from_file_location("independent_curve", CURVE_FILE)
curve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(curve)
N, G = curve.N, curve.G
HARDENED = 1 << 31
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RETAINED_WIDTHS = [0, 8, 16, 32, 48, 64, 96, 128, 160, 192, 224, 240]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha256(data):
    return hashlib.sha256(data).digest()


def point(scalar):
    scalar %= N
    if scalar == 0:
        return None
    numbers = ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_numbers()
    return numbers.x, numbers.y


def ser_point(public):
    require(public is not None, "Cannot serialize infinity")
    return bytes([2 + (public[1] & 1)]) + public[0].to_bytes(32, "big")


def neg(public):
    return None if public is None else (public[0], -public[1] % curve.P)


def base58check(payload):
    raw = payload + sha256(sha256(payload))[:4]
    value = int.from_bytes(raw, "big")
    result = ""
    while value:
        value, digit = divmod(value, 58)
        result = ALPHABET[digit] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


@dataclass(frozen=True)
class PublicNode:
    public: tuple
    chain: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\0" * 4
    index: int = 0

    def serialize(self):
        return base58check(bytes.fromhex("0488b21e") + self.metadata() + ser_point(self.public))

    def metadata(self):
        return (bytes([self.depth]) + self.parent_fingerprint +
                self.index.to_bytes(4, "big") + self.chain)

    def child(self, index):
        if not 0 <= index < HARDENED:
            raise ValueError("A public derivation cannot cross a hardened edge")
        digest = hmac.new(self.chain, ser_point(self.public) + index.to_bytes(4, "big"),
                          hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        if tweak >= N:
            raise ValueError("Invalid BIP32 child; declared mapping must record retry")
        child_public = curve.point_add(self.public, point(tweak))
        if child_public is None:
            raise ValueError("Invalid BIP32 infinity child; declared mapping must record retry")
        return PublicNode(child_public, digest[32:], self.depth + 1,
                          curve.hash160(ser_point(self.public))[:4], index), tweak

    def path(self, indices):
        current, total = self, 0
        for index in indices:
            current, tweak = current.child(index)
            total = (total + tweak) % N
        return current, total


@dataclass(frozen=True)
class PrivateNode:
    secret: int
    chain: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\0" * 4
    index: int = 0

    def neuter(self):
        return PublicNode(point(self.secret), self.chain, self.depth,
                          self.parent_fingerprint, self.index)

    def serialize(self):
        return base58check(bytes.fromhex("0488ade4") + self.neuter().metadata() +
                           b"\0" + self.secret.to_bytes(32, "big"))

    def child(self, index):
        require(0 <= index < (1 << 32), "Invalid BIP32 index")
        public = point(self.secret)
        data = (b"\0" + self.secret.to_bytes(32, "big") if index >= HARDENED
                else ser_point(public)) + index.to_bytes(4, "big")
        digest = hmac.new(self.chain, data, hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        secret = (self.secret + tweak) % N
        if tweak >= N or secret == 0:
            raise ValueError("Invalid BIP32 child; declared mapping must record retry")
        return PrivateNode(secret, digest[32:], self.depth + 1,
                           curve.hash160(ser_point(public))[:4], index)

    def path(self, indices):
        current = self
        for index in indices:
            current = current.child(index)
        return current


def master(seed):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    secret = int.from_bytes(digest[:32], "big")
    require(0 < secret < N, "Invalid synthetic BIP32 master")
    return PrivateNode(secret, digest[32:])


@dataclass(frozen=True)
class Observation:
    index: int
    bits: int
    residue: int
    tweak: int

    @property
    def masked(self):
        return (1 << self.bits) + self.residue


@dataclass(frozen=True)
class Candidates:
    residue: int
    modulus: int
    q_min: int
    q_max: int

    @property
    def count(self):
        return self.q_max - self.q_min + 1

    def contains(self, secret):
        delta = secret - self.residue
        return delta % self.modulus == 0 and self.q_min <= delta // self.modulus <= self.q_max


def ceil_div(numerator, denominator):
    return -((-numerator) // denominator)


def bounded_progression(residue, modulus, low, high):
    q_min = ceil_div(low - residue, modulus)
    q_max = (high - residue) // modulus
    return Candidates(residue, modulus, q_min, q_max) if q_min <= q_max else None


def solve_constraints(order, observations):
    """Return exact finite arithmetic progressions, without receiving a secret.

    The largest retained width fixes x modulo 2**B for either reference wrap.
    Since order is odd, parity then fixes every other positive-width wrap.
    Higher bits test compatibility; inequalities bound the candidate interval.
    Width-zero masks carry no residue information, but still exclude u=0.
    """
    require(order > 2 and order & 1, "This solver requires an odd group order")
    for obs in observations:
        require(obs.bits >= 0 and 0 <= obs.residue < 1 << obs.bits, "Bad masked residue")
        require(0 <= obs.tweak < order, "Tweak must already be reduced modulo order")
    positive = [obs for obs in observations if obs.bits]
    if not positive:
        branches = [Candidates(0, 1, 1, order - 1)]
    else:
        reference = max(positive, key=lambda obs: obs.bits)
        modulus = 1 << reference.bits
        branches = []
        for reference_wrap in (0, 1):
            residue = (reference.residue - reference.tweak + reference_wrap * order) % modulus
            low, high = 1, order - 1
            for obs in positive:
                wrap = (residue - obs.residue + obs.tweak) & 1
                if residue % (1 << obs.bits) != (obs.residue - obs.tweak + wrap * order) % (1 << obs.bits):
                    break
                # Equality x+t=order is invalid because the child scalar is zero.
                if wrap:
                    low = max(low, order - obs.tweak + 1)
                else:
                    high = min(high, order - obs.tweak - 1)
            else:
                branch = bounded_progression(residue, modulus, low, high)
                if branch is not None:
                    branches.append(branch)
    # A b=0 mask always equals 1, regardless of valid u. Exclude only u=0.
    for forbidden in sorted({order - obs.tweak for obs in observations if not obs.bits}):
        split = []
        for branch in branches:
            if not branch.contains(forbidden):
                split.append(branch)
                continue
            q = (forbidden - branch.residue) // branch.modulus
            if branch.q_min < q:
                split.append(replace(branch, q_max=q - 1))
            if q < branch.q_max:
                split.append(replace(branch, q_min=q + 1))
        branches = split
    return sorted(branches, key=lambda branch: (branch.residue + branch.modulus * branch.q_min))


def solve_in_anchor_coordinate(order, observations):
    """Independent formulation in y=(x+t_anchor) mod order, not parent x.

    The anchor has y mod 2**B fixed. Relative tweaks determine all positive-
    width wraps by parity, leaving one interval before invalid-zero exclusions.
    """
    anchor = max(observations, key=lambda obs: obs.bits)
    require(anchor.bits > 0, "Anchor check requires a positive retained width")
    low, high = 1, order - 1
    # y=t_anchor would give the excluded parent x=0.
    forbidden = {anchor.tweak}
    for obs in observations:
        delta = (obs.tweak - anchor.tweak) % order
        forbidden.add(order - delta)
        if obs.bits == 0:
            continue
        wrap = (anchor.residue + delta - obs.residue) & 1
        if (anchor.residue + delta - wrap * order) % (1 << obs.bits) != obs.residue:
            return []
        if wrap:
            low = max(low, order - delta + 1)
        else:
            high = min(high, order - delta - 1)
    initial = bounded_progression(anchor.residue, 1 << anchor.bits, low, high)
    branches = [] if initial is None else [initial]
    for excluded in sorted(forbidden):
        updated = []
        for branch in branches:
            if not branch.contains(excluded):
                updated.append(branch)
                continue
            q = (excluded - branch.residue) // branch.modulus
            if branch.q_min < q:
                updated.append(replace(branch, q_max=q - 1))
            if q < branch.q_max:
                updated.append(replace(branch, q_min=q + 1))
        branches = updated
    return branches


def describe(branches):
    count = sum(branch.count for branch in branches)
    return {
        "candidate_count": count,
        "candidate_count_bit_length": count.bit_length(),
        "log2_candidate_count": math.log2(count) if count else None,
        "sqrt_work_log2": math.log2(count) / 2 if count else None,
        "branch_count": len(branches),
        "branches": [{"residue": branch.residue, "modulus": branch.modulus,
                      "q_min": branch.q_min, "q_max": branch.q_max,
                      "candidate_count": branch.count,
                      "first_candidate": branch.residue + branch.modulus * branch.q_min,
                      "last_candidate": branch.residue + branch.modulus * branch.q_max}
                     for branch in branches],
    }


def test_bip32_vector():
    source = VECTOR_FILE.read_text()
    vector = source.split("TestVector test1 =", 1)[1].split("TestVector test2 =", 1)[0]
    pairs = re.findall(r'\("(xpub[^"\s]+)",\s*"(xprv[^"\s]+)"', vector)
    require(len(pairs) == 6, "Could not identify all BIP32 vector-1 nodes")
    indices = [HARDENED, 1, HARDENED + 2, 2, 1000000000]
    private = master(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    public_equivalence = 0
    for depth, (expected_public, expected_private) in enumerate(pairs):
        require(private.serialize() == expected_private, "BIP32 private test-vector mismatch")
        require(private.neuter().serialize() == expected_public, "BIP32 public test-vector mismatch")
        if depth < len(indices):
            index = indices[depth]
            child = private.child(index)
            if index < HARDENED:
                public_child, tweak = private.neuter().child(index)
                require(public_child == child.neuter(), "CKDpub != neutered CKDpriv")
                require(child.secret == (private.secret + tweak) % N, "Wrong public tweak")
                public_equivalence += 1
            private = child
    return {"source": str(VECTOR_FILE.relative_to(ROOT)),
            "source_sha256": hashlib.sha256(VECTOR_FILE.read_bytes()).hexdigest(),
            "vector": 1, "extended_private_keys_matched": 6,
            "extended_public_keys_matched": 6,
            "nonhardened_public_private_equivalence_checks": public_equivalence}


def test_toy_orders():
    cases = 0
    direct_candidate_checks = 0
    zero_boundaries = 0
    # Exhaust every scalar/tweak/residue for each single-observation toy model.
    for order in (3, 5, 7, 9, 13, 17, 31):
        for bits in range(order.bit_length() + 1):
            for tweak in range(order):
                for residue in range(1 << bits):
                    obs = Observation(0, bits, residue, tweak)
                    branches = solve_constraints(order, [obs])
                    expected = {x for x in range(1, order)
                                if (x + tweak) % order and ((x + tweak) % order) % (1 << bits) == residue}
                    actual = {branch.residue + branch.modulus * q for branch in branches
                              for q in range(branch.q_min, branch.q_max + 1)}
                    require(actual == expected, "Exhaustive single-observation mismatch")
                    if 0 < order - tweak < order:
                        require(order - tweak not in actual, "Accepted invalid zero child")
                        zero_boundaries += 1
                    cases += 1
                    direct_candidate_checks += order - 1
    # Exhaust pairs (tweak,width) for every valid known parent over odd order 9.
    order = 9
    specifications = [(tweak, bits) for tweak in range(order) for bits in range(4)]
    for secret in range(1, order):
        for left in specifications:
            for right in specifications:
                if any((secret + tweak) % order == 0 for tweak, _ in (left, right)):
                    continue
                observations = [Observation(index, bits, ((secret + tweak) % order) % (1 << bits), tweak)
                                for index, (tweak, bits) in enumerate((left, right))]
                branches = solve_constraints(order, observations)
                expected = {x for x in range(1, order)
                            if all((x + obs.tweak) % order and
                                   ((x + obs.tweak) % order) % (1 << obs.bits) == obs.residue
                                   for obs in observations)}
                actual = {branch.residue + branch.modulus * q for branch in branches
                          for q in range(branch.q_min, branch.q_max + 1)}
                require(actual == expected and secret in actual, "Exhaustive paired-observation mismatch")
                if any(obs.bits for obs in observations):
                    anchor = max(observations, key=lambda obs: obs.bits)
                    anchored = solve_in_anchor_coordinate(order, observations)
                    mapped_back = {(branch.residue + branch.modulus * q - anchor.tweak) % order
                                   for branch in anchored for q in range(branch.q_min, branch.q_max + 1)}
                    require(mapped_back == expected, "Anchor coordinate exact set mismatch")
                cases += 1
                direct_candidate_checks += order - 1
    rng = random.Random(0xB1F32)
    for _ in range(1000):
        order = rng.choice((33, 63, 101, 127, 257))
        observations = [Observation(i, bits, rng.randrange(1 << bits), rng.randrange(order))
                        for i, bits in enumerate(rng.randrange(10) for _ in range(rng.randrange(1, 10)))]
        branches = solve_constraints(order, observations)
        for x in range(1, order):
            expected = all((x + obs.tweak) % order and
                           ((x + obs.tweak) % order) % (1 << obs.bits) == obs.residue
                           for obs in observations)
            require(any(branch.contains(x) for branch in branches) == bool(expected),
                    "Random inconsistent/nested multi-observation mismatch")
            direct_candidate_checks += 1
        cases += 1
    return {"constraint_systems_checked": cases,
            "direct_scalar_candidate_checks": direct_candidate_checks,
            "explicit_invalid_zero_boundary_checks": zero_boundaries,
            "includes_odd_composite_orders": True,
            "includes_widths_larger_than_order_bit_length": True,
            "includes_inconsistent_observations": True,
            "positive_width_paired_cases_also_checked_in_anchor_coordinate": True,
            "all_exact_sets_match_direct_enumeration": True}


def observations_for(private, widths):
    public = private.neuter()
    observations = []
    wrap_counts = [0, 0]
    for bits in widths:
        # Explicit known synthetic mapping: observation N=bits+1 -> child index=bits.
        public_child, tweak = public.child(bits)
        reference_child = private.child(bits)
        require(public_child == reference_child.neuter(), "Synthetic public/private derivations differ")
        require(reference_child.secret == (private.secret + tweak) % N, "Incorrect child scalar")
        wrap_counts[int(private.secret + tweak >= N)] += 1
        observations.append(Observation(bits, bits, reference_child.secret % (1 << bits), tweak))
    return observations, wrap_counts


def test_hardened_boundaries():
    private = master(sha256(b"masked-xpub hardened-boundary fixture"))
    rejected = 0
    for path in ([HARDENED], [7, HARDENED + 3], [1, 2, HARDENED + 4, 5]):
        try:
            private.neuter().path(path)
        except ValueError as error:
            require("hardened" in str(error), "Wrong rejection reason")
            rejected += 1
        else:
            raise AssertionError("Public derivation crossed a hardened edge")
    anchor = private.path([HARDENED + 3, HARDENED + 7])
    suffix = [4, 8, 15]
    child_public, effective_tweak = anchor.neuter().path(suffix)
    child_private = anchor.path(suffix)
    require(child_public == child_private.neuter(), "Below-hardened-anchor mismatch")
    require(child_private.secret == (anchor.secret + effective_tweak) % N,
            "Effective nonhardened path tweak mismatch")
    observations = []
    for bits, path in ((69, [4, 8]), (134, suffix), (124, [9, 2, 6])):
        derived, tweak = anchor.neuter().path(path)
        child = anchor.path(path)
        require(derived == child.neuter(), "Mixed-depth descendant mismatch")
        observations.append(Observation(path[-1], bits, child.secret % (1 << bits), tweak))
    branches = solve_constraints(N, observations)
    require(any(branch.contains(anchor.secret) for branch in branches), "Lost hardened-subtree anchor")
    return {"public_paths_crossing_hardened_edge_rejected": rejected,
            "xpub_below_two_hardened_ancestors_works": True,
            "nonhardened_suffix": suffix,
            "mixed_depth_descendant_constraints_contain_anchor": True,
            "effective_tweaks_reduced_modulo_order": True}


def test_full_width_wallets(wallet_count):
    records = []
    wrong_index_rejected = wrong_mask_rejected = 0
    wrap_totals = [0, 0]
    for ordinal in range(wallet_count):
        seed = sha256(b"masked-xpub full-width synthetic wallet v1:" + ordinal.to_bytes(4, "big"))
        private = master(seed)
        observations, wraps = observations_for(private, RETAINED_WIDTHS)
        wrap_totals = [left + right for left, right in zip(wrap_totals, wraps)]
        full = solve_constraints(N, observations)
        anchored = solve_in_anchor_coordinate(N, observations)
        strongest = solve_constraints(N, [max(observations, key=lambda obs: obs.bits)])
        lower_only = solve_constraints(N, [obs for obs in observations if obs.bits <= 64])
        require(any(branch.contains(private.secret) for branch in full), "Known synthetic parent lost")
        anchor = max(observations, key=lambda obs: obs.bits)
        require(any(branch.contains((private.secret + anchor.tweak) % N) for branch in anchored),
                "Known synthetic source scalar lost in anchor coordinate")
        require(sum(branch.count for branch in full) == sum(branch.count for branch in anchored),
                "Parent and anchor formulations disagree on exact candidate count")
        require(len(full) <= 2, "Unexpected positive-width wrap patterns")
        require(sum(branch.count for branch in full) <= sum(branch.count for branch in strongest),
                "Additional observations enlarged candidate set")
        public = private.neuter()
        wrong_index = [replace(obs, tweak=public.child(obs.index + 1)[1]) for obs in observations]
        wrong_mask = [replace(obs, bits=obs.bits + 1, residue=obs.masked) for obs in observations]
        wrong_index_branches = solve_constraints(N, wrong_index)
        wrong_mask_branches = solve_constraints(N, wrong_mask)
        require(not any(branch.contains(private.secret) for branch in wrong_index_branches),
                "Wrong index unexpectedly retains known parent")
        require(not any(branch.contains(private.secret) for branch in wrong_mask_branches),
                "Wrong forced-bit interpretation unexpectedly retains known parent")
        wrong_index_rejected += int(not wrong_index_branches)
        wrong_mask_rejected += int(not wrong_mask_branches)
        record = {"ordinal": ordinal, "synthetic_seed_hex": seed.hex(),
                  "synthetic_parent_xpub": public.serialize(),
                  "known_parent_contained": True, "child_wrap_counts": wraps,
                  "all_observations": describe(full), "strongest_only": describe(strongest),
                  "anchor_coordinate_all_observations": describe(anchored),
                  "through_64_bits": describe(lower_only),
                  "wrong_index_candidate_count": sum(branch.count for branch in wrong_index_branches),
                  "wrong_forced_bit_candidate_count": sum(branch.count for branch in wrong_mask_branches)}
        records.append(record)
    logs = [record["all_observations"]["log2_candidate_count"] for record in records]
    reductions = [record["strongest_only"]["candidate_count"] /
                  record["all_observations"]["candidate_count"] for record in records]
    return {"wallet_count": wallet_count,
            "observations_per_wallet": len(RETAINED_WIDTHS),
            "positive_width_observations_per_wallet": sum(bool(bits) for bits in RETAINED_WIDTHS),
            "retained_widths": RETAINED_WIDTHS,
            "synthetic_index_mapping": "observation N=b+1 uses direct nonhardened child index b",
            "scope": "Disclosed masked scalars and a synthetic parent xpub; exact algebraic counts without a full-width search",
            "summary": {
                "all_known_parents_retained": True,
                "independent_anchor_coordinate_counts_agree": True,
                "total_nonwrap_children": wrap_totals[0], "total_wrap_children": wrap_totals[1],
                "min_log2_candidates": min(logs), "median_log2_candidates": statistics.median(logs),
                "max_log2_candidates": max(logs),
                "mean_candidate_count": sum(record["all_observations"]["candidate_count"]
                                            for record in records) // wallet_count,
                "min_candidate_count": min(record["all_observations"]["candidate_count"] for record in records),
                "max_candidate_count": max(record["all_observations"]["candidate_count"] for record in records),
                "min_sqrt_work_log2": min(logs) / 2,
                "median_sqrt_work_log2": statistics.median(logs) / 2,
                "max_sqrt_work_log2": max(logs) / 2,
                "min_count_reduction_vs_strongest": min(reductions),
                "median_count_reduction_vs_strongest": statistics.median(reductions),
                "max_count_reduction_vs_strongest": max(reductions),
                "positive_width_wrap_pattern_counts": sorted(set(record["all_observations"]["branch_count"]
                                                                for record in records)),
                "wrong_index_systems_with_no_candidates": wrong_index_rejected,
                "wrong_forced_bit_systems_with_no_candidates": wrong_mask_rejected,
            }, "wallets": records}


def bounded_bsgs(base, target, count):
    """Solve target=j*base for 0<=j<count only in the tiny synthetic fixture."""
    require(0 < count <= (1 << 17), "Deliberate bound: no large discrete-log search")
    width = math.isqrt(count - 1) + 1
    table = {}
    current = None
    for j in range(width):
        table[current] = j
        current = curve.point_add(current, base)
    step = neg(curve.point_multiply(width, base))
    current = target
    giant_steps = 0
    for i in range(ceil_div(count, width)):
        giant_steps += 1
        if current in table:
            answer = i * width + table[current]
            if answer < count:
                return answer, {"baby_steps": width, "giant_steps_examined": giant_steps,
                                "table_entries": len(table)}
        current = curve.point_add(current, step)
    return None, {"baby_steps": width, "giant_steps_examined": giant_steps,
                  "table_entries": len(table)}


def test_reduced_interval_dlp():
    private = master(sha256(b"masked-xpub tiny DLP demonstration v1"))
    observations, _ = observations_for(private, [240])
    branches = solve_constraints(N, observations)
    records = []
    found = []
    # This search receives only public K, publicly derived offsets and masks.
    public = private.neuter().public
    for branch in branches:
        first = branch.residue + branch.modulus * branch.q_min
        base = point(branch.modulus)
        target = curve.point_add(public, neg(point(first)))
        answer, stats = bounded_bsgs(base, target, branch.count)
        if answer is not None:
            candidate = first + branch.modulus * answer
            require(point(candidate) == public, "BSGS answer failed public-point verification")
            found.append(candidate)
        records.append({"candidate_count": branch.count, "found": answer is not None, **stats})
    require(found == [private.secret], "Tiny synthetic interval DLP did not recover known fixture")
    return {"scope": "Synthetic-only feasibility check with artificially strong 240-bit disclosure",
            "retained_bits": 240, "forced_mask_bit_does_not_count": True,
            "candidate_geometry": describe(branches), "branch_searches": records,
            "known_synthetic_parent_recovered": True,
            "actual_parameter_recovery_attempted": False,
            "does_not_establish_actual_parameter_feasibility": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet-count", type=int, default=64)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("synthetic_results.json"))
    args = parser.parse_args()
    require(1 <= args.wallet_count <= 256, "Bounded experiment requires 1..256 wallets")
    result = {"format_version": 1,
              "mask": "d_N = 2^(N-1) + (u mod 2^(N-1)); retained bits b=N-1",
              "curve_order": N, "curve_order_bit_length": N.bit_length(),
              "two_to_256_minus_order": (1 << 256) - N,
              "two_to_256_minus_order_bit_length": ((1 << 256) - N).bit_length(),
              "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "curve_helper_sha256": hashlib.sha256(CURVE_FILE.read_bytes()).hexdigest(),
              "bip32_known_vector": test_bip32_vector(),
              "toy_exhaustive": test_toy_orders(),
              "hardened_boundaries": test_hardened_boundaries(),
              "synthetic_wallets": test_full_width_wallets(args.wallet_count),
              "reduced_interval_dlp": test_reduced_interval_dlp()}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "tests_passed": True,
                      "toy_exhaustive": result["toy_exhaustive"],
                      "synthetic_summary": result["synthetic_wallets"]["summary"],
                      "reduced_dlp_candidates": result["reduced_interval_dlp"]["candidate_geometry"]["candidate_count"]},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
