#!/usr/bin/env python3
"""Independent enumeration and curve checks for the chain-code recovery.

The oracle enumerates concrete toy chain codes and uses direct modular products;
it does not use the production quotient bounds, partial states, or generators.
"""

from collections import defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import unittest

import recover

HERE = Path(__file__).resolve().parent
AUDIT = {"transition_systems": 0, "transition_boxes": 0,
         "concrete_transition_evaluations": 0, "chain_systems": 0,
         "concrete_chain_codes": 0, "public_hash_checks": 0,
         "planted_prefix_checks": 0}
TEST_LIMITS = {"max_states": 1000000, "max_extensions": 20000000, "seconds": 30}


def direct_chain(code, last, order, hash_fn):
    key = 1
    sequence = {1: key}
    for target in range(2, last + 1):
        boundary = 2 ** (target - 1)
        key = boundary + ((key * (code ^ hash_fn(key)) % order) % boundary)
        sequence[target] = key
    return sequence


def toy_hash(width):
    mask = 2 ** width - 1
    def digest(key):
        data = b"independent-armory-audit" + width.to_bytes(1, "big") + key.to_bytes(2, "big")
        return int.from_bytes(hashlib.sha256(data).digest(), "little") & mask
    return digest


class RecoveryAudit(unittest.TestCase):
    def test_transition_images_against_all_concrete_completions(self):
        rng = random.Random(0xA12026)
        for width in range(3, 9):
            full = 2 ** width - 1
            hashes = (range(2 ** width) if width <= 4 else
                      sorted({0, full, int("10" * width, 2) & full,
                              *(rng.randrange(2 ** width) for _ in range(5))}))
            for order in sorted({full, full - 2, 2 ** (width - 1) + 1}):
                for depth in range(1, width):
                    # An independent bit-position definition covers overlapping ends.
                    positions = set(range(depth)) | set(range(width - depth, width))
                    mask = sum(2 ** position for position in positions)
                    self.assertEqual(mask, recover.edge_mask(depth, width))
                    maximum = min(2 ** depth - 1, order - 1)
                    keys = (range(1, maximum + 1) if width <= 5 else
                            sorted({1, maximum, max(1, maximum - 1),
                                    *(rng.randrange(1, maximum + 1) for _ in range(5))}))
                    for key in keys:
                        for hashed in hashes:
                            expected = defaultdict(set)
                            for code in range(2 ** width):
                                value = code & mask
                                result = 2 ** depth + ((key * (code ^ hashed) % order) % 2 ** depth)
                                expected[value]  # Retain boxes whose image has no valid scalar.
                                if result < order:
                                    expected[value].add(result)
                            for value, next_keys in expected.items():
                                actual, _ = recover.possible_nexts(key, hashed, value, depth, width, order)
                                self.assertEqual(actual, next_keys,
                                    (width, order, depth, key, hashed, value))
                            AUDIT["transition_systems"] += 1
                            AUDIT["transition_boxes"] += len(expected)
                            AUDIT["concrete_transition_evaluations"] += 2 ** width

    def test_complete_and_gapped_search_against_exhaustive_code_sets(self):
        rng = random.Random(20261026)
        for width in range(4, 10):
            order = 2 ** width - 3
            last = width - 1
            digest = toy_hash(width)
            oracle = {code: direct_chain(code, last, order, digest)
                      for code in range(2 ** width)}
            for planted in sorted({0, 2 ** width - 1, *(rng.randrange(2 ** width) for _ in range(8))}):
                full = oracle[planted]
                gapped = {i: key for i, key in full.items() if i == 1 or i % 2 == 1 or i == last}
                corrupt = {**full, min(3, last): full[min(3, last)] ^ 1}
                for scenario, observations in (("full", full), ("gapped", gapped), ("corrupt", corrupt)):
                    expected = {code for code, seq in oracle.items()
                                if all(seq[index] == key for index, key in observations.items())}
                    actual = recover.solve(observations, width=width, order=order,
                                           hash_fn=digest, limits=TEST_LIMITS)
                    self.assertEqual(actual["status"], "recovered" if expected else "excluded",
                                     (width, planted, scenario, actual))
                    returned = {int(code, 16) for code in actual.get("chain_codes", [])}
                    self.assertEqual(returned, expected, (width, planted, scenario))
                    AUDIT["chain_systems"] += 1
                    AUDIT["concrete_chain_codes"] += 2 ** width

    def test_full_width_public_hash_against_independent_curve(self):
        path = HERE.parent / "shared/curve.py"
        spec = importlib.util.spec_from_file_location("armory_audit_curve", path)
        curve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(curve)
        for key in (1, 2, 7, 8, 2 ** 69 + 12345, 2 ** 134 + 0x123456, recover.ORDER - 1):
            x, y = curve.point_multiply(key, curve.G)
            encodings = {
                "uncompressed": b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"),
                "compressed": bytes([2 + y % 2]) + x.to_bytes(32, "big"),
            }
            for mode, raw in encodings.items():
                expected = int.from_bytes(hashlib.sha256(hashlib.sha256(raw).digest()).digest(), "big")
                self.assertEqual(recover.public_hash(key, mode), expected)
                AUDIT["public_hash_checks"] += 1

    def test_true_full_width_state_survives_every_prefix(self):
        codes = [0, 2 ** 256 - 1,
                 int.from_bytes(hashlib.sha256(b"independent prefix fixture").digest(), "big")]
        for mode in recover.MODES:
            for code in codes:
                digest = lambda key: recover.public_hash(key, mode)
                full = direct_chain(code, 135, recover.ORDER, digest)
                for source in range(1, 135):
                    mask = sum(1 << bit for bit in
                               set(range(source)) | set(range(256 - source, 256)))
                    possible, _ = recover.possible_nexts(full[source], digest(full[source]),
                                                         code & mask, source)
                    self.assertIn(full[source + 1], possible)
                    AUDIT["planted_prefix_checks"] += 1

    def test_partial_result_retains_planted_box(self):
        width = 16
        order = 2 ** width - 15
        code = 0xA12E
        digest = toy_hash(width)
        observed = direct_chain(code, 5, order, digest)
        result = recover.solve(observed, width=width, order=order, hash_fn=digest, limits=TEST_LIMITS)
        self.assertEqual(result["status"], "partial")
        mask = sum(2 ** bit for bit in set(range(4)) | set(range(12, 16)))
        self.assertIn({"value_hex": hex(code & mask), "current_key_hex": hex(observed[5])}, result["boxes"])

    def test_budget_limits_are_inconclusive(self):
        digest = toy_hash(8)
        observations = direct_chain(61, 7, 253, digest)
        for override in ({"max_extensions": 0}, {"max_states": 0}, {"seconds": -1}):
            result = recover.solve(observations, width=8, order=253, hash_fn=digest,
                                   limits={**TEST_LIMITS, **override})
            self.assertEqual(result["status"], "inconclusive", override)

    def test_zero_intermediate_is_masked_before_next_public_key(self):
        # A zero multiplier is allowed by this custom mask-before-public-key model.
        code = recover.public_hash(1)
        self.assertEqual(recover.generate(code, 2), {1: 1, 2: 2})
        candidates, _ = recover.possible_nexts(1, code, code & recover.edge_mask(1, 256), 1)
        self.assertIn(2, candidates)

    def test_bad_inputs_reject(self):
        for observations in ({1: 2, 2: 3}, {1: 1}, {1: 1, 3: 2}):
            with self.assertRaises(AssertionError):
                recover.solve(observations)
        with self.assertRaises(AssertionError):
            recover.possible_nexts(1, 0, 2 ** 100, 1)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RecoveryAudit)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {**AUDIT, "tests_run": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors),
              "passed": result.wasSuccessful(),
              "oracle": "Direct enumeration of concrete toy codes and modular products; independent affine secp256k1 serialization for public hashes."}
    (HERE / "audit_results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
