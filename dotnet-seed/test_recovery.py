"""Independent controls for complete affine seed enumeration and replay."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import audit
import recovery as e


class SeedRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="dotnet-seed-tests-")
        cls.directory = Path(cls.temporary.name)
        cls.binary, _ = e.build_scanner(cls.directory)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scan(self, rows, *arguments):
        text = "1\n0 " + str(len(rows)) + "\n"
        text += "".join(" ".join(map(str, row)) + "\n" for row in rows)
        return json.loads(subprocess.check_output([str(self.binary), *arguments], input=text, text=True))

    def test_independent_constructor_historical_fixtures_and_mapping(self):
        checked = audit.run()
        self.assertTrue(checked["passed"])
        self.assertEqual(checked["historical_seeded_csharp_fixtures"], 10)
        self.assertEqual(checked["historical_exceptional_constructor_fixtures"], 4)
        self.assertEqual(set(checked["ordinary_branch_counts"]), set(range(4)))

    def test_anchor_inversion_exhaustive_small_prime(self):
        # Exhaustive analogue includes both magnitude endpoints, unlike a
        # residue-only set. This checks the inversion's complete-coverage claim.
        modulus, radix = 31, 4
        for a in range(1, modulus):
            for b in range(modulus):
                for value in range(radix):
                    candidates = {(pow(a, -1, modulus) * (word - b)) % modulus
                                  for word in range(value, modulus, radix)}
                    if 0 in candidates:
                        candidates.add(modulus)
                    expected = {seed for seed in range(modulus + 1)
                                if ((a * seed + b) % modulus) % radix == value}
                    self.assertEqual(candidates, expected)

    def test_native_full_domain_scan_preserves_both_zero_residue_endpoints(self):
        modulus = e.REF.MODULUS
        # These observations successively require divisibility by 256,
        # 256^2, 256^3, then 256^4. Only residue zero remains below M.
        rows = [(j, pow(pow(256, j, modulus), -1, modulus), 0, 255, 0)
                for j in range(4)]
        result = self.scan(rows)
        self.assertTrue(result["complete"])
        self.assertEqual(result["candidate_seeds"], [0, modulus])
        self.assertEqual(result["tested_anchor_values"], 1 << 23)
        self.assertEqual(result["branches"][0]["tested_anchor_values"],
                         result["branches"][0]["anchor_values"])

    def test_native_candidate_limit_remains_incomplete(self):
        result = self.scan([(0, 1, 0, 255, 0)], "--max-candidates", "1")
        self.assertFalse(result["complete"])
        self.assertEqual(result["status"], "candidate_limit")
        self.assertLess(result["branches"][0]["tested_anchor_values"],
                        result["branches"][0]["anchor_values"])

    def test_native_rejects_missing_invertible_anchor(self):
        process = subprocess.run([str(self.binary)], input="1\n0 1\n0 0 0 255 0\n",
                                 text=True, capture_output=True)
        self.assertEqual(process.returncode, 2)
        self.assertIn("No invertible full-byte anchor", process.stderr)
        self.assertEqual(process.stdout, "")

    def test_recovery_from_independently_generated_ordinary_and_exceptional_data(self):
        indices = set(range(1, 71)) | set(range(75, 136, 5))
        for config in e.configurations():
            for seed in (2000000000, e.MODEL.EXCEPTIONAL_SEEDS[0]):
                with self.subTest(config=config["id"], seed=seed):
                    values = audit.independent_generate(seed, indices, config)
                    fit = {n: value for n, value in values.items() if n <= 70}
                    recovered = e.recover(fit, config, self.binary)
                    self.assertEqual(recovered["status"], "recovered")
                    self.assertIn(seed, recovered["candidate_seed_magnitudes"])
                    for candidate in recovered["candidate_seed_magnitudes"]:
                        self.assertEqual(audit.independent_generate(candidate, indices, config), values)

    def test_corrupted_synthetic_observations_are_excluded(self):
        for config in e.configurations():
            values = audit.independent_generate(1234567, set(range(1, 71)), config)
            values[70] ^= 1
            result = e.recover(values, config, self.binary)
            self.assertEqual(result["status"], "excluded")
            self.assertTrue(result["complete"])
            self.assertEqual(result["candidate_seed_magnitudes"], [])
            self.assertEqual(result["exceptional_magnitudes_checked"], sorted(e.MODEL.EXCEPTIONAL_SEEDS))

    def test_timeout_is_inconclusive(self):
        delayed = self.directory / "delayed-scanner"
        delayed.write_text("#!/bin/sh\nexec sleep 5\n")
        delayed.chmod(0o700)
        config = e.configurations()[0]
        values = audit.independent_generate(1234567, set(range(1, 71)), config)
        result = e.recover(values, config, delayed, timeout_seconds=0.01)
        self.assertEqual(result["status"], "inconclusive_timeout")
        self.assertFalse(result["complete"])

    def test_incomplete_or_inconsistent_coverage_records_are_rejected(self):
        config = e.configurations()[0]
        values = audit.independent_generate(1234567, set(range(1, 71)), config)
        valid = e.recover(values, config, self.binary)["scanner"]
        e.validate_scan(valid)
        duplicate = copy.deepcopy(valid)
        duplicate["branches"][1]["branch_id"] = 0
        shortened = copy.deepcopy(valid)
        shortened["branches"][0]["tested_anchor_values"] -= 1
        shortened["tested_anchor_values"] -= 1
        omitted = copy.deepcopy(valid)
        omitted["candidate_seeds"] = []
        for damaged in (duplicate, shortened, omitted):
            with self.assertRaises(ValueError):
                e.validate_scan(damaged)


if __name__ == "__main__":
    unittest.main(verbosity=2)
