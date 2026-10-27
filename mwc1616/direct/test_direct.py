#!/usr/bin/env python3
"""Independent finite enumeration, mask extraction, and coverage-accounting checks."""

import importlib.util
import copy
import json
from pathlib import Path
import random
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


def load_runner():
    spec = importlib.util.spec_from_file_location("mwc_direct_runner", HERE / "recovery.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reference_state(index, bits, observed):
    """Insert the observed field between the two independent free fields."""
    low_count = 2 ** (16 - bits)
    return (index // low_count) * 65536 + observed * low_count + index % low_count


def reference_index(state, bits):
    low_count = 2 ** (16 - bits)
    return (state // 65536) * low_count + state % low_count


def reference_units(state, multiplier, bits, count):
    values = []
    for _ in range(count):
        word = (state % 65536) * 65536
        values.append(word // (2 ** (32 - bits)))
        state = multiplier * (state % 65536) + state // 65536
    return values


def reference_scan(multiplier, bits, units, begin, end):
    matches = []
    prefix = [0] * len(units)
    for index in range(begin, end):
        anchor = reference_state(index, bits, units[0])
        actual = reference_units(anchor, multiplier, bits, len(units))
        for position, (observed, expected) in enumerate(zip(actual, units)):
            if observed != expected:
                break
            prefix[position] += 1
        else:
            matches.append(anchor)
    return matches, prefix


def string_observations(mask, n, scalar, bits, order):
    """Place retained scalar bits at their literal positions in 256 raw bits."""
    payload = scalar - 2 ** (n - 1)
    retained = format(payload, f"0{n - 1}b") if n > 1 else ""
    raw = [None] * 256
    start = 0 if mask == "high" else 257 - n
    raw[start:start + n - 1] = retained
    units = [raw[i:i + bits] for i in range(0, 256, bits)]
    if order == "little":
        units.reverse()
    return [(draw, int("".join(unit), 2))
            for draw, unit in enumerate(units) if None not in unit]


class NativeEnumeration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="mwc-direct-tests-")
        cls.binary = Path(cls.temp.name) / "mwc_scan"
        subprocess.run(["cc", "-O3", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(HERE / "mwc_scan.c"), "-o", str(cls.binary)], check=True,
                       capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, multiplier, bits, units, begin, end, limit=4096):
        proc = subprocess.run([str(self.binary), str(multiplier), str(bits),
                               ",".join(map(str, units)), str(begin), str(end), str(limit)],
                              check=True, capture_output=True, text=True)
        return json.loads(proc.stdout)

    def check_interval(self, multiplier, bits, units, begin, end):
        actual = self.invoke(multiplier, bits, units, begin, end)
        matches, prefix = reference_scan(multiplier, bits, units, begin, end)
        self.assertEqual(actual["begin"], begin)
        self.assertEqual(actual["end"], end)
        self.assertEqual(actual["candidates_checked"], end - begin)
        self.assertEqual(actual["match_count"], len(matches))
        self.assertEqual(actual["matches"], matches)
        self.assertEqual(actual["prefix_survivors"], prefix)
        self.assertFalse(actual["matches_truncated"])
        self.assertGreaterEqual(actual["elapsed_seconds"], 0)

    def test_dense_intervals_and_free_field_carries(self):
        rng = random.Random(0x1616)
        for multiplier in (18030, 18273):
            for bits in (4, 8):
                domain = 2 ** (32 - bits)
                low_count = 2 ** (16 - bits)
                starts = [0, low_count - 47, low_count, domain - 257]
                starts.extend(rng.randrange(domain - 257) for _ in range(6))
                for begin in starts:
                    first = rng.randrange(2 ** bits)
                    anchor = reference_state(begin + 123, bits, first)
                    units = reference_units(anchor, multiplier, bits, 12)
                    with self.subTest(multiplier=multiplier, bits=bits, begin=begin):
                        self.check_interval(multiplier, bits, units, begin, begin + 257)

    def test_uint32_endpoints_canonical_fixed_points_and_transients(self):
        for multiplier in (18030, 18273):
            modulus = multiplier * 65536 - 1
            for bits in (4, 8):
                domain = 2 ** (32 - bits)
                for state in (0, 1, 65535, 65536, modulus - 1, modulus,
                              modulus + 1, 2 ** 32 - 1):
                    index = reference_index(state, bits)
                    units = reference_units(state, multiplier, bits, 33)
                    begin, end = max(0, index - 31), min(domain, index + 32)
                    with self.subTest(multiplier=multiplier, bits=bits, state=state):
                        self.check_interval(multiplier, bits, units, begin, end)
                        self.assertIn(state, self.invoke(multiplier, bits, units, begin, end)["matches"])

    def test_single_observation_covers_every_free_coordinate(self):
        for bits in (4, 8):
            for observed in (0, 2 ** bits - 1):
                for begin in (0, 2 ** (16 - bits) - 127, 2 ** (32 - bits) - 257):
                    self.check_interval(18030, bits, [observed], begin, begin + 257)

    def test_truncated_matches_remain_explicit_and_counted(self):
        result = self.invoke(18030, 4, [3], 0, 100, 7)
        self.assertEqual(result["candidates_checked"], 100)
        self.assertEqual(result["match_count"], 100)
        self.assertEqual(result["prefix_survivors"], [100])
        self.assertEqual(len(result["matches"]), 7)
        self.assertTrue(result["matches_truncated"])

    def test_invalid_arguments_fail_without_result(self):
        invalid = [
            ["-1", "4", "1,2", "0", "1"],
            ["18030", "5", "1,2", "0", "1"],
            ["18030", "4", "", "0", "1"],
            ["18030", "4", "1,,2", "0", "1"],
            ["18030", "4", "1,2,", "0", "1"],
            ["18030", "4", "16", "0", "1"],
            ["18030", "8", "256", "0", "1"],
            ["18030", "4", "-1", "0", "1"],
            ["18030", "4", "1.0", "0", "1"],
            ["18030", "4", "1", "-1", "1"],
            ["18030", "4", "1", "2", "1"],
            ["18030", "4", "1", "0", str(2 ** 28 + 1)],
            ["18030", "8", "1", "0", str(2 ** 24 + 1)],
            ["18030", "4", "1", "0", "1", "-1"],
        ]
        for args in invalid:
            with self.subTest(args=args):
                proc = subprocess.run([str(self.binary), *args], capture_output=True, text=True)
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(proc.stdout, "")


class ResultValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_runner()

    def fixture(self):
        units = reference_units(reference_state(101, 4, 3), 18030, 4, 33)
        matches, prefix = reference_scan(18030, 4, units, 0, 256)
        self.assertGreaterEqual(len(matches), 1)
        data = {"multiplier": 18030, "bits": 4, "begin": 0, "end": 256,
                "candidates_checked": 256, "matches_truncated": False,
                "match_count": len(matches), "matches": matches,
                "prefix_survivors": prefix, "elapsed_seconds": 0.001}
        return units, data

    def test_independent_reference_result_is_accepted(self):
        units, data = self.fixture()
        self.runner.check_scan(data, 18030, 4, units, 0, 256)

    def test_incomplete_or_corrupt_scan_results_are_rejected(self):
        units, data = self.fixture()
        changes = [
            ("begin", 1), ("end", 255), ("candidates_checked", 255),
            ("multiplier", 18273), ("bits", 8), ("matches_truncated", True),
            ("match_count", len(data["matches"]) + 1),
            ("matches", [2 ** 32]), ("matches", [-1]),
            ("prefix_survivors", data["prefix_survivors"][:-1]),
            ("prefix_survivors", [-1] + data["prefix_survivors"][1:]),
            ("elapsed_seconds", -1), ("elapsed_seconds", float("inf")),
            ("elapsed_seconds", float("nan")),
        ]
        for key, value in changes:
            broken = copy.deepcopy(data)
            broken[key] = value
            with self.subTest(field=key, value=value):
                with self.assertRaises(ValueError):
                    self.runner.check_scan(broken, 18030, 4, units, 0, 256)


class ObservationExtraction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_runner()
        cls.modules = cls.runner.modules()

    def test_full_units_match_independent_bit_strings_at_boundaries(self):
        rng = random.Random(135)
        for mask, module in self.modules.items():
            for bits in (4, 8):
                for order in ("big", "little"):
                    layout = self.runner.layout(module, bits, order)
                    for n in (9, 16, 17, 64, 65, 128, 129, 135, 136, 137, 255, 256):
                        for payload in (0, 2 ** (n - 1) - 1, rng.randrange(2 ** (n - 1))):
                            scalar = 2 ** (n - 1) + payload
                            reference = string_observations(mask, n, scalar, bits, order)
                            actual = self.runner.full_observations(module, n, scalar, layout)
                            with self.subTest(mask=mask, bits=bits, order=order, n=n, payload=payload):
                                self.assertEqual(actual["first_full_unit"], reference[0][0])
                                self.assertEqual(actual["units"], [value for _, value in reference])
                                self.assertEqual(actual["bits"], bits)
                                self.assertEqual(actual["retained_bits_used"], len(reference) * bits)
                                self.assertEqual(actual["discarded_partial_bits"], (n - 1) % bits)
                                self.assertEqual([draw for draw, _ in reference],
                                                 list(range(reference[0][0], reference[-1][0] + 1)))

    def test_observation135_first_full_draws_are_explicit(self):
        expected = {("low", "big"): 31, ("low", "little"): 0,
                    ("high", "big"): 0, ("high", "little"): 31}
        for (mask, order), first in expected.items():
            module = self.modules[mask]
            actual = self.runner.full_observations(module, 135, 2 ** 134,
                                                   self.runner.layout(module, 4, order))
            self.assertEqual(actual["first_full_unit"], first)
            self.assertEqual(len(actual["units"]), 33)
            self.assertEqual(actual["retained_bits_used"], 132)
            self.assertEqual(actual["discarded_partial_bits"], 2)
        module = self.modules["high"]
        extra = self.runner.full_observations(module, 135, 2 ** 134,
                                              self.runner.layout(module, 8, "little"))
        self.assertEqual(extra["first_full_unit"], 16)
        self.assertEqual(len(extra["units"]), 16)
        self.assertEqual(extra["retained_bits_used"], 128)
        self.assertEqual(extra["discarded_partial_bits"], 6)
