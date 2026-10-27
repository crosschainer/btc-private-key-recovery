#!/usr/bin/env python3
"""Independent known-answer checks for the bounded feedback experiment.

The transition fixtures below were calculated with stdlib hashlib, integer
hexadecimal parsing, and remainder arithmetic, without importing the battery.
They exercise prediction across missing widths, not just adjacent comparisons.
"""

import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("masked_feedback_battery", HERE / "feedback.py")
battery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(battery)


def config(**overrides):
    value = dict(encoding="decimal", state="full", digest="sha256",
                 digest_byte_order="big", counter="none", update="replace", direction=1)
    value.update(overrides)
    return value


FORWARD = {
    32: 0x80012345, 33: 0x11760F22B, 34: 0x228BA6E64, 35: 0x5109048AA,
    36: 0xE3C7134B9, 37: 0x159FFFA2B8, 38: 0x3E02E9F932, 39: 0x5E54FB8F9D,
}
BACKWARD = {
    39: 0x4000012345, 38: 0x3BF53ED218, 37: 0x1C9985FCF8, 36: 0x886616D1F,
    35: 0x7EB06E1B9, 34: 0x3F5BECF6D, 33: 0x1215D6E98, 32: 0xC54ECE79,
}


class PrimitiveVectors(unittest.TestCase):
    def test_hash_known_answers(self):
        answers = {
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha256d": "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
            "sha256_hex_sha256": "dfe7a23fefeea519e9bbfdd1a6be94c4b2e4529dd6b7cbea83f9959c2621b13c",
            "sha512_first32": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "sha512_last32": "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "hash160": "bb1be98c142444d7a56aa3981c3942a978e4dc33",
        }
        for name, expected in answers.items():
            with self.subTest(name=name):
                self.assertEqual(battery.digest_bytes(b"abc", name).hex(), expected)

    def test_hash160_without_openssl_provider(self):
        with patch.object(battery.hashlib, "new", side_effect=ValueError("unsupported hash type ripemd160")):
            self.assertEqual(battery.digest_bytes(b"abc", "hash160").hex(),
                             "bb1be98c142444d7a56aa3981c3942a978e4dc33")

    def test_scalar_serializations(self):
        expected = {
            "bytes32_be": b"\0" * 30 + b"\x0a\xbc",
            "bytes32_le": b"\xbc\x0a" + b"\0" * 30,
            "minimal_be": b"\x0a\xbc", "minimal_le": b"\xbc\x0a",
            "hex64_lower": b"0" * 61 + b"abc", "hex64_upper": b"0" * 61 + b"ABC",
            "hex_lower": b"abc", "hex_upper": b"ABC", "hex_even_lower": b"0abc",
            "hex_0x_lower": b"0xabc", "decimal": b"2748",
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(battery.encode(0xABC, name), value)
        self.assertEqual(battery.encode(0, "minimal_be"), b"\0")
        self.assertEqual(battery.encode(0, "minimal_le"), b"\0")
        self.assertEqual(battery.encode(0, "hex_even_lower"), b"00")

    def test_bitcoin_key_one_serializations(self):
        self.assertEqual(battery.encode(1, "wif_uncompressed"),
                         b"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
        self.assertEqual(battery.encode(1, "wif_compressed"),
                         b"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
        x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        self.assertEqual(battery.encode(1, "sec_compressed"), bytes.fromhex("02" + x))
        self.assertEqual(battery.encode(1, "sec_uncompressed"), bytes.fromhex("04" + x + y))
        # Base58Check's leading-zero preservation matters independently of WIF.
        self.assertEqual(battery.base58check(bytes(21)), "1111111111111111111114oLvT2")

    def test_counters_have_exact_serialized_boundaries(self):
        vectors = {
            "source_decimal_prefix": b"17:2748", "target_decimal_suffix": b"2748:18",
            "source_u32be_prefix": b"\0\0\0\x11" + b"2748",
            "target_u32le_suffix": b"2748\x12\0\0\0",
            "source_u8_suffix": b"2748\x11", "target_u8_prefix": b"\x122748",
        }
        for counter, expected in vectors.items():
            with self.subTest(counter=counter):
                self.assertEqual(battery.message_bytes(0xABC, 17, 18, config(counter=counter)), expected)
        self.assertEqual(battery.message_bytes(0xABC, 18, 17, config(counter="target_decimal_prefix", direction=-1)),
                         b"17:2748")


class TransitionVectors(unittest.TestCase):
    def test_simple_raw_scalar_transition(self):
        self.assertEqual(battery.step(0x12345, 17, 18, config(encoding="bytes32_be")), 0x31D6A)

    def test_arithmetic_modulo_curve_order(self):
        key = (1 << 253) + 0xABC
        expected = {
            "replace": 0x55E3596C73473EE352F27A783F60248AAEE06B7C4BF41D57881E429A9A4DA648,
            "add_mod_order": 0x75E3596C73473EE352F27A783F60248AAEE06B7C4BF41D57881E429A9A4DB104,
            "multiply_mod_order": 0x40753250051537F5CC5A4E7F79DBA4F34B1AF5AE1FD17D311044B0088A5707A1,
        }
        for update, value in expected.items():
            with self.subTest(update=update):
                self.assertEqual(battery.step(key, 254, 255, config(encoding="bytes32_be", update=update)), value)

    def test_residue_input_still_adds_full_scalar(self):
        key = (1 << 63) + 0xABCDEF
        expected = {"full": 0x1976436A0F9B4B396, "residue": 0x1D69E4315BBDD4E55}
        for state, value in expected.items():
            with self.subTest(state=state):
                selected = config(encoding="hex64_lower", state=state, digest="sha256_hex_sha256",
                                  digest_byte_order="little", update="add_mod_order")
                self.assertEqual(battery.step(key, 64, 65, selected), value)

    def test_addition_wraps_curve_order_before_masking(self):
        selected = config(encoding="bytes32_be", update="add_mod_order", direction=-1)
        self.assertEqual(battery.step(1 << 255, 256, 255, selected),
                         0x44B3F13B0A4FBCCE4C3F811E0313E00F1123974B12E14FB9B6872D5C01797707)

    def test_literal_chains_in_both_directions(self):
        for direction, fixture in ((1, FORWARD), (-1, BACKWARD)):
            selected = config(direction=direction)
            indices = sorted(fixture, reverse=direction == -1)
            for source, target in zip(indices, indices[1:]):
                with self.subTest(direction=direction, source=source):
                    self.assertEqual(battery.step(fixture[source], source, target, selected), fixture[target])
            self.assertTrue(battery.continuous(fixture, selected))

    def test_gaps_traverse_intermediate_widths(self):
        for direction, fixture in ((1, FORWARD), (-1, BACKWARD)):
            with self.subTest(direction=direction):
                selected = config(direction=direction)
                gapped = {index: fixture[index] for index in (32, 35, 39)}
                report = battery.compare(gapped, selected)
                self.assertTrue(report["compatible"])
                self.assertEqual(report["tested_transitions"], 2)
                self.assertTrue(battery.continuous(gapped, selected))
                self.assertEqual(battery.compare(gapped, selected, adjacent_only=True)["tested_transitions"], 0)
                first, last = ((32, 39) if direction == 1 else (39, 32))
                self.assertEqual(battery.traverse(fixture[first], first, last, selected), fixture[last])
                # A single hash at the source, masked only at the destination,
                # gives a different value from applying all intermediate masks.
                one_hash = int(hashlib.sha256(str(fixture[first]).encode()).hexdigest(), 16)
                collapsed = 2 ** (last - 1) + one_hash % 2 ** (last - 1)
                self.assertNotEqual(collapsed, fixture[last])

    def test_corrupted_gap_checkpoint_rejected(self):
        for direction, fixture in ((1, FORWARD), (-1, BACKWARD)):
            with self.subTest(direction=direction):
                selected = config(direction=direction)
                gapped = {index: fixture[index] for index in (32, 35, 39)}
                gapped[35] ^= 1
                report = battery.compare(gapped, selected)
                self.assertFalse(report["compatible"])
                self.assertEqual(report["first_counterexample"]["target"], 35)
                self.assertFalse(battery.continuous(gapped, selected))

    def test_wrong_direction_and_skipped_single_step_rejected(self):
        with self.assertRaises(AssertionError):
            battery.traverse(FORWARD[32], 32, 35, config(direction=-1))
        with self.assertRaises(AssertionError):
            battery.step(FORWARD[32], 32, 35, config())

    def test_observation_one_not_counted_as_informative(self):
        report = battery.compare({1: 1, 2: 3}, config(direction=-1))
        self.assertTrue(report["compatible"])
        self.assertEqual(report["tested_transitions"], 1)
        self.assertEqual(report["informative_transitions"], 0)


class ScopeChecks(unittest.TestCase):
    def test_fixed_count_unique_ids_and_no_zero_sec_state(self):
        candidates = list(battery.configurations())
        self.assertEqual(len(candidates), 34272)
        self.assertEqual(len({battery.config_id(value) for value in candidates}), 34272)
        self.assertEqual(sum(value["direction"] == 1 for value in candidates), 17136)
        self.assertFalse(any(value["encoding"].startswith("sec_") and value["state"] == "residue"
                             for value in candidates))


if __name__ == "__main__":
    unittest.main()
