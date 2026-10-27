#!/usr/bin/env python3
"""Offline controls for the reduced historical pipeline.

Frozen RNG expectations come from archived original JavaScript. When the pinned
QuickJS dependency is available, rerun that source rather than only its vectors.
These tests do not establish that a public observation used this historical wallet.
"""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import pipeline as p

HERE = Path(__file__).resolve().parent
VECTORS = json.loads((HERE / "oracle_test_vectors.json").read_text())["vectors"]


def reduced_arguments(arguments):
    return {
        "variant": arguments["variant"], "state": arguments["state0"],
        "times_ms": arguments["times_ms"],
        "extra_seed_ints": arguments.get("extra_seed_ints", ()),
    }


class PoolTests(unittest.TestCase):
    def test_every_frozen_original_javascript_pool_and_stream(self):
        for vector in VECTORS:
            with self.subTest(vector=vector["name"]):
                arguments, expected = vector["input"], vector["expected"]
                reduced = reduced_arguments(arguments)
                pool = p.pool_for_state(**reduced)
                self.assertEqual(pool, bytes(expected["pool_before_arc4"]))
                stream = p.ARC4(pool)
                stream.read(arguments.get("stream_offset", 0))
                self.assertEqual(stream.read(arguments.get("length", 32)).hex(),
                                 expected["seed_hex"])
                self.assertEqual(p.seed_for_state(
                    **reduced, stream_offset=arguments.get("stream_offset", 0)).hex(),
                    expected["seed_hex"][:64])
                self.assertEqual(p.next_state(arguments["state0"], arguments["variant"]),
                                 expected["first_updated_state"][0])
                state = arguments["state0"]
                for _ in range(128):
                    state = p.next_state(state, arguments["variant"])
                self.assertEqual(state, expected["state_after_draws"][0])

    def test_before_and_after_call_boundaries(self):
        for multiplier in p.MULTIPLIERS:
            for state in (0, 1, 0x12345678, 0x80000000, 0xFFFFFFFF):
                with self.subTest(multiplier=multiplier, state=state):
                    arguments = (multiplier, state, [1420000000123, 1420000000456])
                    after = (multiplier, p.next_state(state, multiplier), arguments[2])
                    self.assertEqual(p.pool_for_state(*arguments),
                                     p.pool_for_state(*after, boundary="after"))
                    self.assertEqual(p.seed_for_state(*arguments, stream_offset=49),
                                     p.seed_for_state(*after, boundary="after", stream_offset=49))

    def test_timestamp_slots_byte_order_and_low32_conversion(self):
        for multiplier in p.MULTIPLIERS:
            baseline = p.pool_for_state(multiplier, 17, [0, 0])
            mixed = p.pool_for_state(multiplier, 17, [0x12345678, 0x90ABCDEF])
            self.assertEqual(bytes(x ^ y for x, y in zip(baseline, mixed)),
                             bytes.fromhex("78563412efcdab90") + bytes(248))
            self.assertEqual(p.pool_for_state(multiplier, 17, [-1, -(1 << 32) + 1]),
                             p.pool_for_state(multiplier, 17, [0xFFFFFFFF, 1]))
            self.assertEqual(p.seed_for_state(multiplier, 17, [0, 1]),
                             p.seed_for_state(multiplier, 17, [1 << 32, (1 << 32) + 1]))

    def test_transient_tail_and_fixed_states(self):
        for multiplier in p.MULTIPLIERS:
            modulus = multiplier * 65536 - 1
            maximum = multiplier * 65535 + 65535
            self.assertEqual(p.next_state(0xFFFFFFFF, multiplier), maximum)
            self.assertGreater(maximum, modulus)
            for distance in (1, 65536 - multiplier):
                self.assertEqual(p.next_state(modulus + distance, multiplier),
                                 multiplier * distance)
            self.assertEqual(p.next_state(0, multiplier), 0)
            self.assertEqual(p.next_state(modulus, multiplier), modulus)
            for state in (1, 2, 65535, 65536, modulus - 1):
                self.assertEqual(p.next_state(state, multiplier),
                                 multiplier * state % modulus)
            # The tail's first halfword must be kept; folding modulo m loses it.
            self.assertNotEqual(p.pool_for_state(multiplier, maximum, [0, 0], boundary="after"),
                                p.pool_for_state(multiplier, maximum % modulus, [0, 0], boundary="after"))

    def test_rc4_rfc6229_and_continued_reads(self):
        # RFC 6229 section 2, 40-bit key, offsets 0 and 256:
        # https://www.rfc-editor.org/rfc/rfc6229#section-2
        stream = p.ARC4(bytes.fromhex("0102030405"))
        self.assertEqual(stream.read(0), b"")
        self.assertEqual(stream.read(16).hex(), "b2396305f03dc027ccc3524a0a1118a8")
        stream.read(240)
        self.assertEqual(stream.read(16).hex(), "1cfcf62b03eddb641d77dfcf7f8d8c93")
        key = bytes(range(256))
        split = p.ARC4(key)
        self.assertEqual(split.read(49) + split.read(32) + split.read(943),
                         p.ARC4(key).read(1024))

    def test_invalid_inputs_fail(self):
        for state in (-1, 1 << 32, True):
            with self.subTest(state=state), self.assertRaises(ValueError):
                p.pool_for_state(18273, state, [0, 0])
        for times in ([0], [0, 1.5], [0, 1 << 53]):
            with self.subTest(times=times), self.assertRaises(ValueError):
                p.pool_for_state(18273, 1, times)
        with self.assertRaises(ValueError):
            p.pool_for_state(36969, 1, [0, 0])
        with self.assertRaises(ValueError):
            p.pool_for_state(18273, 1, [0, 0], boundary="ambiguous")
        with self.assertRaises(ValueError):
            p.seed_for_state(18273, 1, [0, 0], stream_offset=-1)
        with self.assertRaises(ValueError):
            p.ARC4(b"")


class DerivationTests(unittest.TestCase):
    def test_leading_zero_hardened_field_retains_compression_suffix(self):
        for length in (1, 2, 30, 31, 32):
            scalar_bytes = b"\x12" + bytes(length - 1)
            scalar = int.from_bytes(scalar_bytes, "big")
            expected = scalar_bytes + b"\x01" if length < 32 else scalar_bytes
            with self.subTest(length=length):
                self.assertEqual(p.hardened_field(scalar), expected)
                parent = p.HDNode(scalar, bytes(range(32)))
                output = (7).to_bytes(32, "big") + bytes([0xA5]) * 32
                with patch.object(p.hmac, "digest", return_value=output) as digest:
                    child = p.derive(parent, p.HARDENED + 9)
                digest.assert_called_once_with(parent.chaincode,
                                               b"\0" + expected + bytes.fromhex("80000009"),
                                               "sha512")
                self.assertEqual(child.scalar, scalar + 7)
                self.assertEqual(child.chaincode, bytes([0xA5]) * 32)

    def test_nonhardened_derivation_uses_compressed_point_and_big_endian_index(self):
        parent = p.HDNode(1, bytes(range(32)))
        generator = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        self.assertEqual(parent.public_key, generator)
        with patch.object(p.hmac, "digest", return_value=bytes(32) + bytes([17]) * 32) as digest:
            child = p.derive(parent, 0x01020304)
        digest.assert_called_once_with(parent.chaincode, generator + bytes.fromhex("01020304"), "sha512")
        self.assertEqual(child.scalar, parent.scalar)
        self.assertEqual(child.chaincode, bytes([17]) * 32)

    def test_old_child_tweak_semantics_and_explicit_zero_failure(self):
        parent = p.HDNode(7, bytes(32))
        for tweak in (0, p.ORDER, p.ORDER + 1, (1 << 256) - 1):
            with self.subTest(tweak=tweak):
                result = tweak.to_bytes(32, "big") + bytes([42]) * 32
                with patch.object(p.hmac, "digest", return_value=result):
                    child = p.derive(parent, p.HARDENED)
                self.assertEqual(child.scalar, (parent.scalar + tweak) % p.ORDER)
        zero_child = (p.ORDER - parent.scalar).to_bytes(32, "big") + bytes(32)
        with patch.object(p.hmac, "digest", return_value=zero_child) as digest:
            with self.assertRaises(p.UnsupportedScalar):
                p.derive(parent, p.HARDENED)
            self.assertEqual(digest.call_count, 1, "Must not silently retry another index")
        for invalid in (0, p.ORDER):
            with self.subTest(master=invalid):
                result = invalid.to_bytes(32, "big") + bytes(32)
                with patch.object(p.hmac, "digest", return_value=result) as digest:
                    with self.assertRaises(p.UnsupportedScalar):
                        p.master(bytes(32))
                    self.assertEqual(digest.call_count, 1)

    def test_raw_master_seed_and_fixed_wallet_path(self):
        seed = bytes(range(32))
        result = (7).to_bytes(32, "big") + bytes([9]) * 32
        with patch.object(p.hmac, "digest", return_value=result) as digest:
            node = p.master(seed)
        digest.assert_called_once_with(b"Bitcoin seed", seed, "sha512")
        self.assertEqual(node, p.HDNode(7, bytes([9]) * 32))
        for branch in (0, 1):
            with self.subTest(branch=branch):
                root, account, expected = object(), object(), object()
                with patch.object(p, "master", return_value=root) as master:
                    with patch.object(p, "derive", side_effect=[account, expected]) as derive:
                        self.assertIs(p.wallet_branch(seed, branch), expected)
                master.assert_called_once_with(seed)
                self.assertEqual([call.args for call in derive.call_args_list],
                                 [(root, p.HARDENED), (account, branch)])

    def test_low_and_fixed256_high_masks(self):
        scalar = int.from_bytes(bytes(range(1, 33)), "big")
        bits = f"{scalar:0256b}"
        for width in (1, 2, 8, 31, 32, 70, 135, 255, 256):
            with self.subTest(width=width):
                retained = width - 1
                low = int("1" + (bits[-retained:] if retained else ""), 2)
                high = int("1" + bits[:retained], 2)
                self.assertEqual(p.mask_scalar(scalar, width, "low"), low)
                self.assertEqual(p.mask_scalar(scalar, width, "high"), high)
        for mode in ("low", "high"):
            self.assertEqual(p.mask_scalar(1, 1, mode), 1)
            self.assertEqual(p.mask_scalar(p.ORDER - 1, 1, mode), 1)
        with self.assertRaises(p.UnsupportedScalar):
            p.mask_scalar((p.ORDER - (1 << 255)), 256, "low")
        for width in (0, 257, True):
            with self.subTest(width=width), self.assertRaises(ValueError):
                p.mask_scalar(scalar, width)

    def test_observation_index_mapping_preserves_gaps(self):
        parent = object()
        observations = [1, 2, 70, 75, 135]
        with patch.object(p, "wallet_branch", return_value=parent) as branch:
            with patch.object(p, "derive", return_value=p.HDNode(7, bytes(32))) as derive:
                result = p.observations(bytes(32), observations, branch=1, start_index=3)
        branch.assert_called_once_with(bytes(32), 1)
        self.assertEqual([call.args for call in derive.call_args_list],
                         [(parent, n + 2) for n in observations])
        self.assertEqual(list(result), observations)
        with self.assertRaises(ValueError):
            p.observations(bytes(32), [2, 2])
        with self.assertRaises(ValueError):
            p.observations(bytes(32), [2], start_index=p.HARDENED - 1)
