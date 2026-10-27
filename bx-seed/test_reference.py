#!/usr/bin/env python3
"""Independent reference tests, without a real-wallet seed search."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import reference as ref

ROOT = Path(__file__).resolve().parents[1]
VECTORS = Path(__file__).resolve().parent / "fixtures/bip32_vectors.json"
VECTOR_SHA256 = "ec4f271a482ec22674f181ef406fb40a6a10a25a1544c5831453845d2e2b3670"


def load_vectors():
    raw = VECTORS.read_bytes()
    if hashlib.sha256(raw).hexdigest() != VECTOR_SHA256:
        raise ValueError("Pinned external BIP32 vectors changed")
    return json.loads(raw)


class ReferenceTests(unittest.TestCase):
    def test_fixture_matches_pinned_upstream(self):
        # Re-extract the externally supplied expected keys and child indexes;
        # this verifies that fixture transcription did not invent its oracle.
        fixture = load_vectors()
        raw = (Path(__file__).resolve().parent.parent / "shared/bip32_tests.cpp").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), fixture["source_sha256"])
        extracted = []
        pattern = r'TestVector test([1-4]) =\s*TestVector\("([0-9a-f]+)"\)(.*?);'
        for match in re.finditer(pattern, raw.decode(), re.DOTALL):
            number, seed, body = match.groups()
            indices, nodes = [], []
            for xpub, xprv, expression in re.findall(
                    r'\("(xpub[^"\s]+)",\s*"(xprv[^"\s]+)",\s*([^\)]+)\)', body):
                nodes.append({"indices": indices[:], "xpub": xpub, "xprv": xprv})
                index = 0
                for term in expression.split("|"):
                    term = term.strip()
                    index |= ref.HARDENED if term == "BIP32_HARDENED_FLAG" else int(term, 0)
                indices.append(index)
            extracted.append({"number": int(number), "seed_hex": seed, "nodes": nodes})
        self.assertEqual(extracted, fixture["vectors"])

    def test_cpp_standard_engines(self):
        # Explicit standard engine types independently exercise constructor seed
        # normalization and update-before-output semantics.  This is the current
        # C++ runtime, not a claim to execute a historical wallet binary.
        source = r'''
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
template<typename Engine>
void emit(const char* name, uint64_t seed, unsigned count) {
    Engine engine(seed);
    std::cout << name << " " << seed << " " << count << " ";
    for (unsigned i = 0; i < count; ++i)
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << (engine() % std::numeric_limits<uint8_t>::max());
    std::cout << std::dec << "\n";
}
int main() {
    for (uint64_t seed: {0ULL, 1ULL, 2ULL, 12345ULL, 2147483646ULL,
                        2147483647ULL, 2147483648ULL, 4294967295ULL,
                        4294967296ULL, 18446744073709551615ULL})
        for (unsigned count: {16U, 24U, 32U}) {
            emit<std::minstd_rand0>("minstd_rand0", seed, count);
            emit<std::minstd_rand>("minstd_rand", seed, count);
        }
}
'''
        with tempfile.TemporaryDirectory(prefix="bx-seed-reference-") as temp:
            directory = Path(temp)
            cpp, executable = directory / "engines.cpp", directory / "engines"
            cpp.write_text(source)
            subprocess.run(["g++", "-std=c++11", "-O2", str(cpp), "-o", str(executable)],
                           check=True, capture_output=True, text=True)
            output = subprocess.run([str(executable)], check=True, capture_output=True, text=True).stdout
        rows = output.splitlines()
        self.assertEqual(len(rows), 60)
        for row in rows:
            engine, state, size, expected = row.split()
            with self.subTest(engine=engine, state=state, size=size):
                self.assertEqual(ref.seed_bytes(int(state), int(size), engine).hex(), expected)

    def test_historical_seed_recipe(self):
        first_outputs = {
            "minstd_rand0": [16807, 282475249, 1622650073, 984943658, 1144108930],
            "minstd_rand": [48271, 182605794, 1291394886, 1914720637, 2078669041],
        }
        for engine, known_outputs in first_outputs.items():
            actual = ref.seed_bytes(1, 32, engine)
            self.assertEqual(actual[:5], bytes(x % 255 for x in known_outputs))
            self.assertNotIn(255, actual)
            self.assertEqual(ref.seed_bytes(0, 32, engine), actual)
            self.assertEqual(ref.seed_bytes(ref.ENGINE_MODULUS, 32, engine), actual)
            self.assertEqual(ref.seed_bytes(ref.ENGINE_MODULUS + 1, 32, engine), actual)
            self.assertEqual(ref.seed_bytes(1, 16, engine), actual[:16])
        with self.assertRaises(ValueError):
            ref.seed_bytes(1, 15)

    def test_official_bip32_vectors(self):
        # Decode external expected private scalar/chain and SEC public point,
        # independently of the scanner and without matching self-generated data.
        vectors = load_vectors()["vectors"]
        total = 0
        self.assertEqual([vector["number"] for vector in vectors], [1, 2, 3, 4])
        for vector in vectors:
            master = ref.master(bytes.fromhex(vector["seed_hex"]))
            for row in vector["nodes"]:
                node = ref.derive_path(master, row["indices"])
                with self.subTest(vector=vector["number"], node=total):
                    self.assertEqual(node, ref.decode_vector_private(row["xprv"]))
                    expected_public = ref.base58check_decode(row["xpub"])
                    self.assertEqual(node.chain, expected_public[13:45])
                    self.assertEqual(ref.compressed_public(node.secret), expected_public[45:])
                total += 1
        self.assertEqual(total, 17)

    def test_reject_invalid_bip32_outputs(self):
        node = ref.master(bytes(range(16)))
        with patch.object(ref, "digest", return_value=b"\0" * 64):
            with self.assertRaises(ValueError):
                ref.master(b"seed")
        with patch.object(ref, "digest", return_value=ref.ORDER.to_bytes(32, "big") + b"\0" * 32):
            with self.assertRaises(ValueError):
                ref.derive(node, 0)
        zero_child = ref.ORDER - node.secret
        with patch.object(ref, "digest", return_value=zero_child.to_bytes(32, "big") + b"\0" * 32):
            with self.assertRaises(ValueError):
                ref.derive(node, 0)
        with self.assertRaises(ValueError):
            ref.derive(node, 1 << 32)
        # A zero tweak is valid under BIP32: only the child chain code changes.
        with patch.object(ref, "digest", return_value=b"\0" * 32 + b"\x55" * 32):
            self.assertEqual(ref.derive(node, 0), ref.Node(node.secret, b"\x55" * 32))

    def test_paths_and_gapped_indexing(self):
        seed = bytes(range(16))
        self.assertEqual(ref.parse_path("m/0'/1h/2H/3"),
                         [ref.HARDENED, ref.HARDENED + 1, ref.HARDENED + 2, 3])
        for path in ("", "0/1", "m//0", "m/-1", "m/2147483648", "m/3x", "m/١", None):
            with self.assertRaises(ValueError):
                ref.parse_path(path)
        all_rows = ref.observations(seed, "m/0'", 1, False, range(1, 71))
        sparse_rows = ref.observations(seed, "m/0'", 1, False, [1, 9, 40, 70])
        self.assertEqual(sparse_rows, {i: all_rows[i] for i in sparse_rows})
        parent = ref.derive(ref.master(seed), ref.HARDENED)
        for observation, value in sparse_rows.items():
            direct_secret = ref.derive(parent, observation).secret
            self.assertEqual(value, (1 << (observation - 1)) | (direct_secret & ((1 << (observation - 1)) - 1)))

    def test_masks_and_boundaries(self):
        secret = int("12" + "00" * 30 + "ab", 16)
        self.assertEqual(ref.masked_scalar(secret, 9, "low"), 0x1ab)
        self.assertEqual(ref.masked_scalar(secret, 9, "high"), 0x112)
        for mask in ("low", "high"):
            self.assertEqual(ref.masked_scalar(secret, 1, mask), 1)
        for bad_observation in (0, 257):
            with self.assertRaises(ValueError):
                ref.masked_scalar(secret, bad_observation)
        with self.assertRaises(ValueError):
            ref.masked_scalar((1 << 255) - 1, 256)

    def test_input_and_index_boundaries(self):
        for state in (-1, 1 << 64, 1.0, True):
            with self.subTest(state=state), self.assertRaises(ValueError):
                ref.seed_bytes(state, 16)
        for size in (0, 15, 16.0, True):
            with self.subTest(size=size), self.assertRaises(ValueError):
                ref.seed_bytes(1, size)
        with self.assertRaises(ValueError):
            ref.Node(1, "a" * 32)
        seed = bytes(range(16))
        for observations in ([0], [257], [1, 1], [True]):
            with self.subTest(observations=observations), self.assertRaises(ValueError):
                ref.observations(seed, "m", 0, False, observations)
        for hard in (False, True):
            self.assertEqual(list(ref.observations(seed, "m", ref.HARDENED - 1, hard, [1])), [1])
            with self.assertRaises(ValueError):
                ref.observations(seed, "m", ref.HARDENED - 1, hard, [2])

    def test_masks_against_bitstrings(self):
        # Independent string slicing catches width, padding, and boundary errors.
        values = [1, ref.ORDER - 1, int.from_bytes(hashlib.sha256(b"bx mask fixture").digest(), "big")]
        for secret in values:
            bits = f"{secret:0256b}"
            for observation in range(1, 257):
                width = observation - 1
                for mask in ("low", "high"):
                    retained = "" if width == 0 else (bits[-width:] if mask == "low" else bits[:width])
                    expected = int("1" + retained, 2)
                    with self.subTest(secret=secret, observation=observation, mask=mask):
                        if expected >= ref.ORDER:
                            with self.assertRaises(ValueError):
                                ref.masked_scalar(secret, observation, mask)
                        else:
                            self.assertEqual(ref.masked_scalar(secret, observation, mask), expected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReferenceTests))
    record = {"tests_run": result.testsRun, "successful": result.wasSuccessful(),
              "failures": len(result.failures), "errors": len(result.errors),
              "bip32_official_vectors": [1, 2, 3, 4], "bip32_nodes": 17,
              "fixture_nodes_reextracted_from_pinned_upstream": 17,
              "explicit_cpp_standard_engine_crosschecks": 60,
              "independent_bitstring_mask_checks": 1536,
              "cpp_compiler": subprocess.run(["g++", "--version"], check=True, capture_output=True,
                                             text=True).stdout.splitlines()[0],
              "cpp_scope": "Current explicit minstd_rand0/minstd_rand types, not a historical binary replay",
              "vector_source": str(VECTORS.relative_to(ROOT)),
              "vector_source_sha256": hashlib.sha256(VECTORS.read_bytes()).hexdigest(),
              "vector_upstream_source": load_vectors()["source_url"],
              "vector_upstream_sha256": load_vectors()["source_sha256"],
              "scope": "Independent Python reference and published vector verification; no real seed search"}
    if args.json_output:
        args.json_output.write_text(json.dumps(record, indent=2) + "\n")
    raise SystemExit(not result.wasSuccessful())


if __name__ == "__main__":
    main()
