#!/usr/bin/env python3
"""Fixed synthetic BIP32 recovery using an address ladder and exact public mapping.

Generates deterministic test wallets. Recovery receives public root material,
a fixed index mapping, masked-key address hashes, and one anchor scalar."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
HELPER = HERE.parent / "shared/curve.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_curve", HELPER)
CURVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CURVE)
ORDER = CURVE.ORDER
MASK = "d_N = 2^(N-1) + (u_N mod 2^(N-1))"
MAX_GAP = 5


def public_key(scalar: int) -> bytes:
    if not 0 < scalar < ORDER:
        raise ValueError("Invalid secp256k1 private scalar")
    return ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint
    )


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def base58check(payload: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    leading = len(raw) - len(raw.lstrip(b"\0"))
    value = int.from_bytes(raw, "big")
    digits = ""
    while value:
        value, digit = divmod(value, 58)
        digits = alphabet[digit] + digits
    return "1" * leading + digits


def serialize_xpub(parent_public: bytes, chain_code: bytes) -> str:
    return base58check(bytes.fromhex("0488b21e") + bytes(9) + chain_code + parent_public)


def public_offset(parent_public: bytes, chain_code: bytes, index: int) -> int:
    if not 0 <= index < 2**31:
        raise ValueError("Hardened or invalid index is not public-derivable")
    digest = hmac.new(chain_code, parent_public + index.to_bytes(4, "big"), hashlib.sha512).digest()
    offset = int.from_bytes(digest[:32], "big")
    if offset >= ORDER:
        raise ValueError("Invalid BIP32 child; exact mapping must specify its skip")
    return offset


def derive_source_public(parent_public: bytes, offset: int) -> bytes:
    parent_point = CURVE.decode_point(parent_public)
    tweak_point = None if offset == 0 else CURVE.decode_point(public_key(offset))
    source_point = CURVE.point_add(parent_point, tweak_point)
    if source_point is None:
        raise ValueError("Invalid zero BIP32 child; mapping must specify its skip")
    return CURVE.encode_point(source_point)


def make_fixture(wallet_number: int):
    seed = hashlib.sha256(f"masked-xpub-address-ladder-fixture-{wallet_number}".encode()).digest()
    master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    secret = int.from_bytes(master[:32], "big")
    chain_code = master[32:]
    parent_public = public_key(secret)
    index_map = {number: 5000 * wallet_number + 3 * (number - 1) for number in range(1, 257)}
    masked = {}
    targets = {}
    sources = {}
    wraps = {0: 0, 1: 0}
    for number, index in index_map.items():
        offset = public_offset(parent_public, chain_code, index)
        source = (secret + offset) % ORDER
        if not source:
            raise ValueError("Fixture generated an invalid BIP32 child")
        # Check genuine CKDpub against independently computed CKDpriv for every row.
        assert derive_source_public(parent_public, offset) == public_key(source)
        modulus = 1 << (number - 1)
        scalar = modulus + source % modulus
        if not 0 < scalar < ORDER:
            raise ValueError("Fixture mask produced invalid scalar; invalid fixture construction")
        masked[number] = scalar
        targets[number] = hash160(public_key(scalar))
        sources[number] = source
        wraps[int(secret + offset >= ORDER)] += 1
    return secret, parent_public, chain_code, index_map, masked, targets, sources, wraps


def recover_synthetic(parent_public, chain_code, index_map, targets, anchor_number, anchor_scalar, sequence):
    """Recover only over the small supplied synthetic ladder; gaps >5 forbidden.

    For delta=(t_j-t_i) mod n, u_j=(u_i+delta) mod n. There are two possible
    wrap bits w, so s_w=(r_i+delta-w*n) mod 2^b_i is a possible target residue.
    Its lift into b_j bits has 2^(b_j-b_i) choices. P2PKH hashes select the lift.
    """
    if not 1 <= anchor_number <= 256:
        raise ValueError("Invalid anchor")
    anchor_modulus = 1 << (anchor_number - 1)
    if not anchor_modulus <= anchor_scalar < min(2 * anchor_modulus, ORDER):
        raise ValueError("Invalid masked anchor")
    if hash160(public_key(anchor_scalar)) != targets[anchor_number]:
        raise ValueError("Anchor address mismatch")
    # Compute from public material only; reject a hardened required index eagerly.
    offsets = {
        number: public_offset(parent_public, chain_code, index_map[number])
        for number in [anchor_number, *sequence]
    }
    counters = {
        "anchor_scalar_hash_checks": 1,
        "candidate_scalar_hash_checks": 0,
        "source_point_comparisons": 0,
        "parent_point_comparisons": 0,
        "maximum_candidates_per_step": 0,
        "steps": 0,
        "per_gap_candidate_checks": {},
    }
    selected = {anchor_number: anchor_scalar}
    for number in sequence:
        gap = number - anchor_number
        if not 1 <= gap <= MAX_GAP:
            raise ValueError("Synthetic experiment permits increasing gaps of at most five bits")
        target_modulus = 1 << (number - 1)
        residue = anchor_scalar - anchor_modulus
        delta = (offsets[number] - offsets[anchor_number]) % ORDER
        low_residues = {(residue + delta - wrap * ORDER) % anchor_modulus for wrap in (0, 1)}
        candidates = sorted({
            target_modulus + low + lift * anchor_modulus
            for low in low_residues for lift in range(1 << gap)
            if 0 < target_modulus + low + lift * anchor_modulus < ORDER
        })
        assert len(candidates) <= 2 ** (gap + 1)
        counters["maximum_candidates_per_step"] = max(counters["maximum_candidates_per_step"], len(candidates))
        matches = []
        for scalar in candidates:
            counters["candidate_scalar_hash_checks"] += 1
            if hash160(public_key(scalar)) == targets[number]:
                matches.append(scalar)
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one matching address at observation {number}, got {len(matches)}")
        counters["steps"] += 1
        gap_key = str(gap)
        counters["per_gap_candidate_checks"][gap_key] = counters["per_gap_candidate_checks"].get(gap_key, 0) + len(candidates)
        anchor_scalar = matches[0]
        anchor_number = number
        anchor_modulus = target_modulus
        selected[number] = anchor_scalar
    if anchor_number != 256:
        raise ValueError("Synthetic sequence must end at 256")
    residue = anchor_scalar - anchor_modulus
    expected_source_public = derive_source_public(parent_public, offsets[256])
    final_sources = []
    for scalar in (residue, residue + anchor_modulus):
        if 0 < scalar < ORDER:
            counters["source_point_comparisons"] += 1
            if public_key(scalar) == expected_source_public:
                final_sources.append(scalar)
    if len(final_sources) != 1:
        raise ValueError("Final full source scalar is not unique")
    recovered_parent = (final_sources[0] - offsets[256]) % ORDER
    counters["parent_point_comparisons"] += 1
    if public_key(recovered_parent) != parent_public:
        raise ValueError("Recovered scalar does not match parent xpub")
    return recovered_parent, selected, counters


def expect_rejection(call):
    try:
        call()
    except ValueError as exc:
        return str(exc)
    raise AssertionError("Negative control unexpectedly accepted")


def run():
    rows = []
    negative = {}
    for wallet_number in range(1, 5):
        secret, parent_public, chain_code, mapping, masked, targets, sources, wraps = make_fixture(wallet_number)
        public_inputs = (parent_public, chain_code, mapping, targets)
        scenarios = [
            ("all_addresses_minimal_anchor", 1, 1, list(range(2, 257))),
            ("all_addresses_96_bit_anchor", 96, masked[96], list(range(97, 257))),
            ("four_bit_steps_then_adjacent", 96, masked[96], [100, 104, 108, 112, 116, *range(117, 257)]),
        ]
        for name, anchor, scalar, sequence in scenarios:
            recovered, recovered_masked, counters = recover_synthetic(*public_inputs, anchor, scalar, sequence)
            assert recovered == secret
            assert all(masked[number] == value for number, value in recovered_masked.items())
            rows.append({
                "wallet_fixture": wallet_number,
                "scenario": name,
                "root_xpub": serialize_xpub(parent_public, chain_code),
                "source_mapping": f"index = {5000 * wallet_number} + 3*(observation_number-1)",
                "full_parent_recovered_correctly": True,
                "every_recovered_masked_scalar_matches_reference": True,
                "source_child_count": 256,
                "all_ckdpub_ckdpriv_agree": True,
                "root_plus_offset_wrap_counts": wraps,
                "counters": counters,
            })
        if wallet_number == 1:
            wrong_mapping = dict(mapping)
            wrong_mapping[97] += 1
            negative["wrong_index_mapping"] = expect_rejection(lambda: recover_synthetic(
                parent_public, chain_code, wrong_mapping, targets, 96, masked[96], list(range(97, 257))))
            hardened_mapping = dict(mapping)
            hardened_mapping[97] |= 2**31
            negative["hardened_boundary"] = expect_rejection(lambda: recover_synthetic(
                parent_public, chain_code, hardened_mapping, targets, 96, masked[96], list(range(97, 257))))
            wrong_mask_targets = dict(targets)
            alternative_136 = 2**96 + (sources[97] >> (256 - 96))
            wrong_mask_targets[97] = hash160(public_key(alternative_136))
            negative["high_bits_instead_of_low_bit_mask"] = expect_rejection(lambda: recover_synthetic(
                parent_public, chain_code, mapping, wrong_mask_targets, 96, masked[96], list(range(97, 257))))
            missing_ladder = [103, *range(143, 257)]
            negative["gap_exceeds_fixed_experiment_bound"] = expect_rejection(lambda: recover_synthetic(
                *public_inputs, 96, masked[96], missing_ladder))
            # Force an artificial hash collision to prove ambiguity fails closed.
            collision_targets = {number: bytes(20) for number in targets}
            with patch(__name__ + ".hash160", return_value=bytes(20)):
                negative["ambiguous_address_oracle"] = expect_rejection(lambda: recover_synthetic(
                    parent_public, chain_code, mapping, collision_targets, 96, masked[96], list(range(97, 257))))
            negative["scalar_at_curve_order"] = expect_rejection(lambda: public_key(ORDER))
    return {
        "scope": "Fixed deterministic synthetic wallets and public fixture hashes.",
        "assumed_mask": MASK,
        "curve": "secp256k1",
        "curve_order": hex(ORDER),
        "seed_rule": "SHA256(UTF8('masked-xpub-address-ladder-fixture-'+wallet_number)) for wallet_number 1..4",
        "master_derivation": "HMAC-SHA512(key='Bitcoin seed', data=seed); genuine non-hardened BIP32 siblings",
        "target_oracle": "HASH160 of compressed SEC1 public key; matches P2PKH script payload",
        "not_independent_entropy": "Adjacent mask lifting uses a known BIP32 additive relation; hash checks identify at most four adjacent candidates.",
        "scalar_hash_check_caveat": "Each check uses a full OpenSSL scalar multiplication plus HASH160, not one group addition.",
        "candidate_bound": "2^(gap+1); for adjacent masks at most 4, at the first one-bit step only 2",
        "negative_controls": negative,
        "successful_recoveries": len(rows),
        "results": rows,
        "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "curve_helper_sha256": hashlib.sha256(HELPER.read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 1:
        raise SystemExit("This fixed synthetic experiment accepts no inputs or command-line options")
    document = run()
    destination = HERE / "bootstrap_results.json"
    destination.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps({"successful_recoveries": document["successful_recoveries"],
                      "negative_controls": document["negative_controls"],
                      "output": str(destination)}, indent=2))
