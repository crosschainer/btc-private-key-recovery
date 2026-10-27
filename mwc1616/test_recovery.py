#!/usr/bin/env python3
"""Independent synthetic MWC checks using literal numeric packing and draw counts."""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import z3


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("mwc_experiment", HERE / "recovery.py")
experiment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(experiment)
MULTIPLIERS = (18030, 36969)
SEED = (0xFEDCBA98, 0x87654321)
OBSERVED_WIDTHS = tuple(range(1, 71)) + tuple(range(75, 136, 5))


def layout_named(name):
    return next(item for item in experiment.LAYOUTS if item["id"] == name)


def reference_stream(seed, multipliers, layout, last=140, skip=0, mask='low'):
    """Direct numerical reference with independent packing and draw accounting."""
    state = tuple(seed)
    states, spans, values = {0: state}, {}, {}
    draws = 0

    def advance():
        nonlocal draws, state
        state = tuple(a * (value % 65536) + value // 65536
                      for a, value in zip(multipliers, state))
        draws += 1
        states[draws] = state
        return (state[0] % 65536) * 65536 + state[1] % 65536

    for n in range(1, last + 1):
        bits = layout["bits"]
        size = (n + bits - 1) // bits if layout["width"] == "ceil_n" else 256 // bits
        spans[n] = (draws + 1, draws + size)
        units = []
        for _ in range(size):
            word = advance()
            projection = layout["projection"]
            if projection == "bswap32":
                unit = int.from_bytes(word.to_bytes(4, "little"), "big")
            elif projection.startswith("high"):
                # Math.random scaling by powers of two is exact for 32-bit U.
                unit = int((word / 2**32) * 2**bits)
            elif projection.startswith("low"):
                unit = word % 2**bits
            else:
                unit = word
            units.append(format(unit, f"0{bits}b"))
        if layout["order"] == "little":
            units.reverse()
        raw = int("".join(units), 2)
        retained = (raw % 2**(n - 1) if mask == 'low'
                    else int(format(raw, '0256b')[:n - 1] or '0', 2))
        values[n] = 2**(n - 1) + retained
        for _ in range(skip):
            advance()
    return values, states, spans


class HistoricalVectors(unittest.TestCase):
    def test_javascript_source_equivalent_vectors(self):
        fixture = json.loads((HERE / "fixtures/reference_vectors.json").read_text())
        self.assertGreaterEqual(len(fixture["vectors"]), 10)
        for vector in fixture["vectors"]:
            state = tuple(vector["initial_states"])
            for expected in vector["outputs"]:
                with self.subTest(multipliers=vector["multipliers"],
                                  seed=vector["initial_states"], step=expected["step"]):
                    state = experiment.step(state, vector["multipliers"])
                    word = experiment.output(state)
                    self.assertEqual(state, (expected["state0"], expected["state1"]))
                    self.assertEqual(word, expected["uint32"])
                    self.assertEqual(word / 2**32, expected["math_random"])
                    self.assertEqual(experiment.project(word, "high8"), expected["top_byte"])
                    self.assertEqual(experiment.project(word, "high16"), expected["top_16"])


class CanonicalStateProof(unittest.TestCase):
    def test_all_uint32_states_enter_canonical_interval_after_two_draws(self):
        # Integer SMT proves the universal claim by refuting a counterexample;
        # this is not a random sampling test or a duplicate of the inverse code.
        for a in sorted({a for v in experiment.VARIANTS for a in v["multipliers"]}):
            with self.subTest(multiplier=a):
                state = z3.Int("arbitrary_initial_uint32")
                step = lambda value: a * (value % 65536) + value / 65536
                solver = z3.Solver()
                solver.set(timeout=10000)
                solver.add(state >= 0, state < 2**32,
                           z3.Or(step(step(state)) < 0, step(step(state)) > a * 65536 - 1))
                self.assertEqual(solver.check(), z3.unsat)
                # One draw is insufficient for the maximum uint32 seed.
                maximum_first = a * 65535 + 65535
                self.assertGreater(maximum_first, a * 65536 - 1)

    def test_modular_inverse_identity_for_every_canonical_interior_state(self):
        for a in sorted({a for v in experiment.VARIANTS for a in v["multipliers"]}):
            with self.subTest(multiplier=a):
                modulus = a * 65536 - 1
                state = z3.Int("canonical_interior_state")
                next_state = a * (state % 65536) + state / 65536
                solver = z3.Solver()
                solver.set(timeout=10000)
                solver.add(state > 0, state < modulus,
                           z3.Or(next_state <= 0, next_state >= modulus,
                                 a * state - next_state != modulus * (state / 65536)))
                self.assertEqual(solver.check(), z3.unsat)
                # The identity proves f(x) == a*x (mod p) throughout the
                # interior; a*65536 == 1 (mod p) proves the implemented inverse.
                self.assertEqual((a * 65536) % modulus, 1)

    def test_inverse_identity_interior_and_fixed_points(self):
        for variant in experiment.VARIANTS:
            multipliers = variant["multipliers"]
            endpoints = tuple(a * 65536 - 1 for a in multipliers)
            for state in ((0, 0), endpoints, (0, endpoints[1]), (1, 1), (65535, 65536),
                          tuple(p - 1 for p in endpoints), (1234567, 987654321)):
                for draws in (0, 1, 2, 7, 257):
                    with self.subTest(variant=variant["id"], state=state, draws=draws):
                        previous = experiment.rewind_canonical(state, multipliers, draws)
                        self.assertIsNotNone(previous)
                        forward = previous
                        for _ in range(draws):
                            forward = experiment.step(forward, multipliers)
                        self.assertEqual(forward, state)
                        if state == endpoints:
                            self.assertEqual(previous, endpoints)
                for component in range(2):
                    invalid = list(state)
                    invalid[component] = endpoints[component] + 1
                    self.assertIsNone(experiment.rewind_canonical(invalid, multipliers, 2))
            self.assertIsNone(experiment.rewind_canonical((-1, 0), multipliers, 1))

    def test_transient_seed_has_observationally_equivalent_canonical_seed(self):
        for variant in experiment.VARIANTS:
            multipliers = variant["multipliers"]
            initial = (2**32 - 1, 2**32 - 1)
            after_two = experiment.step(experiment.step(initial, multipliers), multipliers)
            canonical = experiment.rewind_canonical(after_two, multipliers, 2)
            self.assertNotEqual(canonical, initial)
            # Draw 1 is intentionally not constrained: observation 1 reveals no bits.
            for layout in experiment.LAYOUTS:
                with self.subTest(variant=variant["id"], layout=layout["id"]):
                    self.assertEqual(experiment.generate(initial, multipliers, layout),
                                     experiment.generate(canonical, multipliers, layout))


class PackingAndReplay(unittest.TestCase):
    def test_every_layout_against_independent_stream_and_draw_index(self):
        for layout in experiment.LAYOUTS:
            for skip in (0, 1, 8):
                with self.subTest(layout=layout["id"], skip=skip):
                    expected, states, spans = reference_stream(SEED, MULTIPLIERS, layout, skip=skip)
                    self.assertEqual(experiment.generate(SEED, MULTIPLIERS, layout, last=max(expected), skip=skip), expected)
                    self.assertEqual(expected[1], 1)
                    self.assertEqual(experiment.observed_units(1, 1, layout), [])
                    for n in (2, 8, 9, 16, 17, 32, 33, 64, 65, 70, 75, 135):
                        observations = experiment.observed_units(n, expected[n], layout)
                        self.assertEqual(sum(bits for _, bits, _ in observations), n - 1)
                        first = observations[0][0]
                        draw = spans[n][0] + first
                        self.assertEqual(experiment.anchor_draw(n, first, layout, skip), draw)
                        self.assertGreaterEqual(draw, 2)
                    obs = experiment.observed_units(135, expected[135], layout)
                    anchor = states[spans[135][0] + obs[0][0]]
                    selected = {n: expected[n] for n in OBSERVED_WIDTHS}
                    replay, generated = experiment.replay_candidate(
                        anchor, MULTIPLIERS, layout, 135, obs[0][0], selected, skip)
                    self.assertTrue(replay["compatible"])
                    self.assertEqual(replay["compared_retained_bits"], 3767)
                    self.assertEqual(experiment.generate(tuple(int(x, 16) for x in replay["canonical_initial_state"]), MULTIPLIERS, layout, last=140, skip=skip)[140], expected[140])
                    selected[70] ^= 1
                    negative, _ = experiment.replay_candidate(
                        anchor, MULTIPLIERS, layout, 135, obs[0][0], selected, skip)
                    self.assertFalse(negative["compatible"])
                    self.assertEqual(negative["first_mismatch"], 70)

    def test_symbolic_constraints_agree_with_numeric_at_bit_boundaries(self):
        for layout in experiment.LAYOUTS:
            expected, states, spans = reference_stream(SEED, MULTIPLIERS, layout, skip=1)
            for n in (2, 9, 17, 33, 65, 135):
                with self.subTest(layout=layout["id"], observation=n):
                    solver, anchor, obs = experiment.make_solver(n, expected[n], MULTIPLIERS, layout, 5000)
                    correct = states[spans[n][0] + obs[0][0]]
                    solver.add(*(anchor[i] == correct[i] for i in range(2)))
                    self.assertEqual(solver.check(), z3.sat)
                    corrupted, wrong_anchor, _ = experiment.make_solver(
                        n, expected[n] ^ 1, MULTIPLIERS, layout, 5000)
                    corrupted.add(*(wrong_anchor[i] == correct[i] for i in range(2)))
                    self.assertEqual(corrupted.check(), z3.unsat)

    def test_recovered_active_anchor_is_unique_and_predicts_future(self):
        for name in ("fixed256_word32_big", "fixed256_high16_little"):
            layout = layout_named(name)
            expected, states, spans = reference_stream(SEED, MULTIPLIERS, layout, skip=8)
            solver, anchor, obs = experiment.make_solver(65, expected[65], MULTIPLIERS, layout, 20000)
            self.assertEqual(solver.check(), z3.sat, name)
            recovered = experiment.state_from_model(solver, anchor, layout)
            exact = states[spans[65][0] + obs[0][0]]
            for component in experiment.active_components(layout):
                self.assertEqual(recovered[component], exact[component])
            selected = {n: expected[n] for n in OBSERVED_WIDTHS}
            replay, predicted = experiment.replay_candidate(
                recovered, MULTIPLIERS, layout, 65, obs[0][0], selected, 8)
            self.assertTrue(replay["compatible"])
            self.assertEqual(experiment.generate(tuple(int(x, 16) for x in replay["canonical_initial_state"]), MULTIPLIERS, layout, last=140, skip=8)[140], expected[140])
            experiment.block_state(solver, anchor, recovered, layout)
            self.assertEqual(solver.check(), z3.unsat)


class HighBitRecovery(unittest.TestCase):
    def test_upper_bit_solver_recovers_and_replays_independent_stream(self):
        spec = importlib.util.spec_from_file_location('mwc_high_reference', HERE / 'high_bits.py')
        high = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(high)
        for name in ('fixed256_high16_big', 'fixed256_high16_little'):
            layout = next(c for c in high.LAYOUTS if c['id'] == name)
            expected, states, spans = reference_stream(SEED, MULTIPLIERS, layout,
                                                       last=96, skip=1, mask='high')
            solver, anchor, observations = high.make_solver(65, expected[65], MULTIPLIERS,
                                                            layout, 20000)
            solver.add(z3.ULE(anchor[0], MULTIPLIERS[0] * 65536 - 1))
            self.assertEqual(solver.check(), z3.sat)
            state = high.state_from_model(solver, anchor, layout)
            exact = states[spans[65][0] + observations[0][0]]
            self.assertEqual(state[0], exact[0])
            fit = {n: expected[n] for n in range(1, 66)}
            replay, _ = high.replay_candidate(state, MULTIPLIERS, layout, 65,
                                              observations[0][0], fit, 1)
            self.assertTrue(replay['compatible'])
            initial = tuple(int(x, 16) for x in replay['canonical_initial_state'])
            self.assertEqual(high.generate(initial, MULTIPLIERS, layout, last=96, skip=1)[96],
                             expected[96])
            high.block_state(solver, anchor, state, layout)
            self.assertEqual(solver.check(), z3.unsat)
