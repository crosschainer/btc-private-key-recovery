#!/usr/bin/env python3
"""Independent set arithmetic, byte mapping, and synthetic domain-screen controls."""
import hashlib
import random
import unittest

import screen as e
from reference import LegacyRandom, MODULUS


class ScreenTests(unittest.TestCase):
    def test_modular_wrap_projection_exhaustive(self):
        # Exhaust all true state pairs in a small Mersenne-modulus analogue.
        for a in range(31):
            for b in range(31):
                x = (a - b) % 31
                self.assertIn((x - a + b) % 8, (0, 7))
                self.assertEqual(x & 7, ((a & 7) - (b & 7) - int(a < b)) % 8)

    def test_set_arithmetic_against_brute_force(self):
        rng = random.Random(80555)
        fixtures = [(set(), {0}), ({0}, set()), ({255}, {0, 1}),
                    (set(range(256)), {1}), ({1}, set(range(256)))]
        for _ in range(250):
            fixtures.append((set(rng.sample(range(256), rng.randrange(1, 30))),
                             set(rng.sample(range(256), rng.randrange(1, 30)))))
        for left, right in fixtures:
            lbits, rbits = sum(1 << x for x in left), sum(1 << x for x in right)
            for subtract in (False, True):
                expected = {(a - b if subtract else a + b) % 256 for a in left for b in right}
                self.assertEqual(set(e.members(e.combine(lbits, rbits, subtract))), expected)
            self.assertEqual(set(e.members(e.rotate(lbits, -1))), {(x - 1) % 256 for x in left})

    def test_every_layout_maps_back_to_reference_bytes(self):
        wanted = set(range(1, 71)) | set(range(75, 136, 5))
        for config in e.configs():
            with self.subTest(config=config["id"]):
                values = e.generate(LegacyRandom(123456), wanted, config)
                length, obs = e.observations(values, config)
                stream = LegacyRandom(123456).next_bytes(length)
                self.assertEqual(sum(mask.bit_count() for mask, _ in obs.values()), 3767)
                for draw, (mask, value) in obs.items():
                    self.assertEqual(stream[draw] & mask, value)

    def test_arbitrary_states_and_stream_offsets_survive_all_layouts(self):
        wanted = set(range(1, 71)) | set(range(75, 136, 5))
        words = [int.from_bytes(hashlib.sha256(f"dotnet-control/{i}".encode()).digest(), "big") % MODULUS
                 for i in range(55)]
        for config in e.configs():
            for kind in ("zero", "maximum", "hashed-offset"):
                with self.subTest(config=config["id"], kind=kind):
                    state = [0] * 55 if kind == "zero" else [MODULUS - 1] * 55 if kind == "maximum" else words
                    rng = LegacyRandom.from_state(state)
                    if kind == "hashed-offset":
                        rng.next_bytes(137)
                    values = e.generate(rng, wanted, config)
                    self.assertEqual(e.solve(values, config)["status"], "survives_necessary_screen")

    def test_resource_limit_is_never_exclusion(self):
        config = e.configs()[0]
        values = e.generate(LegacyRandom(1), set(range(1, 20)), config)
        self.assertEqual(e.solve(values, config, max_visits=0)["status"], "inconclusive_limit")

    def test_corruption_produces_auditable_contradiction(self):
        # A wide contiguous synthetic output makes a deliberately wrong byte observable.
        config = e.configs()[0]
        values = e.generate(LegacyRandom(777), set(range(1, 136)), config)
        values[130] ^= 127
        result = e.solve(values, config)
        self.assertEqual(result["status"], "excluded")
        self.assertEqual(result["trace"][-1]["after"], "0x0")
        import audit
        self.assertEqual(audit.audit_result(values, config, result)["status"], "excluded")
        result["trace"][0]["after"] = "0x0"
        with self.assertRaises(audit.AuditError):
            audit.audit_result(values, config, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
