"""Bounded seed recovery, search boundaries, and finite-space controls."""
import unittest
import reference as r
import recovery
import seed_space


class RecoveryTests(unittest.TestCase):
    def test_seed_recovery_including_interval_boundaries(self):
        for state in (1, 9, 16):
            seed = r.seed_bytes(state, 16)
            values = r.observations(seed, "m/0'", 0, False, [32, 48, 64])
            result = recovery.scan_interval(1, 17, values)
            self.assertEqual(result['matching_states'], [state])
            self.assertEqual(result['states_checked'], 16)
            self.assertTrue(result['complete_interval'])

    def test_invalid_ranges_are_rejected(self):
        for begin, end in ((0, 1), (2, 2), (3, 2), (1, r.ENGINE_MODULUS + 1), (True, 2)):
            with self.assertRaises(ValueError):
                recovery.scan_interval(begin, end, {32: 1 << 31})

    def test_finite_output_space_controls(self):
        self.assertEqual(seed_space.toy_controls(), 216)


if __name__ == '__main__':
    unittest.main()
