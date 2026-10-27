"""State recovery and contradiction checks against a separate uint32 C oracle."""
import unittest
import recovery as r
from native_reference import NativeReference, independent_values, verify_certificate


class RecoveryTests(unittest.TestCase):
    def test_all_layouts_recover_state_and_predict_new_outputs(self):
        state = 0x0123456789ABCDEFFEDCBA9876543210
        with NativeReference() as native:
            for config in r.configs():
                with self.subTest(layout=config['id']):
                    values = independent_values(native, state, range(1, 97), config)
                    fit = {n: values[n] for n in range(1, 41)}
                    result = r.solve(fit, config)
                    self.assertTrue(result['compatible'])
                    self.assertEqual(result['rank'], 128)
                    recovered = int(result['initial_state_hex'], 16)
                    self.assertEqual(recovered, state)
                    self.assertEqual(r.predict(recovered, [64, 96], config),
                                     {n: values[n] for n in (64, 96)})

    def test_independently_verified_contradiction(self):
        config = r.configs()[0]
        with NativeReference() as native:
            values = independent_values(native, 123456789, range(1, 41), config)
            values[40] ^= 1
            result = r.solve(values, config)
            self.assertFalse(result['compatible'])
            checked = verify_certificate(native, config, values,
                                         result['first_conflict']['certificate'])
            self.assertTrue(checked['verified'])

    def test_zero_state_and_underdetermined_counts(self):
        config = r.configs()[0]
        result = r.solve({1: 1}, config)
        self.assertTrue(result['compatible'])
        self.assertEqual(result['surviving_states'], (1 << 128) - 1)
        zero = r.predict(0, range(1, 41), config)
        self.assertFalse(r.solve(zero, config)['compatible'])


if __name__ == '__main__':
    unittest.main()
