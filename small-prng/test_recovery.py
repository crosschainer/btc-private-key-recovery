"""Independent small-domain and fixed-vector state recovery checks."""
import unittest
import recovery as r


class RecoveryTests(unittest.TestCase):
    def test_xorshift_known_step_and_recovery_across_layouts(self):
        self.assertEqual(r.xorshift(1, (13, 17, 5), 'LRL'), 270369)
        for layout in r.LAYOUTS:
            config = dict(shifts=(13, 17, 5), orientation='LRL', layout=layout,
                          skip_after_each_key=1)
            values = r.xorshift_values(0x12345678, range(1, 49), config)
            result = r.solve_xorshift(values, config)
            self.assertEqual(result['_state'], 0x12345678, layout['id'])
            values[48] ^= 1
            self.assertFalse(r.solve_xorshift(values, config)['compatible'])

    def test_lcg_projected_recovery_against_full_toy_enumeration(self):
        config = dict(a=13, c=7, state_bits=8, shift=2, output_bits=4)
        for planted in range(0, 256, 31):
            state, values = planted, {}
            for index in range(1, 7):
                for _ in range(3):
                    state = (13 * state + 7) % 256
                values[index] = (state // 4) % 16
            expected = set()
            for initial in range(256):
                value, match = initial, True
                for index in range(1, 7):
                    for _ in range(3):
                        value = (13 * value + 7) % 256
                    match &= (value // 4) % 16 == values[index]
                if match:
                    expected.add(value)
            actual = r.solve_lcg_projection(values, config, 3)
            self.assertEqual(set(actual['_terminal_states']), expected)

    def test_underdetermined_state_count(self):
        config = dict(shifts=(13, 17, 5), orientation='LRL', layout=r.LAYOUTS[0],
                      skip_after_each_key=0)
        result = r.solve_xorshift({1: 1}, config)
        self.assertTrue(result['compatible'])
        self.assertEqual(result['surviving_states'], 1 << 32)


if __name__ == '__main__':
    unittest.main()
