"""Independent replay and boundary controls for the exact state solver."""
import unittest
import screen
import exact_solver
from reference import LegacyRandom


class ExactTests(unittest.TestCase):
    def test_fixed_state_replays_through_recurrence(self):
        config = screen.configs()[0]
        values = screen.generate(LegacyRandom.from_state([0] * 55), range(1, 9), config)
        result = exact_solver.solve(values, config, fixed_first55=[0] * 55)
        self.assertEqual(result['status'], 'sat_exact_replay')
        self.assertTrue(result['replay_matches'])

    def test_corrupted_observation_contradicts_fixed_state(self):
        config = screen.configs()[0]
        values = screen.generate(LegacyRandom.from_state([0] * 55), range(1, 9), config)
        values[8] ^= 1
        result = exact_solver.solve(values, config, fixed_first55=[0] * 55)
        self.assertEqual(result['status'], 'excluded')

    def test_unconstrained_words_have_replayable_model_values(self):
        config = next(c for c in screen.configs()
                      if c['count'] == 'ceil_n' and c['skip'] == 0)
        result = exact_solver.solve({1: 1, 2: 3}, config)
        self.assertEqual(result['status'], 'sat_exact_replay')
        self.assertEqual(len(result['first55_outputs']), 55)

    def test_invalid_initial_output_words_rejected(self):
        config = screen.configs()[0]
        for words in ([0] * 54, [0] * 54 + [(1 << 31) - 1]):
            with self.assertRaises(ValueError):
                exact_solver.solve({1: 1, 2: 3}, config, fixed_first55=words)


if __name__ == '__main__':
    unittest.main()
