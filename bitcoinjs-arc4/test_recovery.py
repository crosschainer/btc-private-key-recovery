"""Synthetic state enumeration, replay rejection, and input validation."""
import unittest
import recovery as e
import pipeline as p

class RecoveryTests(unittest.TestCase):
    def recipe(self):
        return {'id': 'test', 'multiplier': 18273, 'times_ms': [0, 1],
                'extra_seed_ints': [], 'stream_offset': 0, 'rationale': 'Synthetic test only'}

    def values(self):
        return p.observations(e.seed_at(self.recipe(), 2), (32, 48, 64, 75, 95))

    def test_unknown_state_and_replay_corruption(self):
        values = self.values()
        found = e.scan_interval(self.recipe(), 1, 4, values)
        self.assertEqual(found['matches'], [{'state_after_first_call': 2, 'config': e.configurations()[0]}])
        values[95] ^= 1
        rejected = e.scan_interval(self.recipe(), 1, 4, values)
        self.assertEqual(rejected['fit_survivors'], 1)
        self.assertEqual(rejected['matches'], [])

    def test_domains_and_recipe_validation(self):
        for begin, end in ((0, 2), (2, 2), (1, 1197586592), (True, 2)):
            with self.assertRaises(ValueError):
                e.scan_interval(self.recipe(), begin, end, self.values())
        for change in ({'times_ms': [0]}, {'stream_offset': -1}, {'multiplier': 7}, {'rationale': ''}):
            with self.assertRaises(ValueError):
                e.validate_recipes([self.recipe() | change])
        with self.assertRaises(ValueError):
            e.validate_recipes([self.recipe(), self.recipe()])
        with self.assertRaises(ValueError):
            e.check_seed(e.seed_at(self.recipe(), 2), self.values(), e.configurations(), (1, 32, 48))
