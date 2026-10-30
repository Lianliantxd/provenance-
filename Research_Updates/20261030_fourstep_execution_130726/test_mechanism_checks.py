import itertools
import math
import unittest

from mechanism_checks import (
    effective_restart, induced_neighbors, shuffle_row, unambiguous_adjacent_pairs,
)


class MechanismTests(unittest.TestCase):
    def test_tied_order_is_invariant_and_does_not_bridge(self):
        for middle in itertools.permutations([(2, 'B'), (2, 'C')]):
            events = [(1, 'A'), *middle, (3, 'D'), (4, 'E')]
            self.assertEqual(unambiguous_adjacent_pairs(events, 10), ([('D', 'E')], 2))

    def test_integer_time_and_identity(self):
        with self.assertRaises(TypeError):
            unambiguous_adjacent_pairs([(1.0, 'a')], 2)
        with self.assertRaises(ValueError):
            unambiguous_adjacent_pairs([(1, 'a'), (2, 'a')], 2)

    def test_gap_is_a_real_limit(self):
        self.assertEqual(unambiguous_adjacent_pairs([(1, 'a'), (100, 'b')], 10), ([], 0))

    def test_row_control_preserves_restart(self):
        original = [0.02, 0.1, 0.3, 0.08]
        for seed in range(25):
            shuffled = shuffle_row(original, seed)
            self.assertEqual(sorted(original), sorted(shuffled))
            self.assertAlmostEqual(effective_restart(original), effective_restart(shuffled))

    def test_fallback_and_empty_channels(self):
        self.assertAlmostEqual(effective_restart([0.55]), 0.56)
        self.assertAlmostEqual(effective_restart([0.55 * 0.25]), 0.89)
        self.assertEqual(effective_restart([]), 1)

    def test_invalid_probabilities_fail(self):
        for weights in [[-1], [math.nan], [0.6, 0.6]]:
            with self.assertRaises(ValueError):
                shuffle_row(weights, 0)

    def test_truncation_does_not_create_edges(self):
        graph = {'a': ['b'], 'b': ['c'], 'c': ['a']}
        self.assertEqual(induced_neighbors(graph, {'a', 'c'}), {'a': [], 'c': ['a']})


if __name__ == '__main__':
    unittest.main()
