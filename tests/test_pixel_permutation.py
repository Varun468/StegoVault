import unittest

import numpy as np

from core.pixel_permutation import iter_permuted_positions


class PixelPermutationTests(unittest.TestCase):
    def test_is_reproducible_and_covers_each_index_once(self) -> None:
        key = b"p" * 32
        first = np.concatenate(list(iter_permuted_positions(37, key, 37, 8)))
        second = np.concatenate(list(iter_permuted_positions(37, key, 37, 8)))

        self.assertTrue(np.array_equal(first, second))
        self.assertEqual(set(first.tolist()), set(range(37)))

    def test_different_keys_produce_different_orderings(self) -> None:
        first = np.concatenate(list(iter_permuted_positions(128, b"a" * 32, 128)))
        second = np.concatenate(list(iter_permuted_positions(128, b"b" * 32, 128)))

        self.assertFalse(np.array_equal(first, second))

    def test_prefix_is_stable_across_batch_sizes(self) -> None:
        key = b"q" * 32
        first = np.concatenate(list(iter_permuted_positions(300, key, 73, 11)))
        second = np.concatenate(list(iter_permuted_positions(300, key, 73, 64)))

        self.assertTrue(np.array_equal(first, second))

    def test_rejects_invalid_lengths(self) -> None:
        with self.assertRaises(ValueError):
            list(iter_permuted_positions(0, b"k" * 32, 0))
        with self.assertRaises(ValueError):
            list(iter_permuted_positions(3, b"k" * 32, 4))


if __name__ == "__main__":
    unittest.main()
