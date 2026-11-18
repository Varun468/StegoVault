import io
import unittest

import numpy as np
from PIL import Image

from analysis.image_quality import analyze_image_pair


def image_bytes(size: tuple[int, int], color: tuple[int, int, int]) -> bytes:
    output = io.BytesIO()
    Image.new("RGB", size, color).save(output, format="PNG")
    return output.getvalue()


class ImageQualityTests(unittest.TestCase):
    def test_identical_images_have_infinite_psnr_and_unit_ssim(self) -> None:
        image = image_bytes((32, 32), (20, 40, 60))
        result = analyze_image_pair(image, image)

        self.assertEqual(result.psnr_db, float("inf"))
        self.assertAlmostEqual(result.ssim, 1.0)
        self.assertGreater(result.capacity.capacity_bytes, 0)

    def test_modified_pixels_reduce_quality_metrics(self) -> None:
        original = np.full((32, 32, 3), 100, dtype=np.uint8)
        modified = original.copy()
        modified[:8, :8] = 0
        first, second = io.BytesIO(), io.BytesIO()
        Image.fromarray(original).save(first, format="PNG")
        Image.fromarray(modified).save(second, format="PNG")

        result = analyze_image_pair(first.getvalue(), second.getvalue())

        self.assertLess(result.psnr_db, float("inf"))
        self.assertLess(result.ssim, 1.0)

    def test_different_dimensions_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "identical dimensions"):
            analyze_image_pair(
                image_bytes((32, 32), (0, 0, 0)),
                image_bytes((24, 32), (0, 0, 0)),
            )

    def test_invalid_images_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "malformed"):
            analyze_image_pair(b"bad", b"bad")


if __name__ == "__main__":
    unittest.main()
