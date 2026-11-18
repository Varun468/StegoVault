from __future__ import annotations

import io
from dataclasses import dataclass

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError
from skimage.metrics import structural_similarity

from core.encoder import EmbeddingStats, embedding_capacity
from security.validation import MAX_IMAGE_PIXELS


@dataclass(frozen=True)
class ImageAnalysis:
    width: int
    height: int
    original_size_bytes: int
    modified_size_bytes: int
    psnr_db: float
    ssim: float
    capacity: EmbeddingStats


def _decode_rgb(data: bytes) -> np.ndarray:
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format not in {"PNG", "BMP", "JPEG", "WEBP"}:
                raise ValueError("Unsupported image format.")
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image exceeds the 40-megapixel processing limit.")
            image.load()
            return np.asarray(image.convert("RGB"), dtype=np.uint8)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Image is malformed or cannot be decoded.") from exc


def analyze_image_pair(original: bytes, modified: bytes) -> ImageAnalysis:
    original_rgb = _decode_rgb(original)
    modified_rgb = _decode_rgb(modified)
    if original_rgb.shape != modified_rgb.shape:
        raise ValueError("Images must have identical dimensions for comparison.")
    psnr = (
        float("inf")
        if np.array_equal(original_rgb, modified_rgb)
        else float(cv2.PSNR(original_rgb, modified_rgb))
    )
    ssim = float(
        structural_similarity(
            original_rgb, modified_rgb, channel_axis=2, data_range=255
        )
    )
    capacity = embedding_capacity(original)
    height, width, _ = original_rgb.shape
    return ImageAnalysis(
        width=width,
        height=height,
        original_size_bytes=len(original),
        modified_size_bytes=len(modified),
        psnr_db=psnr,
        ssim=ssim,
        capacity=capacity,
    )
