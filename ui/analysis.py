from __future__ import annotations

import streamlit as st

from analysis.image_quality import analyze_image_pair
from core.encoder import embedding_capacity
from ui.common import page_heading


def render() -> None:
    page_heading(
        "Image analysis",
        "Compare a carrier with its modified image and inspect lossless embedding capacity.",
    )
    original_file = st.file_uploader(
        "Original carrier", type=["png", "bmp", "jpg", "jpeg", "webp"], key="analysis_original"
    )
    modified_file = st.file_uploader(
        "Modified image", type=["png", "bmp"], key="analysis_modified"
    )
    if original_file is not None:
        try:
            capacity = embedding_capacity(original_file.getvalue())
            st.info(
                f"Carrier dimensions: {capacity.width} × {capacity.height} · "
                f"Estimated payload capacity: {capacity.capacity_bytes:,} bytes"
            )
        except ValueError as exc:
            st.error(str(exc))
    if st.button("Compare images", type="primary"):
        if original_file is None or modified_file is None:
            st.error("Choose both the original and modified images.")
            return
        try:
            original_bytes = original_file.getvalue()
            modified_bytes = modified_file.getvalue()
            result = analyze_image_pair(original_bytes, modified_bytes)
            columns = st.columns(4)
            columns[0].metric("PSNR", "∞ dB" if result.psnr_db == float("inf") else f"{result.psnr_db:.2f} dB")
            columns[1].metric("SSIM", f"{result.ssim:.6f}")
            columns[2].metric("Dimensions", f"{result.width} × {result.height}")
            columns[3].metric(
                "Image size",
                f"{result.original_size_bytes:,} → {result.modified_size_bytes:,} bytes",
            )
            stats = st.session_state.get("last_embedding_stats")
            if stats:
                st.metric(
                    "Last embedding utilization",
                    f"{stats['utilization']:.2%}",
                    f"{stats['payload_bytes']:,} bytes embedded",
                )
            left, right = st.columns(2)
            left.image(original_bytes, caption="Original carrier", use_container_width=True)
            right.image(modified_bytes, caption="Modified image", use_container_width=True)
            st.caption(
                "PNG output preserves the modified pixels. Image compression and "
                "LSB changes may still be statistically detectable."
            )
        except ValueError as exc:
            st.error(str(exc))
