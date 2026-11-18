from __future__ import annotations

import io

import streamlit as st
from PIL import Image, UnidentifiedImageError

from core.encoder import hide_data
from core.payload_manager import PayloadKind
from database.storage import record_operation, record_security_event
from security.validation import validate_payload_size
from ui.common import page_heading


def _read_image_file(uploaded_file: st.runtime.uploaded_file_manager.UploadedFile) -> bytes:
    content = uploaded_file.getvalue()
    try:
        with Image.open(io.BytesIO(content)) as image:
            if image.format not in {"PNG", "BMP"}:
                raise ValueError("Hidden images must be PNG or BMP files.")
            image.verify()
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("The uploaded image file is malformed.") from exc
    return content


def render() -> None:
    page_heading(
        "Hide information",
        "Encrypt locally, then embed the authenticated payload in a lossless PNG.",
    )
    mode_label = st.radio(
        "Payload type", ("Text", "File", "Image"), horizontal=True, key="hide_mode"
    )
    carrier = st.file_uploader(
        "Carrier image (PNG, BMP, JPEG, or WebP)",
        type=["png", "bmp", "jpg", "jpeg", "webp"],
        key="carrier_upload",
    )

    data = b""
    filename: str | None = None
    if mode_label == "Text":
        text = st.text_area(
            "Secret text",
            height=150,
            max_chars=1_000_000,
            help="Unicode is supported. Empty text can also be encrypted.",
            key="secret_text",
        )
        data = text.encode("utf-8")
        kind = PayloadKind.TEXT
    else:
        accepted = ["png", "bmp"] if mode_label == "Image" else None
        uploaded = st.file_uploader(
            "Image to hide (PNG/BMP)" if mode_label == "Image" else "File to hide",
            type=accepted,
            key="payload_upload",
        )
        kind = PayloadKind.IMAGE if mode_label == "Image" else PayloadKind.FILE
        if uploaded is not None:
            filename = uploaded.name
            data = _read_image_file(uploaded) if kind == PayloadKind.IMAGE else uploaded.getvalue()

    password = st.text_input("Password", type="password", key="hide_password")
    confirmation = st.text_input(
        "Confirm password", type="password", key="hide_password_confirmation"
    )
    st.caption("Use a unique, strong password. It cannot be recovered if lost.")

    if st.button("Encrypt and embed", type="primary", use_container_width=True):
        progress = st.progress(0, text="Validating inputs…")
        try:
            if carrier is None:
                raise ValueError("Choose a carrier image.")
            if not password:
                raise ValueError("Enter a password.")
            if password != confirmation:
                raise ValueError("The passwords do not match.")
            if kind != PayloadKind.TEXT and filename is None:
                raise ValueError("Choose a file to hide.")
            validate_payload_size(len(data))
            carrier_bytes = carrier.getvalue()
            progress.progress(15, text="Encrypting payload with AES-GCM…")
            stego_png, stats = hide_data(
                carrier_bytes, data, password, kind, filename
            )
            progress.progress(100, text="Embedding complete.")
            st.session_state["last_stego_png"] = stego_png
            st.session_state["last_carrier_image"] = carrier_bytes
            st.session_state["last_embedding_stats"] = {
                "capacity_bytes": stats.capacity_bytes,
                "payload_bytes": stats.payload_bytes,
                "utilization": stats.utilization,
                "width": stats.width,
                "height": stats.height,
            }
            record_operation(
                "hide", kind.name.lower(), len(data), stats.width, stats.height
            )
            record_security_event("payload_hidden")
            st.success("Payload encrypted and embedded successfully.")
            metrics = st.columns(3)
            metrics[0].metric("Carrier dimensions", f"{stats.width} × {stats.height}")
            metrics[1].metric("Available capacity", f"{stats.capacity_bytes:,} bytes")
            metrics[2].metric("Capacity used", f"{stats.utilization:.2%}")
            st.download_button(
                "Download stego PNG",
                data=stego_png,
                file_name="stegovault_image.png",
                mime="image/png",
                use_container_width=True,
            )
        except ValueError as exc:
            st.error(str(exc))
        finally:
            progress.empty()
