from __future__ import annotations

import io

import streamlit as st
from PIL import Image, UnidentifiedImageError

from core.decoder import reveal_data
from core.payload_manager import PayloadKind
from database.storage import record_operation, record_security_event
from ui.common import page_heading


def render() -> None:
    page_heading(
        "Extract information",
        "Authenticate and decrypt a payload from a lossless StegoVault PNG or BMP.",
    )
    image_file = st.file_uploader(
        "Stego image", type=["png", "bmp"], key="stego_upload"
    )
    password = st.text_input("Password", type="password", key="extract_password")

    if st.button("Detect and extract", type="primary", use_container_width=True):
        progress = st.progress(0, text="Checking image…")
        try:
            if image_file is None:
                raise ValueError("Choose a PNG or BMP image.")
            if not password:
                raise ValueError("Enter the password.")
            progress.progress(20, text="Authenticating the payload header…")
            stego_bytes = image_file.getvalue()
            payload = reveal_data(stego_bytes, password)
            progress.progress(100, text="Authenticated and decrypted.")
            with Image.open(io.BytesIO(stego_bytes)) as carrier:
                width, height = carrier.size
            record_operation(
                "extract",
                payload.kind.name.lower(),
                len(payload.data),
                width,
                height,
            )
            record_security_event("payload_extracted")
            st.success("Payload authenticated and decrypted.")
            st.write(f"Type: **{payload.kind.name.title()}** · Size: **{len(payload.data):,} bytes**")
            if payload.kind == PayloadKind.TEXT:
                text = payload.data.decode("utf-8")
                if len(text) <= 20_000:
                    st.text_area("Extracted text", text, height=220, disabled=True)
                st.download_button(
                    "Download text",
                    data=payload.data,
                    file_name="stegovault_message.txt",
                    mime="text/plain; charset=utf-8",
                )
            else:
                filename = payload.filename or "extracted_file"
                st.download_button(
                    f"Download {filename}",
                    data=payload.data,
                    file_name=filename,
                    mime="application/octet-stream",
                    use_container_width=True,
                )
                if payload.kind == PayloadKind.IMAGE:
                    try:
                        with Image.open(io.BytesIO(payload.data)) as hidden_image:
                            hidden_image.load()
                            st.image(hidden_image, caption=filename)
                    except (UnidentifiedImageError, OSError) as exc:
                        raise ValueError("The authenticated image payload is malformed.") from exc
        except ValueError as exc:
            record_security_event("authentication_failed")
            st.error(str(exc))
        finally:
            progress.empty()
