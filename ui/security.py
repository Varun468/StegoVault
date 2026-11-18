from __future__ import annotations

import streamlit as st

from database.storage import is_history_enabled, recent_security_events
from ui.common import page_heading


def render() -> None:
    page_heading("Security center", "Cryptographic design and local security events.")
    st.subheader("Encryption")
    st.markdown(
        """
        - **Data encryption:** AES-256-GCM with a fresh 96-bit random nonce per
          encryption and authenticated ciphertext.
        - **Password derivation:** Scrypt (`N=32768`, `r=8`, `p=1`, 16-byte
          random salt), followed by HKDF-SHA-256 domain separation.
        - **Separate keys:** encryption, embedding permutation, and header
          authentication keys are independently derived.
        - **Payload integrity:** AES-GCM authentication; the clear, versioned
          header has a separate HMAC-SHA-256 tag.
        - **Pixel ordering:** an AES-based Feistel permutation indexes RGB LSBs;
          it permutes positions only and is not a custom data-encryption cipher.
        """
    )
    st.warning(
        "LSB steganography is not undetectable. Re-encoding, resizing, or editing "
        "the carrier can destroy the payload. Use a strong, unique password."
    )
    st.subheader("Local security controls")
    st.write(
        "The application is configured for IPv4 loopback only; the app code "
        "does not call remote APIs. Passwords and plaintext payloads are not "
        "written to SQLite."
    )
    if not is_history_enabled():
        st.info("Security event history is disabled in Settings.")
        return
    st.subheader("Security event history")
    events = recent_security_events()
    if events:
        st.dataframe(events, use_container_width=True, hide_index=True)
    else:
        st.info("No local security events have been recorded.")
