from __future__ import annotations

import streamlit as st

from database.storage import (
    cleanup_temporary_files,
    clear_history,
    is_history_enabled,
    set_history_enabled,
    storage_info,
)
from ui.common import page_heading


def render() -> None:
    page_heading("Settings", "Manage optional local storage and application data.")
    enabled = is_history_enabled()
    new_enabled = st.toggle(
        "Enable local operation and security-event history",
        value=enabled,
        help="Stores operation metadata only. Passwords and payload content are never stored.",
    )
    if new_enabled != enabled:
        set_history_enabled(new_enabled)
        st.success("History setting updated.")

    info = storage_info()
    st.subheader("Storage")
    st.write(f"SQLite database: `{info['path']}`")
    st.write(f"Database size: **{info['bytes']:,} bytes**")
    st.caption("The database stores timestamps, operation types, sizes, and dimensions only.")

    if st.button("Clean app-owned temporary files"):
        removed = cleanup_temporary_files()
        st.success(f"Removed {removed} app-owned temporary file(s).")

    st.subheader("History management")
    if st.button("Clear operation and security history", type="secondary"):
        clear_history()
        st.success("History was cleared.")

    st.subheader("Application")
    st.write("StegoVault · offline-first local application · Python 3.11+")
    st.caption(
        "Uploaded and extracted payloads are processed in memory. Downloads are "
        "initiated by your browser; the app does not write them to disk."
    )
