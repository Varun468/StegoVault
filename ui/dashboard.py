from __future__ import annotations

import streamlit as st

from database.storage import (
    get_dashboard_stats,
    is_history_enabled,
    recent_operations,
    storage_info,
)
from ui.common import page_heading


def render() -> None:
    page_heading("Dashboard", "Your local workspace at a glance.")
    stats = get_dashboard_stats()
    files = stats["total_files_processed"]
    messages = stats["total_messages_hidden"]
    operations = stats["total_operations"]

    left, middle, right = st.columns(3)
    left.metric("Files processed", files)
    middle.metric("Messages hidden", messages)
    right.metric("Recorded operations", operations)

    st.subheader("Security status")
    st.success("Local-only mode · AES-256-GCM · Scrypt · no telemetry")
    st.caption(
        "Steganography can be detected by analysis and does not guarantee "
        "that hidden data is undiscoverable."
    )

    info = storage_info()
    st.subheader("Local storage")
    storage_columns = st.columns(3)
    storage_columns[0].metric(
        "History", "Enabled" if info["history_enabled"] else "Disabled"
    )
    storage_columns[1].metric("Database size", f"{info['bytes']:,} bytes")
    storage_columns[2].metric("Security events", info["security_events"])
    st.caption(f"SQLite file: `{info['path']}`")

    st.subheader("Recent local operations")
    if not is_history_enabled():
        st.info("Local history is disabled in Settings.")
        return
    records = recent_operations(10)
    if not records:
        st.info("No operations have been recorded yet.")
        return
    st.dataframe(records, use_container_width=True, hide_index=True)
