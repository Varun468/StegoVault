from __future__ import annotations

import streamlit as st


def apply_styles() -> None:
    st.markdown(
        """
        <style>
        .stApp { background: #0b1120; color: #e5e7eb; }
        [data-testid="stSidebar"] { background: #111827; }
        [data-testid="stMetric"] {
            background: #151f32; border: 1px solid #25334b;
            padding: 1rem; border-radius: 0.8rem;
        }
        div.stButton > button, div.stDownloadButton > button {
            border-radius: 0.55rem; font-weight: 600;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def page_heading(title: str, subtitle: str) -> None:
    st.title(title)
    st.caption(subtitle)
