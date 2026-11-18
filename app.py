import streamlit as st

from ui import analysis, dashboard, extract, hide, security, settings
from ui.common import apply_styles

st.set_page_config(
    page_title="StegoVault",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

if st.get_option("server.address") != "127.0.0.1":
    st.error("StegoVault requires Streamlit to bind exclusively to 127.0.0.1.")
    st.stop()

apply_styles()
with st.sidebar:
    st.title("🔐 StegoVault")
    st.caption("Advanced Offline Steganography & Encryption")
    page = st.radio(
        "Workspace",
        (
            "Dashboard",
            "Hide Information",
            "Extract Information",
            "Image Analysis",
            "Security Center",
            "Settings",
        ),
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Local-only · 127.0.0.1:8501 · No telemetry")

{
    "Dashboard": dashboard.render,
    "Hide Information": hide.render,
    "Extract Information": extract.render,
    "Image Analysis": analysis.render,
    "Security Center": security.render,
    "Settings": settings.render,
}[page]()
