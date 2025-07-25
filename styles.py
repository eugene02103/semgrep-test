import streamlit as st

def apply_main_styles():
    """메인 CSS 스타일을 적용합니다."""
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .severity-high {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 10px;
        margin: 5px 0;
    }
    .severity-medium {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 10px;
        margin: 5px 0;
    }
    .severity-low {
        background-color: #f3e5f5;
        border-left: 4px solid #9c27b0;
        padding: 10px;
        margin: 5px 0;
    }
    .code-block {
        background-color: #f5f5f5;
        border-radius: 5px;
        padding: 10px;
        font-family: monospace;
        margin: 10px 0;
    }
    .settings-section {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
    }
    .credential-info {
        background-color: #fff;
        border-radius: 30px;
        padding: 15px;
        margin: 30px 0 30px 0;
        box-shadow: 0 0 15px rgba(234, 231, 174, 1);
    }
    .credential-expired {
        background-color: #fff;
        border-radius: 30px;
        padding: 15px;
        margin: 30px 0 30px 0;
        box-shadow: 0 0 15px rgba(219, 138, 138, 1);
    }
    .countdown-warning {
        color: #ff9800 !important;
        font-weight: bold !important;
        animation: blink 1s linear infinite;
    }
    @keyframes blink {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    .ai-section {
        background-color: #f0f8ff;
        border: 1px solid #4a90e2;
        border-radius: 10px;
        padding: 20px;
        margin: 15px 0;
    }
    .ai-fix-card {
        background-color: #f8f9ff;
        border-left: 4px solid #4a90e2;
        padding: 15px;
        margin: 10px 0;
        border-radius: 5px;
    }
    .rounded-box {
        border: 2px solid #f7f7f7;
        border-radius: 30px;
        padding: 16px;
        text-align: center;
        background-color: #fff;
        box-shadow: 3px 3px 7px rgba(0,0,0,0.08);
        margin: 0 10px;
    }
    .rounded-box h4 {
        margin-bottom: 0.6rem;
    }
    </style>
    """, unsafe_allow_html=True)