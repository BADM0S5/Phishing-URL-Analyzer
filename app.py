import streamlit as st

from analyzer import analyze_url
from scorer import calculate_risk

st.set_page_config(page_title="Phishing URL Analyzer", layout="wide")

st.title("Phishing URL Analyzer")
st.write("Enter a URL below to check for suspicious patterns and calculate its risk score.")

target_url = st.text_input("Target URL:", placeholder="http://example.com/login")
analyze_btn = st.button("Analyze URL", type="primary")

if analyze_btn and target_url.strip():
    features = analyze_url(target_url.strip())
    result = calculate_risk(features)

    score = result["risk_score"]
    level = result["risk_level"]

    st.subheader("Analysis Results")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Risk Score", f"{score} / 100")
    with col2:
        st.metric("Risk Level", level)

    st.progress(score / 100)

    if level == "Low":
        st.success(f"Risk Level: Low ({score}/100) - URL appears safe.")
    elif level == "Medium":
        st.warning(f"Risk Level: Medium ({score}/100) - Some suspicious indicators detected.")
    else:
        st.error(f"Risk Level: High ({score}/100) - Strong phishing indicators detected.")

    st.subheader("Risk Explanations")
    for exp in result["explanations"]:
        st.write(f"- {exp}")
