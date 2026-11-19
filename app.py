from datetime import datetime
import pandas as pd
import streamlit as st

from analyzer import analyze_url
from scorer import calculate_risk

st.set_page_config(page_title="Phishing URL Analyzer", layout="wide")

# Session state setup
if "history" not in st.session_state:
    st.session_state["history"] = []
if "selected_url" not in st.session_state:
    st.session_state["selected_url"] = ""
if "trigger_scan" not in st.session_state:
    st.session_state["trigger_scan"] = False


def set_sample_url(url: str):
    st.session_state["selected_url"] = url
    st.session_state["trigger_scan"] = True


with st.sidebar:
    st.title("About Project")
    st.write(
        "This tool inspects URLs for lexical and structural features commonly associated with phishing attacks."
    )
    st.markdown("---")
    st.write("**Git Branches**")
    st.write("- main: Integrated branch")
    st.write("- feature/url-analysis: URL parser")
    st.write("- feature/risk-scoring: Scoring algorithm")
    st.write("- feature/dashboard: Streamlit dashboard")

st.title("Phishing URL Analyzer")
st.write("Enter a URL below or click one of the quick test presets to calculate its risk score.")

st.write("**Quick Test Presets:**")
btn_col1, btn_col2, btn_col3 = st.columns(3)
with btn_col1:
    st.button("Safe URL (Google)", on_click=set_sample_url, args=("https://www.google.com",), use_container_width=True)
with btn_col2:
    st.button("Medium Risk (HTTP + TLD)", on_click=set_sample_url, args=("http://account-update-portal.xyz/login",), use_container_width=True)
with btn_col3:
    st.button("High Risk (IP + Redirect + Keywords)", on_click=set_sample_url, args=("http://192.168.1.100//login.php?user=admin@paypal.com&verify=urgent&password=123",), use_container_width=True)

target_url = st.text_input(
    "Target URL:",
    value=st.session_state["selected_url"],
    placeholder="e.g. http://example.com/login",
)

analyze_btn = st.button("Analyze URL", type="primary", use_container_width=True)

should_run = analyze_btn or st.session_state["trigger_scan"]
st.session_state["trigger_scan"] = False

active_url = target_url.strip()

if should_run:
    if not active_url:
        st.warning("Please enter a valid URL.")
    else:
        features = analyze_url(active_url)
        result = calculate_risk(features)

        score = result["risk_score"]
        level = result["risk_level"]
        explanations = result["explanations"]
        triggered = result["triggered_count"]

        # Save to history avoiding consecutive duplicates
        entry = {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "URL": active_url,
            "Risk Score": score,
            "Risk Level": level,
            "Triggered Checks": triggered,
        }
        if not st.session_state["history"] or st.session_state["history"][-1]["URL"] != active_url:
            st.session_state["history"].append(entry)

        st.subheader("Analysis Results")

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Risk Score", f"{score} / 100")
        with m2:
            st.metric("Risk Level", level)
        with m3:
            st.metric("Flagged Rules", f"{triggered} / 9")
        with m4:
            st.metric("Domain", features["domain"] if features["domain"] else "None")

        st.progress(score / 100)

        if level == "Low":
            st.success(f"Risk Level: Low ({score}/100) - No major suspicious patterns found.")
        elif level == "Medium":
            st.warning(f"Risk Level: Medium ({score}/100) - Some suspicious indicators detected. Proceed with caution.")
        else:
            st.error(f"Risk Level: High ({score}/100) - Strong phishing indicators detected.")

        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Risk Explanations")
            for exp in explanations:
                st.write(f"- {exp}")

        with col_right:
            st.subheader("Heuristic Breakdown")
            breakdown_rows = [
                {
                    "Rule": "Protocol",
                    "Value": "HTTPS" if features["uses_https"] else "HTTP",
                    "Status": "Pass" if features["uses_https"] else "Flagged",
                    "Impact": "0 pts" if features["uses_https"] else "+15 pts",
                },
                {
                    "Rule": "IP Address Host",
                    "Value": features["domain"] if features["has_ip_address"] else "Domain Name",
                    "Status": "Flagged" if features["has_ip_address"] else "Pass",
                    "Impact": "+30 pts" if features["has_ip_address"] else "0 pts",
                },
                {
                    "Rule": "URL Length (> 75)",
                    "Value": f"{features['url_length']} chars",
                    "Status": "Flagged" if features["is_long_url"] else "Pass",
                    "Impact": "+10 pts" if features["is_long_url"] else "0 pts",
                },
                {
                    "Rule": "Subdomains (> 2)",
                    "Value": f"{features['subdomain_count']} subdomain(s)",
                    "Status": "Flagged" if features["excessive_subdomains"] else "Pass",
                    "Impact": "+15 pts" if features["excessive_subdomains"] else "0 pts",
                },
                {
                    "Rule": "Keywords",
                    "Value": ", ".join(features["suspicious_keywords"]) if features["suspicious_keywords"] else "None",
                    "Status": "Flagged" if features["suspicious_keywords"] else "Pass",
                    "Impact": f"+{min(25, len(features['suspicious_keywords']) * 10)} pts" if features["suspicious_keywords"] else "0 pts",
                },
                {
                    "Rule": "At Symbol (@)",
                    "Value": "Present" if features["has_at_symbol"] else "Absent",
                    "Status": "Flagged" if features["has_at_symbol"] else "Pass",
                    "Impact": "+20 pts" if features["has_at_symbol"] else "0 pts",
                },
                {
                    "Rule": "Double Slash Redirect (//)",
                    "Value": "Present in Path" if features["has_double_slash_redirect"] else "Absent",
                    "Status": "Flagged" if features["has_double_slash_redirect"] else "Pass",
                    "Impact": "+10 pts" if features["has_double_slash_redirect"] else "0 pts",
                },
                {
                    "Rule": "Domain Hyphen (-)",
                    "Value": "Present" if features["has_hyphen_in_domain"] else "Absent",
                    "Status": "Flagged" if features["has_hyphen_in_domain"] else "Pass",
                    "Impact": "+5 pts" if features["has_hyphen_in_domain"] else "0 pts",
                },
                {
                    "Rule": "Suspicious TLD",
                    "Value": "." + features["domain"].split(".")[-1] if "." in features["domain"] else "None",
                    "Status": "Flagged" if features["suspicious_tld"] else "Pass",
                    "Impact": "+15 pts" if features["suspicious_tld"] else "0 pts",
                },
            ]
            st.dataframe(pd.DataFrame(breakdown_rows), use_container_width=True, hide_index=True)

st.markdown("---")
st.subheader("Scan History")

if st.session_state["history"]:
    history_df = pd.DataFrame(st.session_state["history"])
    st.dataframe(history_df, use_container_width=True, hide_index=True)

    h_col1, h_col2 = st.columns(2)
    with h_col1:
        csv_data = history_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download CSV",
            data=csv_data,
            file_name="url_scan_history.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with h_col2:
        if st.button("Clear History", use_container_width=True):
            st.session_state["history"] = []
            st.rerun()
else:
    st.write("No scan history recorded in this session yet.")
