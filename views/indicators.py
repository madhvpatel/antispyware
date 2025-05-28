import streamlit as st
from datetime import datetime
import pandas as pd

# Sample threat indicator data structure
threat_indicators = [
    {
        "name": "Suspicious IP Communication",
        "severity": "High",
        "triggered": True,
        "score": 85,
        "description": [
            "Detected outbound connections to known malicious IP addresses.",
            "Processes invoked: Clash of Clans.",
        ],
        "findings": [
            {
                "file": "Jetsam.csv",
                "above": [f"Line {i} context before" for i in range(1, 6)],
                "match": "Mar 28 14:02 MobileSafari invoked connection to IP X",
                "below": [f"Line {i} context after" for i in range(6, 11)],
            }
        ],
        "ai_summary": "Several background processes are communicating with malicious IP X; likely exfiltration of user data.",
        "recommendations": [
            "Do not visit untrusted websites or open suspicious links.",
            "Uninstall Clash of Clans or other apps initiating these connections.",
            "Scan your device for unknown applications and remove them.",
        ],
    },
    # Add more indicators here...
]

st.title("Threat Indicators")

# Top-level summary table
summary_df = pd.DataFrame([
    {
        "Indicator Name": ind["name"],
        "Severity": ind["severity"],
        "Triggered?": "✅" if ind["triggered"] else "❌",
        "Score": ind["score"],
    }
    for ind in threat_indicators
])
st.table(summary_df)

st.markdown("---")

# Detailed cards for each indicator
for ind in threat_indicators:
    with st.container():
        # Header row: Name, Severity, Triggered icon, Score
        cols = st.columns([4, 1, 1, 1])
        cols[0].markdown(f"## {ind['name']}")
        cols[1].markdown(f"**{ind['severity']}**")
        cols[2].markdown("✅" if ind["triggered"] else "❌")
        cols[3].markdown(f"**Score:** {ind['score']}  ")

        # Description lines
        for line in ind["description"]:
            st.write(line)

        # Findings from log files
        st.markdown("**Findings (from Log Files)**")
        for f in ind.get("findings", []):
            st.markdown(f"*File:* `{f['file']}`")
            st.text("\n".join(f["above"]))
            st.markdown(f"<span style='color:red'>**{f['match']}**</span>", unsafe_allow_html=True)
            st.text("\n".join(f["below"]))

        # AI Summary
        st.markdown("**AI Summary**")
        st.write(ind["ai_summary"])

        # Security Recommendations
        st.markdown("**Security Recommendations**")
        for rec in ind["recommendations"]:
            st.write(f"- {rec}")

        st.markdown("---")

if __name__ == "__main__":
    pass  # Streamlit auto-runs render")]}
