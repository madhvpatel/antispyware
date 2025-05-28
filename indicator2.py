import streamlit as st
import pandas as pd
from datetime import datetime

__all__ = ["render_indicators"]

def render_indicators(demo_indicators, process_indicators=None):
    """
    Render KPI cards for demo indicators and optional process indicators
    using the unified threat-indicator style UI.

    Parameters:
    - demo_indicators: list of dicts with keys:
        title, severity, triggered (optional), value, description
    - process_indicators: list of dicts with keys:
        name, severity, triggered, score, description (list of lines),
        findings (list), ai_summary, recommendations
    """
    # Combine both sets into one list of full-format indicators
    all_indicators = []
    # Map demo indicators into full format
    for ind in demo_indicators:
        all_indicators.append({
            "name": ind.get("title"),
            "severity": ind.get("severity", "Normal"),
            "triggered": True,
            "score": ind.get("value"),
            "description": [ind.get("description", "")],
            "findings": [],
            "ai_summary": "",
            "recommendations": [],
        })
    # Append process indicators if any
    if process_indicators:
        all_indicators.extend(process_indicators)

    # Page title
    st.title("System Health & Threat Indicators")

    # Summary table
    summary_df = pd.DataFrame([
        {
            "Indicator Name": ind["name"],
            "Severity": ind.get("severity"),
            "Triggered?": "✅" if ind.get("triggered") else "❌",
            "Score": ind.get("score"),
        }
        for ind in all_indicators
    ])
    st.table(summary_df)
    st.markdown("---")

    # Detailed UI cards for each indicator
    for ind in all_indicators:
        with st.container():
            cols = st.columns([4, 1, 1, 1])
            cols[0].markdown(f"## {ind['name']}")
            cols[1].markdown(f"**{ind.get('severity')}**")
            cols[2].markdown("✅" if ind.get('triggered') else "❌")
            cols[3].markdown(f"**Score:** {ind.get('score')}  ")

            # Description lines
            for line in ind.get("description", []):
                st.write(line)

            # Optional findings section
            if ind.get("findings"):
                st.markdown("**Findings (from Log Files)**")
                for f in ind["findings"]:
                    st.markdown(f"*File:* `{f['file']}`")
                    st.text("\n".join(f.get("above", [])))
                    st.markdown(
                        f"<span style='color:red'>**{f.get('match')}**</span>",
                        unsafe_allow_html=True,
                    )
                    st.text("\n".join(f.get("below", [])))

            # AI Summary button and display
            if ind.get("ai_summary"):
                if st.button("Generate AI Summary", key=f"ai_{ind['name']}"):
                    st.markdown("**AI Summary**")
                    st.write(ind.get("ai_summary"))

            # Security Recommendations button and display
            if ind.get("recommendations"):
                if st.button("Show Security Recommendations", key=f"rec_{ind['name']}"):
                    st.markdown("**Security Recommendations**")
                    for rec in ind.get("recommendations", []):
                        st.write(f"- {rec}")

            st.markdown("---")

