# views/scanners.py

import os
import glob
import re
import streamlit as st
import pandas as pd

from indicator_engine import load_indicators, scan_path
from ai_summary import summarize_indicators

# Main rendering function

def render_scanners(glob_files: list[str], tmpdir: str, indicators_dir: str = "indicators"):
    st.title("Threat Indicators")

    # 1) Load indicators
    indicator_files = glob.glob(os.path.join(indicators_dir, "*.json"))
    indicators = []
    for jf in sorted(indicator_files):
        indicators.extend(load_indicators(jf))

    # 2) Scan logs
    txt_logs = [f for f in glob_files if f.lower().endswith('.txt')]
    if not txt_logs:
        st.info("No text logs to scan.")
    dfs = [scan_path(p, indicators) for p in txt_logs]
    non_empty = [d for d in dfs if not d.empty]
    df_hits = pd.concat(non_empty, ignore_index=True) if non_empty else pd.DataFrame()

    # 3) Executive Summary Table
    summary = []
    seen = set()
    for ind in indicators:
        name = ind['name']
        if name in seen:
            continue
        seen.add(name)
        severity = ind.get('severity', '')
        score = ind.get('score', '')
        triggered = bool('indicator' in df_hits.columns and name in df_hits['indicator'].values)
        summary.append({
            'Indicator Name': name,
            'Indicator Severity': severity,
            'Triggered?': '✅' if triggered else '❌',
            'Indicator Score': score
        })
    df_summary = pd.DataFrame(summary)
    unique_indicators = { ind['name'] for ind in indicators }
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Indicators Scanned", len(unique_indicators))
    total_triggers = df_hits.shape[0]
    col2.metric("Total Triggers", total_triggers)
    sev_counts = df_summary[df_summary['Triggered?'] == '✅']['Indicator Severity'].value_counts().to_dict()
    breakdown = ", ".join([f"{v} {k}" for k, v in sev_counts.items()]) if sev_counts else "None"
    col3.metric("Severity Breakdown", breakdown)
    repeat_hits = sum(count > 1 for count in df_hits.get('indicator', pd.Series()).value_counts())
    col4.metric("Repeat Hits", repeat_hits)
    st.subheader("Indicator Summary Table")
    st.table(df_summary)

    # 4) Per-Indicator Detail Panels
    # Use unique indicator names to prevent duplicates
    unique_names = list(df_summary['Indicator Name'])
    for name in unique_names:
        # Get indicator definition
        ind_def = next((i for i in indicators if i['name']==name), {})
        desc = ind_def.get('description', '')
        severity = ind_def.get('severity', '')
        score = ind_def.get('score', '')
        # Filter hits for this indicator
        grp = df_hits[df_hits.get('indicator','') == name] if not df_hits.empty else pd.DataFrame()
        count = len(grp)

        # Top-level expander for this indicator
        with st.expander(f"{name} ({count} hits)", expanded=False):
            # Header row
            cols = st.columns([3,1,1,1])
            cols[0].markdown(f"**{name}**")
            cols[1].write(f"Severity: {severity}")
            cols[2].write(f"Hits: {count}")
            cols[3].write(f"Score: {score}")
            st.markdown(f"*{desc}*")

                        # Log File Previews
            st.write("**Log File Previews:**")
            for file_path in txt_logs:
                fname = os.path.basename(file_path)
                st.write(f"**{fname}**")
                try:
                    lines = open(file_path, 'r', errors='ignore').read().splitlines()[:5]
                except Exception:
                    lines = []
                st.code("".join(lines) or "No content to preview.", language='text')

            # Findings Tabs
            if count > 0:
                files = grp['file'].unique().tolist()
                tabs = st.tabs([os.path.basename(f) for f in files])
                for tab, filepath in zip(tabs, files):
                    with tab:
                        st.write(f"**File:** {os.path.basename(filepath)}")
                        try:
                            lines = open(filepath, 'r', errors='ignore').read().splitlines()
                        except Exception:
                            lines = []
                        for _, row in grp[grp['file']==filepath].iterrows():
                            ln = int(row['lineno'])
                            start = max(0, ln-6)
                            end = min(len(lines), ln+5)
                            snippet = lines[start:ln-1] + [f">> {lines[ln-1]} <<"] + lines[ln:end]
                            st.code("".join(snippet), language='text')
            else:
                st.info("No findings in log files.")

            # AI Summary
            st.subheader("AI Summary")
            if count > 0:
                snippets = grp['line'].tolist()
                ai_summary = summarize_indicators({name: snippets})
                st.write(ai_summary)
            else:
                st.write("No hits to summarize.")

            # Security Recommendations (AI-generated)
            st.subheader("Security Recommendations")
            if count > 0:
                recs = summarize_indicators({name: grp['line'].tolist()})
                for i, rec in enumerate(recs.splitlines(), 1):
                    st.write(f"{i}. {rec}")
            else:
                st.write("No recommendations: no indicator hits.")

            # Download snippets as CSV
            if not grp.empty:
                csv_data = grp[['file','lineno','line']].to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download Snippets CSV",
                    data=csv_data,
                    file_name=f"{name}_snippets.csv",
                    mime="text/csv"
                )
            st.markdown("---")
