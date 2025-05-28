# views/report.py

import streamlit as st
import pandas as pd
import json
import os
from pathlib import Path
import folium
from streamlit_folium import st_folium
import io
import zipfile
import glob
import smtplib
from email.message import EmailMessage
import pdfkit
import smtplib
from email.message import EmailMessage

from ai_summary import get_summary, summarize_indicators
from indicator_engine import scan_path, load_indicators


def render_report():
    # Email setup from environment
    SMTP_SERVER = os.getenv("SMTP_SERVER", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    REPORT_RECIPIENT = os.getenv("REPORT_EMAIL", "")

    def send_report_via_email(attachments: dict):
        """
        Sends an email with the given attachments to REPORT_RECIPIENT.
        """
        if not REPORT_RECIPIENT or not SMTP_USER or not SMTP_PASS or not SMTP_SERVER:
            st.error("Email settings incomplete. Please configure SMTP_SERVER, SMTP_USER, SMTP_PASS, and REPORT_EMAIL in .env.")
            return
        msg = EmailMessage()
        msg['Subject'] = f'Case Report - {latest_case}'
        msg['From'] = SMTP_USER
        msg['To'] = REPORT_RECIPIENT
        msg.set_content(f'Please find attached the full report and supporting tables for case {latest_case}.')
        # Attach files
        for filename, data in attachments.items():
            msg.add_attachment(data, maintype='application', subtype='octet-stream', filename=filename)
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
            st.success(f'Report emailed to {REPORT_RECIPIENT}')
        except Exception as e:
            st.error(f'Failed to send email: {e}')
    # ─── Paths ───────────────────────────────────────────────────────────────────
    SCRIPT_DIR   = Path(__file__).resolve().parent
    PROJECT_ROOT = SCRIPT_DIR.parent
    CASES_ROOT   = PROJECT_ROOT / "sysdiagnose" / "cases"
    REPORT_DIR   = PROJECT_ROOT / "reports"
    REPORT_DIR.mkdir(exist_ok=True)

    # ─── Pick latest case ────────────────────────────────────────────────────────
    case_dirs = [d for d in os.listdir(CASES_ROOT) if (CASES_ROOT / d).is_dir()]
    if not case_dirs:
        st.error("No sysdiagnose cases found.")
        return
    latest_case = max(case_dirs, key=lambda d: (CASES_ROOT / d).stat().st_mtime)
    parsed_data = CASES_ROOT / latest_case / "parsed_data"

    # ─── Load DataFrames ──────────────────────────────────────────────────────────
    def load_jsonl(fp): return [json.loads(l) for l in open(fp, 'r')]
    def load_json(fp):  return json.load(open(fp, 'r'))

    try:
        accessibility = pd.DataFrame(load_jsonl(parsed_data/"accessibility_tcc.jsonl"))
        activation    = pd.DataFrame(load_jsonl(parsed_data/"mobileactivation.jsonl"))
        backup        = pd.DataFrame(load_jsonl(parsed_data/"mobilebackup.jsonl"))
        wifinetworks  = pd.DataFrame(load_json(parsed_data/"wifinetworks.json"))
        crashlogs     = pd.DataFrame(load_jsonl(parsed_data/"crashlogs.jsonl"))
        lockdownd     = pd.DataFrame(load_jsonl(parsed_data/"lockdownd.jsonl"))
        wifiscan      = pd.DataFrame(load_jsonl(parsed_data/"wifiscan.jsonl"))
    except FileNotFoundError as e:
        st.error(f"Missing file: {e}")
        return

    dfs = [
        (accessibility, "Accessibility Permissions",
         "Records of which services/apps requested device permissions and whether they were granted."),
        (activation,    "Mobile Activation",
         "Timestamps of device activation events (e.g. unlocks, wakeups)."),
        (backup,        "Mobile Backups",
         "Metadata about device backups, including file sizes."),
        (crashlogs,     "Crash Logs",
         "Parsed crash reports, categorized by crash reason."),
        (lockdownd,     "Lockdown Pairings",
         "Bluetooth lockdown pairings between device and peripherals."),
        (wifinetworks,  "Wi-Fi Networks",
         "Known Wi-Fi networks saved on device, including auto-join settings."),
        (wifiscan,      "Wi-Fi Scans",
         "Geo-located Wi-Fi scan results showing networks seen nearby."),
    ]

    # ─── Persist ALL tables ─────────────────────────────────────────────────────
    xlsx_path = REPORT_DIR / f"{latest_case}_tables.xlsx"
    with pd.ExcelWriter(xlsx_path, engine="xlsxwriter") as writer:
        for df, name, _ in dfs:
            df.to_excel(writer, sheet_name=name[:31], index=False)
            (REPORT_DIR / f"{name}.csv").write_text(df.to_csv(index=False))

    # ─── Report Tab ──────────────────────────────────────────────────────────────
    tab = st.tabs(["Report"])[0]
    with tab:
        # ─── Quick Summary ────────────────────────────────────────────────────
        st.header("🔍 Quick Summary")
        st.info("This section summarizes key forensic metrics extracted from the device.")
        col1, col2, col3 = st.columns(3)
        cam_count = accessibility[accessibility['service']=='kTCCServiceCamera'].shape[0] if 'service' in accessibility.columns else 0
        col1.metric("Apps with Camera Access", cam_count)
        wifi_known_count = wifinetworks.shape[0] 
        col2.metric("Wi-Fi Networks Known", wifi_known_count)
        total_crashes = crashlogs.shape[0]
        col3.metric("Total Crashes", total_crashes)
        st.metric("Number of Files", lockdownd.shape[0])
        st.markdown("---")

        # ─── Section Loop ───────────────────────────────────────────────────────
        for df, name, desc in dfs:
            st.header(name)
            st.markdown(f"**What is this section about?**  {desc}")
            st.markdown("**Important Findings**")
            st.write(f"- Total entries: **{len(df)}**")

            # Raw Table
            with st.expander("Show Raw Table (10 rows)", expanded=True):
                st.dataframe(df.head(10))

            # Section-specific charts & notes
            if name == "Crash Logs":
                # Crash category summary
                if 'category' in df.columns:
                    top = df['category'].value_counts()
                    if not top.empty:
                        st.write(f"- Top crash category **{top.index[0]}**: {top.iloc[0]} entries.")
                # Top crashing apps
                st.subheader("🏆 Top Crashing Apps")
                if 'app_name' in df.columns:
                    top_crashes = df['app_name'].value_counts().head(10)
                    st.bar_chart(top_crashes)
                # Crash events over time
                st.subheader("⏱️ Crash Events Over Time")
                if 'timestamp' in df.columns:
                    df_ts = df.copy()
                    df_ts['timestamp'] = pd.to_datetime(df_ts['timestamp'], unit='s', errors='coerce')
                    crashes_by_day = df_ts.dropna(subset=['timestamp']).groupby(df_ts['timestamp'].dt.date).size()
                    st.line_chart(crashes_by_day)
            if name == "Wi-Fi Networks":
                # Auto-join scan locations
                st.subheader("Auto-Join Locations Map")
                auto_ssids = df.loc[df['auto_join'], 'ssid'].unique() if 'auto_join' in df.columns else []
                scans = wifiscan[wifiscan['ssid'].isin(auto_ssids)] if auto_ssids else pd.DataFrame()
                if not scans.empty and {'lat','lon'}.issubset(scans.columns):
                    m2 = folium.Map(location=[0,0], zoom_start=2)
                    for _, r in scans.iterrows():
                        folium.Marker([r.lat, r.lon], popup=r.ssid).add_to(m2)
                    st_folium(m2, width=700, height=400, key="auto_join_overview")
                # Deep Dive Auto-Join Map
                wifi_auto_locations = []
                wifi_plist = parsed_data / "plists" / "WiFi_com.apple.wifi.plist.json"
                try:
                    with open(wifi_plist, "r") as f:
                        wifi_plist_map = json.load(f)
                    loc = wifi_plist_map.get("UserAutoJoinLocationMetric", {})
                    lat = loc.get("kCLLocationCodingKeyRawCoordinateLatitude")
                    lon = loc.get("kCLLocationCodingKeyRawCoordinateLongitude")
                    if lat and lon:
                        wifi_auto_locations.append((lat, lon))
                except Exception:
                    pass
                if wifi_auto_locations:
                    st.subheader("🌍 Wi-Fi Auto-Join Locations Map (Deep Dive)")
                    m3 = folium.Map(location=wifi_auto_locations[0], zoom_start=15)
                    for lat, lon in wifi_auto_locations:
                        folium.Marker([lat, lon], icon=folium.Icon(color="blue", icon="wifi", prefix="fa")).add_to(m3)
                    st_folium(m3, width=800, key="auto_join_deep")

            # AI-generated summary
            st.subheader("AI-Generated Summary")
            csv_path = REPORT_DIR / f"{name}.csv"
            try:
                st.write(get_summary(str(csv_path)))
            except Exception as e:
                st.error(f"Summary failed: {e}")

        # ─── Triggered Indicators ────────────────────────────────────────────────
        st.header("Triggered Indicators")
        indicators = []
        ind_dir = PROJECT_ROOT / "indicators"
        if ind_dir.is_dir():
            for f in ind_dir.iterdir():
                if f.is_file():
                    indicators.extend(load_indicators(str(f)))
        hits = scan_path(str(CASES_ROOT/latest_case), indicators)
        # Executive Summary of Indicators
        summary_rows = []
        seen = set()
        counts = hits['indicator'].value_counts().to_dict() if not hits.empty and 'indicator' in hits.columns else {}
        for ind in indicators:
            name = ind.get('name')
            if name in seen:
                continue
            seen.add(name)
            summary_rows.append({
                'Indicator': name,
                'Hits': counts.get(name, 0),
                'Severity': ind.get('severity', '')
            })
        df_indicator_summary = pd.DataFrame(summary_rows)
        st.subheader("Indicator Executive Summary")
        st.table(df_indicator_summary)

        # AI on indicators
        st.subheader("AI-Generated Indicators Summary")
        try:
            st.write(summarize_indicators(hits))
        except Exception as e:
            st.error(f"Indicators summary failed: {e}")

        # ─── Download Supporting Tables ─────────────────────────────────────────
        st.header("Download Supporting Tables")
        reports_data = {}
        for df, name, _ in dfs:
            reports_data[f"{name}.csv"] = df.to_csv(index=False).encode('utf-8')
        # Excel workbook
        try:
            with open(xlsx_path, 'rb') as xf:
                reports_data[xlsx_path.name] = xf.read()
        except Exception:
            pass
        # Triggered indicators
        reports_data['triggered_indicators.csv'] = hits.to_csv(index=False).encode('utf-8')

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for filename, data in reports_data.items():
                zf.writestr(filename, data)
        zip_buffer.seek(0)
        st.download_button(
            label="Download All Report Tables (ZIP)",
            data=zip_buffer,
            file_name="report_supporting_tables.zip",
            mime="application/zip"
        )
        if st.button("Email Report and Tables"):
            send_report_via_email(reports_data)
            data=zip_buffer,
            file_name="report_supporting_tables.zip",
            mime="application/zip"
            st.success("Report emailed successfully!")