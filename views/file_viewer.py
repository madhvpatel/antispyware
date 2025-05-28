import streamlit as st
import pandas as pd
import plistlib
import json
import os
import io
import zipfile
import tarfile
import tempfile
import sqlite3
from pathlib import Path
import shutil

def _read_text(path: str) -> str | None:
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read()
    except Exception:
        return None

def _show_json(path: str) -> None:
    try:
        with open(path, 'r', errors='ignore') as f:
            data = json.load(f)
    except Exception:
        st.write("Failed to parse JSON.")
        return

    st.subheader("JSON")
    st.json(data)

    flat = None
    if isinstance(data, list) and data and all(isinstance(i, dict) for i in data):
        flat = pd.json_normalize(data)
    elif isinstance(data, dict):
        flat = pd.json_normalize(data)

    if flat is not None and not flat.empty:
        st.subheader("Flattened Data")
        st.dataframe(flat)

def _show_plist(path: str) -> None:
    try:
        with open(path, 'rb') as f:
            data = plistlib.load(f)
    except Exception:
        st.write("Failed to parse PLIST.")
        return

    st.subheader("PLIST")
    st.json(data)

    flat = pd.json_normalize(data)
    if not flat.empty:
            # Prevent ArrowInvalid: convert all object columns to strings
            obj_cols = flat.select_dtypes(include=['object']).columns
            for c in obj_cols:
                flat[c] = flat[c].astype(str)

            st.subheader("Flattened Data")
            st.dataframe(flat)

def list_archive_members(path: str) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    suffix = Path(path).suffix.lower()

    if suffix == ".zip":
        with zipfile.ZipFile(path, 'r') as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    members[info.filename] = zf.read(info)

    elif suffix in (".tar", ".tgz") or path.lower().endswith(".tar.gz"):
        mode = "r:gz" if path.lower().endswith((".tgz", ".tar.gz")) else "r:"
        with tarfile.open(path, mode) as tf:
            for member in tf.getmembers():
                if member.isreg():
                    f = tf.extractfile(member)
                    if f:
                        members[member.name] = f.read()

    return members

def render_file(sel: str) -> None:
    """
    Render a two-column view for the selected file—including
    archive browsing, raw text + search, structured views for
    CSV/JSON/PLIST/.ips and now SQLite/DB tables.
    """
    import streamlit as st
    import pandas as pd
    import tempfile
    import shutil
    import sqlite3
    from pathlib import Path

    st.subheader(f"Viewing: {Path(sel).name}")

    # Archive handling
    ext = Path(sel).suffix.lower()
    if ext in (".zip", ".tar", ".tgz") or sel.lower().endswith(".tar.gz"):
        st.subheader(f"Archive Contents: {Path(sel).name}")
        members = list_archive_members(sel)
        choice = st.selectbox(
            "Choose a file inside this archive",
            options=["<none>"] + sorted(members.keys()),
            format_func=lambda x: x if x=="<none>" else Path(x).name
        )
        if choice and choice != "<none>":
            tmp_path = Path(tempfile.gettempdir()) / Path(choice).name
            tmp_path.write_bytes(members[choice])
            render_file(str(tmp_path))
        return

    # Shared search bar
    search_term = st.text_input("🔍 Search file content")

    # Fixed-height two-column layout
    left, right = st.columns([1, 1], gap="large")

    fixed_height = 400

    # Left: raw + search
    with left:
        raw = _read_text(sel)
        st.subheader("Raw Data")
        if raw:
            lines = raw.splitlines()
            if search_term:
                lines = [l for l in lines if search_term.lower() in l.lower()]
                if not lines:
                    lines = ["No matches found."]
            st.text_area("", "\n".join(lines), height=fixed_height, label_visibility="hidden")
        else:
            st.write("Binary or non-text file.")

    # Right: structured by extension
    with right:
        st.subheader("Structured View")
        if ext == '.csv':
            try:
                df = pd.read_csv(sel)
                if search_term:
                    mask = df.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False)).any(axis=1)
                    filtered_df = df[mask]
                    st.dataframe(filtered_df, height=fixed_height)
                else:
                    st.dataframe(df, height=fixed_height)
            except Exception:
                st.write("Failed to load CSV.")

        elif ext == '.json':
            _show_json(sel)

        elif ext == '.plist':
            _show_plist(sel)

        elif ext in ('.ips', '.crash'):
            report = raw or _read_text(sel) or ""
            sections = report.split('\n\n', 1)
            header = sections[0].splitlines()
            body = sections[1].splitlines() if len(sections) > 1 else []
            with st.expander("Report Header", expanded=True):
                st.code("\n".join(header), language='text')
            if body:
                with st.expander("Stack & Details", expanded=False):
                    st.code("\n".join(body), language='text')

        elif ext in ('.db', '.sqlite', '.db-wal', '.db-shm'):
            sel_path = Path(sel)
            base = sel_path.name
            if base.endswith(".db-wal") or base.endswith(".db-shm"):
                main_name = base.rsplit("-", 1)[0] + ".db"
            else:
                main_name = base

            src_dir = sel_path.parent
            candidates = [
                src_dir / main_name,
                src_dir / (main_name + "-wal"),
                src_dir / (main_name + "-shm")
            ]
            existing = [p for p in candidates if p.exists()]

            if not existing:
                st.write(f"No SQLite database found for base name '{main_name}'.")
            else:
                tmp = Path(tempfile.mkdtemp())
                for p in existing:
                    shutil.copy(p, tmp / p.name)

                db_temp = tmp / main_name
                try:
                    conn = sqlite3.connect(str(db_temp))
                    tables = pd.read_sql_query(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;", conn
                    )['name'].tolist()

                    choice = st.selectbox("Choose a table", ["<none>"] + tables)
                    if choice and choice != "<none>":
                        df = pd.read_sql_query(f"SELECT * FROM `{choice}` LIMIT 1000;", conn)
                        if search_term:
                            mask = df.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False)).any(axis=1)
                            filtered_df = df[mask]
                            st.dataframe(filtered_df, height=fixed_height)
                        else:
                            st.dataframe(df, height=fixed_height)
                    conn.close()
                except Exception as e:
                    st.write(f"Failed to read SQLite DB: {e}")