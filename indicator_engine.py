import json
import re
import pandas as pd
import streamlit as st
import os 


import os
import glob
import json

def load_indicators(path):
    """
    Load one or more indicator JSON files.
    If `path` is a directory, load all .json files inside.
    Otherwise load the single JSON file at `path`.
    Returns a list of valid indicator dicts, each containing 'name', 'pattern', and optional 'severity'.
    Supports entries with 'regex_patterns' by expanding each regex into its own indicator.
    """
    indicators = []
    loaded = []
    try:
        if os.path.isdir(path):
            pattern = os.path.join(path, "*.json")
            files = glob.glob(pattern)
            if not files:
                st.warning(f"No JSON indicator files found in directory: {path}")
            for fn in files:
                try:
                    with open(fn, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            loaded.extend(data)
                        else:
                            loaded.append(data)
                except json.JSONDecodeError as e:
                    st.warning(f"Invalid JSON in indicator file {fn}: {e}")
                except Exception as e:
                    st.warning(f"Error loading indicator file {fn}: {e}")
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    loaded = data
                else:
                    loaded = [data]
    except Exception as e:
        st.error(f"Failed to load indicators from {path}: {e}")
        return []

    # Expand and validate indicators
    for ind in loaded:
        if not isinstance(ind, dict):
            st.warning(f"Skipping invalid indicator entry (not a dict): {ind}")
            continue
        name = ind.get('name') or ind.get('id')
        severity = ind.get('severity')
        description = ind.get('description')
        # Direct pattern field
        if 'pattern' in ind:
            indicators.append({
                'name': name,
                'pattern': ind['pattern'],
                'severity': severity,
                'description': description
            })
        # Expand regex_patterns list
        elif 'regex_patterns' in ind:
            for regex in ind['regex_patterns']:
                indicators.append({
                    'name': name,
                    'pattern': regex,
                    'severity': severity,
                    'description': description
                })
        else:
            st.warning(f"Skipping indicator missing 'pattern' or 'regex_patterns': {ind}")
    return indicators




def scan_file_lines(
    lines: list[str],
    pattern: str,
    neg_pattern: str | None = None,
    context: int = 2
) -> list[dict]:
    """
    Scan lines for a regex pattern, optionally excluding neg_pattern.
    Returns list of dicts with keys: lineno, line, context.
    """
    regex = re.compile(pattern)
    neg_regex = re.compile(neg_pattern) if neg_pattern else None
    hits = []
    for idx, line in enumerate(lines):
        if regex.search(line) and (not neg_regex or not neg_regex.search(line)):
            start = max(0, idx - context)
            end = min(len(lines), idx + context + 1)
            snippet = ''.join(lines[start:end])
            hits.append({
                'lineno': idx + 1,
                'line': line.rstrip(),
                'context': snippet.rstrip()
            })
    return hits


def scan_path(path: str, indicators: list[dict]) -> pd.DataFrame:
    """
    For a given text file, run through all indicators and
    return every line that matches any of their regex_patterns.
    """
    matches = []
    basename = os.path.basename(path)

    try:
        with open(path, 'r', errors='ignore') as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.rstrip()
                for ind in indicators:
                    # 1) Filename filter
                    if not any(re.search(fp, basename, re.IGNORECASE)
                               for fp in ind.get('file_patterns', [])):
                        continue

                    # 2) Regex scan
                    for rpat in ind.get('regex_patterns', []):
                        if re.search(rpat, line, re.IGNORECASE):
                            matches.append({
                                'id':        ind.get('id'),
                                'indicator': ind.get('name'),
                                'file':      path,
                                'line_no':   lineno,
                                'line':      line,
                                'severity':  ind.get('severity', '')
                            })
                            break  # don’t double-count one line per indicator
    except Exception:
        # you can log here if you like
        pass

    return pd.DataFrame(matches)


def render_results(df: pd.DataFrame) -> None:
    """
    Render scan results in Streamlit:
      - An expander per indicator
      - A summary table and CSV download
    """
    if df.empty:
        st.info("No findings.")
        return

    # Summary table
    summary = (
        df.groupby(['indicator','severity','triggered','score'])
          .size()
          .reset_index(name='count')
          .sort_values(['score','severity'], ascending=False)
    )
    st.subheader('Indicator Summary')
    st.dataframe(summary, use_container_width=True)

    # Detailed expanders
    for name, group in df.groupby('indicator'):
        with st.expander(f"{name} ({len(group)} hits)"):
            st.markdown(group[['file','lineno','line','context']]
                        .to_markdown(index=False))
    
    # Download all results
    csv_data = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label='Download All Findings as CSV',
        data=csv_data,
        file_name='indicator_findings.csv',
        mime='text/csv'
    )
