import os
from dotenv import load_dotenv
from pathlib import Path
from typing import List, Dict, Optional
import json
import sqlite3
import pandas as pd
import plistlib
import requests
from itertools import cycle
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile

# Load environment variables
load_dotenv()

# Configuration
API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "deepseek/deepseek-r1-zero:free"
MAX_CHARS = 2000  # Max characters for logs/text

# Build API keys pool
_raw_keys = os.getenv("OPENROUTER_API_KEYS", "").split(",")
API_KEYS = [k.strip() for k in _raw_keys if k.strip()]
if not API_KEYS:
    raise ValueError("No API keys found. Set the OPENROUTER_API_KEYS env var.")
_key_cycle = cycle(API_KEYS)


def _extract_csv_cols(path: str) -> List[str]:
    df = pd.read_csv(path, nrows=0)
    return df.columns.tolist()


def _extract_db_schema(path: str) -> List[Dict]:
    base = Path(path)
    main_db = base.with_suffix('.db') if base.suffix in ('.db-wal', '.db-shm') else base
    con = sqlite3.connect(str(main_db))
    schema = pd.read_sql(
        "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name;", con
    ).to_dict(orient='records')
    con.close()
    return schema


def _extract_json_keys(path: str) -> List[str]:
    data = json.load(open(path, 'r', errors='ignore'))
    keys = set()

    def recurse(obj, prefix=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                recurse(v, f"{prefix}{k}.")
        elif isinstance(obj, list) and obj:
            recurse(obj[0], prefix)
        else:
            keys.add(prefix.rstrip('.'))

    recurse(data)
    return sorted(keys)


def _extract_plist_keys(path: str) -> List[str]:
    data = plistlib.load(open(path, 'rb'))
    return list(data.keys())


def _build_prompt(path: str) -> str:
    ext = Path(path).suffix.lower()
    fname = Path(path).name

    if ext == '.csv':
        cols = _extract_csv_cols(path)
        short = cols[:20]
        return (
            f"The CSV file `{fname}` has columns:\n```{', '.join(short)}```\n"
            "Explain each column briefly and highlight anomalies."
        )

    if ext in ('.db', '.sqlite', '.db-wal', '.db-shm'):
        schema = _extract_db_schema(path)
        schema_json = json.dumps(schema, indent=2)
        return (
            f"The SQLite database `{fname}` has schema:\n```json\n{schema_json}\n```\n"
            "Describe each table and key columns succinctly."
        )

    if ext == '.json':
        keys = _extract_json_keys(path)
        return (
            f"The JSON file `{fname}` contains keys:\n```{', '.join(keys)}```\n"
            "Explain what each field likely represents."
        )

    if ext == '.plist':
        keys = _extract_plist_keys(path)
        return (
            f"The PLIST file `{fname}` contains keys:\n```{', '.join(keys)}```\n"
            "Explain the purpose of each key."
        )

    if ext in ('.ips', '.crash'):
        text = open(path, 'r', errors='ignore').read(MAX_CHARS)
        return (
            f"Summarize crash report `{fname}` in 3-5 sentences:\n```{text}"
        )

    if ext in ('.txt', '.log'):
        text = open(path, 'r', errors='ignore').read(MAX_CHARS)
        return (
            f"Summarize log file `{fname}` in 3-5 sentences, noting errors/warnings:\n```{text}"
        )

    snippet = open(path, 'rb').read(500).decode('ascii', 'ignore')
    return (
        f"Provide a concise summary of file `{fname}`:\n```{snippet}"
    )


def get_summary(path: str) -> str:
    """
    Generate a context-aware AI summary for the given file, cycling through API keys.
    """
    prompt = _build_prompt(path)
    messages = [
        {"role": "system", "content": "You are a system diagnostics expert."},
        {"role": "user", "content": prompt}
    ]

    payload = {"model": MODEL, "messages": messages}
    key = next(_key_cycle)
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    try:
        resp = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return f"API error: {e}"

    if "choices" in data:
        choice = data["choices"][0]
        if msg := choice.get("message"):
            return msg.get("content", "").strip()
        if txt := choice.get("text"):
            return txt.strip()

    return f"Unexpected API response: {data}"

def get_summary_2(file_path: str) -> str:
    """
    Wrapper to call Deepseek R1 chat completion on a prompt file.
    """
    prompt_text = open(file_path, 'r', encoding='utf-8').read()
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content":
             "You are a forensic security analyst for IOS mobile devices. Return results in Markdown using "
             "the schema: headings, a details table, summary, and security recommendations. "
             "Do NOT include LaTeX or boxed text."},
            {"role": "user", "content": prompt_text}
        ],
        "temperature": 0.6,
        "top_p": 0.95
    }
    headers = {
        "Authorization": f"Bearer {next(_key_cycle)}",
        "Content-Type": "application/json"
    }
    resp = requests.post(API_URL, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    # Assume same chat-format response structure as OpenAI
    return data["choices"][0]["message"]["content"].strip()

def get_summaries(paths: List[str]) -> Dict[str, str]:
    """
    Summarize multiple files in parallel using available API keys.
    """
    results: Dict[str, str] = {}
    if not paths:
        return results

    with ThreadPoolExecutor(max_workers=len(API_KEYS)) as executor:
        future_map = {executor.submit(get_summary, p): p for p in paths}
        for future in as_completed(future_map):
            p = future_map[future]
            try:
                results[p] = future.result()
            except Exception as e:
                results[p] = f"Error: {e}"
    return results



# Load environment variables
def summarize_indicators(triggered_contexts: dict[str, list[str]]) -> str:
    """
    Generate a structured, layman-friendly summary *and* security recommendations
    with deep reasoning and explicit schema for each triggered indicator.
    """
    # 1) Few-shot examples to demonstrate reasoning on dotted numbers
    examples = (
        "### Example: Distinguishing IP vs Version String\n"
        "Dotted string: 10.0.0.5\n"
        "Reasoning: All segments ≤255 → valid IPv4 address → treat as Remote Endpoint.\n\n"
        "Dotted string: 5200.3.6.1.1\n"
        "Reasoning: First segment ‘5200’ >255 → cannot be IP → treat as build/version string.\n"
        "### End Examples\n"
    )

    # 2) Instruction header with Chain‐of‐Thought prompt
    instructions = (
        "Now analyze each of the following triggered indicators from an IOS device. For any dotted number, "
        "think step‐by‐step (apply the segment‐range test) and explain your reasoning. "
        "Then produce the report in Markdown as:\n"
        "## Indicator: <Name>\n"
        "### Affected Process\n"
        "- Name: …\n"
        "- Bundle ID: …\n"
        "- Process ID: …\n\n"
        "### Details\n"
        "| Field            | Value |\n"
        "|------------------|-------|\n"
        "| Remote Endpoint  | …     |\n"
        "| Data Transferred | …     |\n"
        "| CPU Usage        | …     |\n"
        "| Timestamp        | …     |\n\n"
        "### Summary\n"
        "A concise, non-technical description.\n\n"
        "### Security Recommendations\n"
        "1. …\n"
        "2. …\n\n"
    )

    # 3) Build the combined prompt body
    body_lines = [examples, instructions]
    for name, contexts in triggered_contexts.items():
        body_lines.append(f"## Indicator: {name}\n")
        # include up to 3 enriched snippets
        for snippet in contexts[:3]:
            flat = snippet.replace("\n", " ").strip()
            body_lines.append(f"- Context: {flat}\n")
        body_lines.append("")  # spacer

    full_prompt = "\n".join(body_lines)

    # 4) Write to temp file and invoke the model
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=".txt", mode="w", encoding="utf-8"
    ) as tf:
        tf.write(full_prompt)
        prompt_path = tf.name

    return get_summary_2(prompt_path)