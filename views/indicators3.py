#!/usr/bin/env python3
"""
indicators.py

Forensic indicators for iOS sysdiagnose:
  - Unauthorized daemons in ps.txt / ps_thread.txt
  - Normal Apple-signed processes (SpringBoard, backboardd)
  - Suspicious kernel panic backtraces in error_log.txt
  - Panic entries in kbdebug.txt

Usage:
  python3 indicators.py --root /path/to/sysdiagnose [--json report.json]
"""

import os
import re
import json
import argparse

# Patterns to flag as suspicious
SUSPICIOUS_PATHS = [
    re.compile(r'/private/var/tmp', re.IGNORECASE),
    re.compile(r'/private/var/db', re.IGNORECASE),
]

# Known-normal, Apple-signed executables to show script is working
NORMAL_PATTERNS = [
    re.compile(r'\bSpringBoard\b'),
    re.compile(r'\bbackboardd\b'),
    re.compile(r'\blaunchd\b'),
]

# Patterns for kernel backtrace flags
BACKTRACE_FLAGS = [
    re.compile(r'\.staging', re.IGNORECASE),
    re.compile(r'payload', re.IGNORECASE),
]

PANIC_LINE = re.compile(r'\bpanic\b', re.IGNORECASE)


def find_files(root, name):
    for dp, _, files in os.walk(root):
        if name in files:
            yield os.path.join(dp, name)


def scan_background(root):
    """Detect unauthorized daemons and capture a few normal, Apple-signed processes."""
    suspicious = []
    normal = []
    for fname in ('ps.txt', 'ps_thread.txt'):
        for path in find_files(root, fname):
            with open(path, 'r', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    if any(p.search(line) for p in SUSPICIOUS_PATHS):
                        suspicious.append({
                            'file': os.path.relpath(path, root),
                            'line_no': i,
                            'line': line.strip()
                        })
                    elif any(p.search(line) for p in NORMAL_PATTERNS):
                        normal.append({
                            'file': os.path.relpath(path, root),
                            'line_no': i,
                            'line': line.strip()
                        })
    return suspicious, normal


def scan_kernel_panic(root):
    backtraces = []
    panics = []
    # error_log.txt -> backtrace flags
    for path in find_files(root, 'error_log.txt'):
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                if any(p.search(line) for p in BACKTRACE_FLAGS):
                    backtraces.append({
                        'file': os.path.relpath(path, root),
                        'line_no': i,
                        'line': line.strip()
                    })
    # kbdebug.txt -> panic entries
    for path in find_files(root, 'kbdebug.txt'):
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                if PANIC_LINE.search(line):
                    panics.append({
                        'file': os.path.relpath(path, root),
                        'line_no': i,
                        'line': line.strip()
                    })
    return backtraces, panics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True,
                        help='Path to extracted sysdiagnose directory')
    parser.add_argument('--json', help='Dump detailed findings to JSON file')
    args = parser.parse_args()

    bg_susp, bg_norm = scan_background(args.root)
    bt, pn = scan_kernel_panic(args.root)

    report = {
        'unauthorized_daemons': bg_susp,
        'normal_processes': bg_norm,
        'suspicious_backtraces': bt,
        'kernel_panics': pn
    }

    # Print normal processes
    print("\n=== Normal Apple-signed Processes ===")
    if not bg_norm:
        print("  (None of the expected Apple-signed processes were found.)")
    else:
        for x in bg_norm:
            print(f"  {x['file']}:{x['line_no']}  {x['line']}")

    # Print unauthorized daemons
    print("\n=== Unauthorized Daemons ===")
    if not bg_susp:
        print("  (None found in ps.txt / ps_thread.txt)")
    else:
        for x in bg_susp:
            print(f"  {x['file']}:{x['line_no']}  {x['line']}")

    # Print suspicious backtraces
    print("\n=== Suspicious Backtraces ===")
    if not bt:
        print("  (No exploit flags found in error_log.txt)")
    else:
        for x in bt:
            print(f"  {x['file']}:{x['line_no']}  {x['line']}")

    # Print kernel panics
    print("\n=== Kernel Panics in kbdebug.txt ===")
    if not pn:
        print("  (No panic entries detected in kbdebug.txt)")
    else:
        for x in pn:
            print(f"  {x['file']}:{x['line_no']}  {x['line']}")

    # Optional JSON export
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nDetailed report written to {args.json}")


if __name__ == '__main__':
    main()
