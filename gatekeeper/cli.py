"""
gatekeeper.cli
==============
Command-line entry point for Gatekeeper.

Installed as the `gatekeeper` console script via pyproject.toml so that
after `pip install .` the tool is available on PATH:

    gatekeeper sample_files\\invoice.xlsm
    gatekeeper --triage

Can also be invoked directly:

    python -m gatekeeper sample_files\\invoice.xlsm
"""

import os
import argparse

from gatekeeper.pipeline import GatekeeperPipeline
from gatekeeper.quarantine_manager import QuarantineManager
from gatekeeper.file_router import FORMAT_ROUTER


def main():
    """
    Entry point for the Gatekeeper CLI.

    Dispatches to one of two modes:

        File scan (default):
            gatekeeper <file>
            Supported formats: .xlsm .xls .xlsb .xltm .doc .docm .dotm
                               .pdf .jpg .jpeg .png .docx .xlsx .msg .md
            Each format has its own risk threshold and scanner.
            Files scoring >= threshold are BLOCKED and quarantined.
            Files below threshold are CLEAN and forwarded to clean_output/.

        Triage (--triage):
            gatekeeper --triage
            Lists all quarantined files with SHA-256 hashes, risk scores,
            findings counts, and scan timestamps from the audit log.
    """
    parser = argparse.ArgumentParser(
        description="Gatekeeper Multi-Format Document Security Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to the document to scan"
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help="List all quarantined files with hashes, scores, and scan details"
    )

    args    = parser.parse_args()
    manager = QuarantineManager()

    # ------------------------------------------------------------------
    # Mode: --triage
    # ------------------------------------------------------------------
    if args.triage:
        print("[*] Running Quarantine Triage Analysis...")
        reports = manager.triage_quarantine()

        if not reports:
            print("[+] Quarantine folder is currently empty.")
            return

        print(f"[+] Found {len(reports)} quarantined item(s):\n")
        for report in reports:
            print(f"    {'─' * 60}")
            print(f"    Filename     : {report['filename']}")
            print(f"    SHA-256      : {report['sha256_hash']}")
            print(f"    Size         : {report['size_bytes']} bytes")
            print(f"    Risk Score   : {report['risk_score']}")
            print(f"    Findings     : {report['findings_count']}")
            print(f"    Scanned At   : {report['scanned_at']}")
            print(f"    Status       : {report['status']}")
        print(f"    {'─' * 60}")
        return

    # ------------------------------------------------------------------
    # Mode: file scan (default)
    # ------------------------------------------------------------------
    if not args.file:
        parser.print_help()
        return

    if not os.path.exists(args.file):
        print(f"[!] File not found: {args.file}")
        return

    ext = os.path.splitext(args.file)[1].lower()
    if ext not in FORMAT_ROUTER:
        supported = ", ".join(sorted(FORMAT_ROUTER.keys()))
        print(f"[!] Unsupported file format: '{ext}'")
        print(f"    Supported: {supported}")
        return

    print(f"[*] Initializing Gatekeeper Pipeline for: {args.file}")

    try:
        pipeline = GatekeeperPipeline(args.file)
        result   = pipeline.execute()

        print(f"[+] Scan Complete.")
        print(f"    - Format         : {result['format']}")
        print(f"    - Verdict        : {result['verdict']}")
        print(f"    - Risk Score     : {result['risk_score']} / threshold {result['risk_threshold']}")
        print(f"    - Destination    : {result['destination']}")
        print(f"    - Findings Count : {len(result['findings'])}")

    except (ValueError, FileNotFoundError) as e:
        print(f"[!] {e}")


if __name__ == "__main__":
    main()
