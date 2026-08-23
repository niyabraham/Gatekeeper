"""
gatekeeper.cli
==============
Command-line entry point for Gatekeeper.

Installed as the `gatekeeper` console script via pyproject.toml so that
after `pip install .` the tool is available on PATH:

    gatekeeper sample_files\\invoice.xlsm
    gatekeeper sample_files\\invoice.xlsm --no-copy
    gatekeeper --triage

Can also be invoked directly:

    python -m gatekeeper sample_files\\invoice.xlsm
"""

import os
import argparse

from gatekeeper.pipeline import GatekeeperPipeline
from gatekeeper.quarantine_manager import QuarantineManager


def main():
    """
    Entry point for the Gatekeeper CLI.

    Dispatches to one of two modes:

        File scan (default):
            gatekeeper <file>
            Format is detected from the file's actual content, not its
            extension — see gatekeeper.content_sniffer. Each detected
            format has its own risk threshold and scanner. Files scoring
            >= threshold are BLOCKED, otherwise CLEAN.

            By default, BLOCKED files are copied to quarantine/ and CLEAN
            files are copied to clean_output/. Pass --no-copy to skip this
            and only get the scan result — verdict, score, and findings
            are always returned and always logged to logs/audit_log.jsonl
            either way; only the physical file copy is optional.

        Triage (--triage):
            gatekeeper --triage
            Lists all quarantined files with SHA-256 hashes, risk scores,
            findings counts, and scan timestamps from the audit log.
            (Only reflects scans that were run with file copying enabled.)
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
    parser.add_argument(
        "--no-copy",
        action="store_true",
        help="Scan only — do not copy the file to quarantine/ or clean_output/.\n"
             "The verdict, risk score, and findings are still fully computed\n"
             "and still logged to logs/audit_log.jsonl."
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Mode: --triage
    # ------------------------------------------------------------------
    if args.triage:
        manager = QuarantineManager()
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

    # No extension pre-check here — the format is determined by content,
    # not filename, so a file with an unfamiliar extension but recognised
    # content should still reach the scanner. GatekeeperPipeline/FileRouter
    # raise a clear ValueError below if the content truly isn't supported.

    print(f"[*] Initializing Gatekeeper Pipeline for: {args.file}")
    if args.no_copy:
        print(f"    (--no-copy: scan only, no files will be moved)")

    try:
        pipeline = GatekeeperPipeline(args.file, copy_files=not args.no_copy)
        result   = pipeline.execute()

        print(f"[+] Scan Complete.")
        print(f"    - Format         : {result['format']}")
        print(f"    - Verdict        : {result['verdict']}")
        print(f"    - Risk Score     : {result['risk_score']} / threshold {result['risk_threshold']}")
        if result["file_copied"]:
            print(f"    - Destination    : {result['destination']}")
        else:
            print(f"    - Destination    : (not copied — scan-only mode)")
        print(f"    - Findings Count : {len(result['findings'])}")

    except (ValueError, FileNotFoundError) as e:
        print(f"[!] {e}")


if __name__ == "__main__":
    main()
