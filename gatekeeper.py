"""
gatekeeper.py — Entry point. Ties scanner + extractor into one pipeline.

Flow:
    1. Scan file (static analysis only, zero execution).
    2. If verdict is SUSPICIOUS / ENCRYPTED / ERROR -> quarantine, block,
       write an audit record. Data team never gets the file.
    3. If verdict is CLEAN / MACROS_BENIGN -> extract all data to a clean
       macro-free .xlsx, write an audit record. Data team gets the clean file.

Usage:
    python gatekeeper.py path/to/supplier_file.xlsm
"""

import json
import os
import shutil
import sys
from datetime import datetime, timezone

from scanner import scan_file, BLOCKING_VERDICTS
from extractor import extract_all_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
OUTPUT_DIR = os.path.join(BASE_DIR, "clean_output")
AUDIT_LOG = os.path.join(BASE_DIR, "audit_log.jsonl")


def _log(record):
    record["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def process_file(file_path):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    filename = os.path.basename(file_path)
    scan_result = scan_file(file_path)

    if scan_result["verdict"] in BLOCKING_VERDICTS:
        dest = os.path.join(QUARANTINE_DIR, filename)
        shutil.copy(file_path, dest)
        result = {
            "file": filename,
            "status": "BLOCKED",
            "verdict": scan_result["verdict"],
            "message": scan_result["message"],
            "findings": scan_result["findings"],
            "quarantined_to": dest,
        }
        _log(result)
        return result

    # CLEAN or MACROS_BENIGN -> safe to extract
    stem = os.path.splitext(filename)[0]
    output_path = os.path.join(OUTPUT_DIR, f"clean_{stem}.xlsx")

    try:
        extraction_report = extract_all_data(file_path, output_path)
    except Exception as e:
        # Fail closed: scanner said okay, but the file isn't a valid
        # workbook openpyxl can parse (corrupt / wrong format / not
        # really Office at all). Block rather than crash or pass it on.
        dest = os.path.join(QUARANTINE_DIR, filename)
        shutil.copy(file_path, dest)
        result = {
            "file": filename,
            "status": "BLOCKED",
            "verdict": "ERROR",
            "message": f"Extraction failed, file rejected: {e}",
            "findings": scan_result["findings"],
            "quarantined_to": dest,
        }
        _log(result)
        return result

    result = {
        "file": filename,
        "status": "ALLOWED",
        "verdict": scan_result["verdict"],
        "message": scan_result["message"],
        "findings": scan_result["findings"],
        "clean_output": output_path,
        "extraction_report": extraction_report,
    }
    _log(result)
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python gatekeeper.py <path_to_excel_file>")
        sys.exit(1)

    outcome = process_file(sys.argv[1])
    print(json.dumps(outcome, indent=2))

    sys.exit(0 if outcome["status"] == "ALLOWED" else 1)