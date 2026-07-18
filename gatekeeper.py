"""
gatekeeper.py — Entry point. Ties scanner + extractor into one pipeline.

Flow:
    1. Scan file (static analysis only, zero execution).
    2. If verdict is SUSPICIOUS / ENCRYPTED / ERROR -> quarantine, block,
       write an audit record. (Collisions prevented by timestamping).
    3. If verdict is CLEAN / MACROS_BENIGN -> extract all data to a clean
       macro-free .xlsx, write an audit record.
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

    # 1. PRE-FLIGHT CHECK: Ensure file exists before touching it
    if not os.path.exists(file_path):
        result = {
            "file": os.path.basename(file_path),
            "status": "BLOCKED",
            "verdict": "ERROR",
            "message": "File not found at specified path.",
            "findings": [],
            "quarantined_to": None,
        }
        _log(result)
        return result

    filename = os.path.basename(file_path)
    scan_result = scan_file(file_path)
    
    # Generate timestamp for unique naming
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 2. BLOCKING LOGIC
    if scan_result["verdict"] in BLOCKING_VERDICTS:
        # Use timestamp to prevent overwriting existing quarantined files
        dest_filename = f"{timestamp_str}_{filename}"
        dest = os.path.join(QUARANTINE_DIR, dest_filename)
        
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

    # 3. EXTRACTION LOGIC (CLEAN or MACROS_BENIGN)
    stem = os.path.splitext(filename)[0]
    output_path = os.path.join(OUTPUT_DIR, f"clean_{stem}.xlsx")

    try:
        extraction_report = extract_all_data(file_path, output_path)
    except Exception as e:
        # Fail closed: Scanner ok, but extraction failed (corrupt/unreadable)
        dest_filename = f"CORRUPT_{timestamp_str}_{filename}"
        dest = os.path.join(QUARANTINE_DIR, dest_filename)
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