Technical Documentation

**1. Project Overview & Architecture**

The Gatekeeper project is an automated security interception, scanning, and sanitization workflow engineered to process incoming macro-enabled Excel files (`.xlsm`). Its core objective is to prevent malicious macros or hidden threats from reaching team members by automatically analyzing, quarantining dangerous payloads, and cleaning safe files before deployment.

**2. Prerequisites & Installation**

To set up and run the Gatekeeper project locally, ensure you have Python 3.8+ installed.

Setup Steps:
A. Clone the repository and navigate to the project directory:

git clone https://github.com/niyabraham/Gatekeeper.git

cd Gatekeeper

 B. Create and activate a virtual environment:

python -m venv venv

source venv/bin/activate  # On Windows use: venv\Scripts\activate

C. Install the required dependencies:

pip install -r requirements.txt



**3. Libraries & Dependencies Used**
The project relies on a combination of third-party security/data libraries and built-in Python standard libraries:

Third-Party Dependencies (`requirements.txt`)

* `oletools` (specifically `olevba`): Provides static analysis capabilities to parse Microsoft OLE2 and OpenXML macro-enabled files (`.xlsm`, `.docm`). It extracts VBA source code and scans for indicators of compromise (IOCs) and risky behaviors.
* `openpyxl`: Handles programmatic loading, data extraction, structural metric gathering (rows, columns, non-empty cells), range flattening, and saving of safe Excel workbooks.

Built-In Python Standard Libraries

* `json`: Serializes structured dictionaries and scan results into JSON format for terminal feedback and appends records into the audit log.
* `pathlib` / `os`: Manages cross-platform file paths, verifies existence, and handles physical file relocation (moving malicious files to quarantine or saving cleaned outputs).
* `datetime`: Generates precise UTC timestamps (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`) for immutable event tracking.


**4. Core Modules & Script Logic**

The project structure is broken down into modular scripts that work in tandem:

A. `gatekeeper.py` 

* Role: Acts as the primary entry point and command-line interface (CLI) wrapper.
* Logic: Accepts the target file path as an input argument, invokes the scanner, evaluates the returned verdict, routes the file to either quarantine or the extractor, and triggers the audit logging mechanism.

B. `scanner.py` (Threat Detection Engine)

* Role:Performs static analysis on the macro-enabled workbook using `oletools`.
  Logic:
* Parses the VBA streams.
* Identifies threat categories (`type`):
* **`AutoExec`:** Triggers that fire automatically upon opening (e.g., `AutoOpen`).
* **`Suspicious`:** Potentially dangerous APIs or functions (e.g., `Shell`, Hex-encoded strings used for obfuscation).
* **`IOC` (Indicator of Compromise):** References to harmful executable files (e.g., `cmd.exe`, `calc.exe`).


* Assigns a status verdict (`BLOCKED` or `ALLOWED`).


C. `extractor.py` (Safe Processing & Cleanup Engine)

* **Role:** Sanitizes and processes files that pass security validation.
  Logic:
* Uses `openpyxl` to load the allowed workbook safely without executing macros.
* Measures metrics: counts total rows, columns, and non-empty cells, and flattens merged cell ranges.
* Exports a clean, sanitized output workbook to the designated directory.


5. Step-by-Step Execution Workflow

Step 1: Ingestion & Command Execution

* Input / Command: An incoming Excel file processed via CLI:

python gatekeeper.py sample_files/malicious_calc.xlsm
Logic: The system captures the file path via command-line arguments and validates that the file exists on the local path.

Step 2: Static Analysis & Scanning
* Logic: The scanner module runs `olevba` against the target file. It inspects macros for dangerous keywords and outputs a structured findings list containing error classifications (`type`, `keyword`, `description`).

Step 3: Decision Engine Routing
The system evaluates the security verdict:
* **Condition A (High-Risk Detected):** If `AutoExec` triggers, shell commands, or IOCs are present, the verdict is set to **`BLOCKED` / `SUSPICIOUS**`.
* **Condition B (No High-Risk Keywords):** If no dangerous indicators are found (even if harmless VBA is present), the verdict is set to **`ALLOWED` / `MACROS PRESENT**`.

Step 4A: The Malicious Branch (Quarantine Isolation)
* **Triggered by:** `BLOCKED` status.
 Logic:
* The file is intercepted before any user can open it.
* Using `pathlib`, the system programmatically relocates the file out of the working folder.
* It moves the file into the `quarantine/` directory, prepending an exact UTC timestamp to the file name (e.g., `20260718_101437_malicious_calc.xlsm`).



Step 4B: The Clean Branch (Sanitization & Extraction)
* **Triggered by:** `ALLOWED` status.
  Logic:
* The file is routed to `extractor.py`.
* `openpyxl` reads the workbook structure, flattens merged ranges, and gathers metrics (sheet rows, columns, non-empty cells).
* A sanitized workbook is generated and saved into the `clean_output/` directory (e.g., `clean_output/clean_test_input.xlsx`).


Step 5: Immutable Audit Logging (`audit_log.jsonl`)
* Logic: Regardless of whether a file is blocked or allowed, a comprehensive log entry is compiled.
* **Captured Fields:** File name, status (`BLOCKED` or `ALLOWED`), verdict description, structured findings, output/quarantine file path, and precise UTC timestamp.
* **Sample Log Entry Record (`audit_log.jsonl`):**
```json
{
  "file_name": "malicious_calc.xlsm",
  "status": "BLOCKED",
  "verdict": "High-risk macros or IOCs detected",
  "findings": [
    {
      "type": "AutoExec",
      "keyword": "AutoOpen",
      "description": "Auto-execution trigger found"
    }
  ],
  "destination": "quarantine/20260718_101437_malicious_calc.xlsm",
  "timestamp": "2026-07-18T10:14:37.123456+00:00"
}

```

6. Summary of Inputs and Outputs

System Inputs:
Raw macro-enabled Excel files (`.xlsm`) provided via CLI invocation.

System Outputs:
**Terminal Feedback:** Real-time structured JSON objects detailing the scan status, messages, finding types, and target destinations.
* **Quarantined Files:** Securely isolated files stored in `quarantine/` with timestamp prefixes.
* **Clean Outputs:** Sanitized, verified Excel workbooks stored in `clean_output/`.
* **Audit Records:** Persistent, line-delimited records appended to `audit_log.jsonl`.
