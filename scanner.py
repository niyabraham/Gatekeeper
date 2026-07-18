"""
scanner.py — Static security scan for Excel files.

Never opens the file in Excel, never runs any macro. Uses oletools to read
the VBA project's raw code/structure and flag risky API calls.

Verdicts:
    CLEAN          - no VBA project in the file at all
    MACROS_BENIGN  - VBA present, no risky keywords found
    SUSPICIOUS     - VBA present with confirmed malicious/risky keywords
    ENCRYPTED      - file is password-protected, cannot be inspected -> block
    ERROR          - file unreadable/corrupt -> block (fail closed)
"""

from oletools.olevba import VBA_Parser
from oletools.olevba import FileOpenError

# Keywords that indicate the macro is actually performing dangerous actions.
# We whitelist these to avoid blocking benign macros (like AutoOpen) 
# that are flagged incorrectly by generic 'Suspicious' or 'AutoExec' tags.
HIGH_RISK_KEYWORDS = {
    "Shell", "CreateObject", "WinHttp", "WinHttpRequest",
    "URLDownloadToFileA", "URLDownloadToFile", "Kill", "Lib",
    "Run", "ShellExecute", "RegWrite", "RegDelete",
}


def _classify(findings, has_macros):
    """
    Classify based on actual risk indicators, not just the presence of 
    generic tags like 'Suspicious' or 'AutoExec'.
    """
    # Logic: Block ONLY if an IOC (Indicator of Compromise) is found 
    # OR if a known high-risk keyword is detected.
    risky = [
        f for f in findings
        if f["type"] == "IOC" or f["keyword"] in HIGH_RISK_KEYWORDS
    ]

    if risky:
        return "SUSPICIOUS"
    if has_macros:
        return "MACROS_BENIGN"
    return "CLEAN"


def scan_file(file_path):
    """
    Run static analysis on file_path.
    """
    parser = None
    try:
        parser = VBA_Parser(file_path)

        has_macros = parser.detect_vba_macros()
        findings = []

        if has_macros:
            # analyze_macros() returns list of (kw_type, keyword, description)
            for kw_type, keyword, description in parser.analyze_macros():
                findings.append(
                    {"type": kw_type, "keyword": keyword, "description": description}
                )

        verdict = _classify(findings, has_macros)

        messages = {
            "CLEAN": "No VBA project found.",
            "MACROS_BENIGN": f"VBA present ({len(findings)} finding(s) logged), no high-risk keywords detected.",
            "SUSPICIOUS": f"Risky macro behavior detected: {len(findings)} flagged item(s).",
        }

        return {
            "verdict": verdict,
            "findings": findings,
            "message": messages[verdict],
        }

    except FileOpenError as e:
        return {
            "verdict": "ENCRYPTED",
            "findings": [],
            "message": f"Cannot open for inspection (likely encrypted): {e}",
        }
    except Exception as e:
        return {
            "verdict": "ERROR",
            "findings": [],
            "message": f"Scan failed, file unreadable: {e}",
        }
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass


# Verdicts that must NOT reach the data team without manual review.
BLOCKING_VERDICTS = {"SUSPICIOUS", "ENCRYPTED", "ERROR"}