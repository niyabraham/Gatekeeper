"""
scanner.py — Static security scan for Excel files.

Never opens the file in Excel, never runs any macro. Uses oletools to read
the VBA project's raw code/structure and flag risky API calls (the same
technique antivirus engines use for Office documents).

Verdicts:
    CLEAN          - no VBA project in the file at all
    MACROS_BENIGN  - VBA present, no risky keywords found
    SUSPICIOUS     - VBA present with auto-exec / shell / network / obfuscation
    ENCRYPTED      - file is password-protected, cannot be inspected -> block
    ERROR          - file unreadable/corrupt -> block (fail closed)
"""

from oletools.olevba import VBA_Parser
from oletools.olevba import FileOpenError

# oletools tags each finding with a type. These three types indicate the
# macro is *doing* something risky, not just existing.
RISK_TYPES = {"AutoExec", "Suspicious", "IOC"}


def _classify(findings, has_macros):
    risky = [f for f in findings if f["type"] in RISK_TYPES]
    if risky:
        return "SUSPICIOUS"
    if has_macros:
        return "MACROS_BENIGN"
    return "CLEAN"


def scan_file(file_path):
    """
    Run static analysis on file_path.

    Returns dict:
        {
          "verdict": "CLEAN" | "MACROS_BENIGN" | "SUSPICIOUS" | "ENCRYPTED" | "ERROR",
          "findings": [ {"type": .., "keyword": .., "description": ..}, ... ],
          "message": human-readable summary
        }
    """
    parser = None
    try:
        parser = VBA_Parser(file_path)

        has_macros = parser.detect_vba_macros()
        findings = []

        if has_macros:
            # analyze_macros() returns list of (kw_type, keyword, description)
            # It performs static string/pattern analysis on the extracted
            # VBA source — it does not compile or run anything.
            for kw_type, keyword, description in parser.analyze_macros():
                findings.append(
                    {"type": kw_type, "keyword": keyword, "description": description}
                )

        verdict = _classify(findings, has_macros)

        messages = {
            "CLEAN": "No VBA project found.",
            "MACROS_BENIGN": f"VBA present ({len(findings)} keyword hit(s)), nothing risky flagged.",
            "SUSPICIOUS": f"Risky macro behavior detected: {len(findings)} flagged item(s).",
        }

        return {
            "verdict": verdict,
            "findings": findings,
            "message": messages[verdict],
        }

    except FileOpenError as e:
        # Usually means password-protected / encrypted workbook.
        return {
            "verdict": "ENCRYPTED",
            "findings": [],
            "message": f"Cannot open for inspection (likely encrypted): {e}",
        }
    except Exception as e:
        # Fail closed: anything unreadable/corrupt is treated as unsafe.
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