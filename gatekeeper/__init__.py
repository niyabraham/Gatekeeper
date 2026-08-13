"""
Gatekeeper — Multi-format document security scanner.

Scans macro-enabled Office files, PDFs, images, OOXML documents,
Outlook email messages, and Markdown files for malicious content
using static analysis, YARA rules, and deobfuscation.

Quick start::

    from gatekeeper import GatekeeperPipeline

    result = GatekeeperPipeline("invoice.xlsm").execute()
    print(result["verdict"])        # "CLEAN" or "BLOCKED"
    print(result["risk_score"])     # cumulative weighted score
    print(result["risk_threshold"]) # per-format threshold
    for finding in result["findings"]:
        print(finding["rule"], finding["weight"], finding["desc"])

Supported formats::

    .xlsm .xls .xlsb .xltm      Excel (macro-enabled)
    .doc  .docm .dotm            Word  (macro-enabled)
    .pdf                         PDF documents
    .jpg  .jpeg .png             Images
    .docx .xlsx                  Open XML (no macros)
    .msg                         Outlook email messages
    .md                          Markdown / plain text

Output directories (created in working directory if absent)::

    quarantine/    BLOCKED files are copied here
    clean_output/  CLEAN files are copied here
    logs/          audit_log.jsonl — append-only scan records
"""

from gatekeeper.pipeline import GatekeeperPipeline
from gatekeeper.file_router import FileRouter, FORMAT_ROUTER
from gatekeeper.quarantine_manager import QuarantineManager
from gatekeeper.deobfuscator import MacroDeobfuscator

__version__ = "1.0.0"
__all__ = [
    "GatekeeperPipeline",
    "FileRouter",
    "FORMAT_ROUTER",
    "QuarantineManager",
    "MacroDeobfuscator",
]
