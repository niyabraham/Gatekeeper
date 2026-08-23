"""
Gatekeeper — Multi-format document security scanner.

Scans macro-enabled Office files, PDFs, images, OOXML documents, email
messages, CSV/XML/HTML data files, and Windows/Internet shortcuts for
malicious content using static analysis, YARA rules, and deobfuscation.

Format is detected from the file's actual content, not its filename
extension — see gatekeeper.content_sniffer.

Quick start::

    from gatekeeper import GatekeeperPipeline

    result = GatekeeperPipeline("invoice.xlsm").execute()
    print(result["verdict"])        # "CLEAN" or "BLOCKED"
    print(result["risk_score"])     # cumulative weighted score
    print(result["risk_threshold"]) # per-format threshold
    print(result["file_copied"])    # whether a physical copy was made
    for finding in result["findings"]:
        print(finding["rule"], finding["weight"], finding["desc"])

Results-only mode — skip the physical file copy, e.g. when the calling
application already manages its own file storage::

    result = GatekeeperPipeline("invoice.xlsm", copy_files=False).execute()
    # verdict, risk_score, and findings are still fully computed and still
    # logged to logs/audit_log.jsonl; result["destination"] is None and no
    # file is written to quarantine/ or clean_output/.

Supported formats (19, detected by content)::

    .xlsm .xls .xlsb .xltm .doc .docm .dotm    Macro-enabled Office
    .pdf                                       PDF documents
    .jpg  .jpeg .png                           Images
    .docx .xlsx                                Open XML (no macros)
    .msg  .eml                                 Email messages
    .md   .csv  .xml  .html                    Text / data formats
    .lnk  .url                                 Shortcuts

Output directories (created in working directory only if copy_files=True
and only once actually needed)::

    quarantine/    BLOCKED files are copied here
    clean_output/  CLEAN files are copied here
    logs/          audit_log.jsonl — append-only scan records, always written
"""

from gatekeeper.pipeline import GatekeeperPipeline
from gatekeeper.file_router import FileRouter, FORMAT_ROUTER
from gatekeeper.quarantine_manager import QuarantineManager
from gatekeeper.deobfuscator import MacroDeobfuscator
from gatekeeper.content_sniffer import detect_format

__version__ = "1.1.0"
__all__ = [
    "GatekeeperPipeline",
    "FileRouter",
    "FORMAT_ROUTER",
    "QuarantineManager",
    "MacroDeobfuscator",
    "detect_format",
]
