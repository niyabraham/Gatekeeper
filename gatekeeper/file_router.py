import os

from gatekeeper.content_sniffer import detect_format, classify_ambiguous_text
from gatekeeper.scanners.macro_scanner     import DocumentScanner
from gatekeeper.scanners.pdf_scanner       import PDFScanner
from gatekeeper.scanners.image_scanner     import ImageScanner
from gatekeeper.scanners.office_scanner    import OfficeScanner
from gatekeeper.scanners.email_scanner     import EmailScanner
from gatekeeper.scanners.text_scanner      import TextScanner
from gatekeeper.scanners.csv_scanner       import CSVScanner
from gatekeeper.scanners.xml_scanner       import XMLScanner
from gatekeeper.scanners.html_scanner      import HTMLScanner
from gatekeeper.scanners.shortcut_scanner  import LNKScanner, URLFileScanner

# ---------------------------------------------------------------------------
# Format routing table
# Maps canonical format keys to their scanner class and per-format threshold.
# Thresholds differ per format because threat severity and false-positive
# rates vary significantly across file types.
#
# As of the content-based routing change, these keys are matched against
# the file's DETECTED content type, not its filename extension — see
# FileRouter.__init__ and gatekeeper.content_sniffer.
# ---------------------------------------------------------------------------

FORMAT_ROUTER = {
    # Macro-enabled Office documents — VBA execution risk
    ".xlsm": (DocumentScanner, 50),
    ".xls":  (DocumentScanner, 50),
    ".xlsb": (DocumentScanner, 50),
    ".xltm": (DocumentScanner, 50),
    ".doc":  (DocumentScanner, 50),
    ".docm": (DocumentScanner, 50),
    ".dotm": (DocumentScanner, 50),

    # PDF — JS/action execution risk, higher FP rate
    ".pdf":  (PDFScanner, 60),

    # Images — steganography / polyglot, rare threat
    ".jpg":  (ImageScanner, 65),
    ".jpeg": (ImageScanner, 65),
    ".png":  (ImageScanner, 65),

    # Open XML without macros — DDE, external links, embeds
    ".docx": (OfficeScanner, 55),
    ".xlsx": (OfficeScanner, 55),

    # Outlook email / MIME email — phishing, malicious attachments
    ".msg":  (EmailScanner, 55),
    ".eml":  (EmailScanner, 55),

    # Markdown / plain text — script injection, malicious links
    ".md":   (TextScanner, 70),

    # Data / structured text — download only, never rendered
    ".csv":  (CSVScanner, 70),
    ".xml":  (XMLScanner, 65),

    # HTML — force-downloaded, never rendered
    ".html": (HTMLScanner, 60),

    # Shortcut / link files — never executed by opening, but the target matters
    ".lnk":  (LNKScanner, 50),
    ".url":  (URLFileScanner, 55),
}

# A supported extension whose content the sniffer failed to identify at
# all (Tier 1-4 all miss, and it isn't resolvable as ambiguous text either)
# is treated as a hard mismatch rather than silently trusted — this is the
# whole point of routing by content.
AMBIGUOUS_TEXT_EXTENSIONS = {".csv", ".md"}

WEIGHT_EXTENSION_MISMATCH = 50  # Content doesn't match what the filename claims


# Extensions that are cosmetically different but identical in content —
# a real .jpeg file will always sniff as ".jpg" since they share one
# magic-byte signature; this must not be treated as a mismatch.
EXTENSION_ALIASES = {
    ".jpg": {".jpg", ".jpeg"},
}


class FileRouter:
    def __init__(self, file_path: str):
        """
        Initialises the router for a single file.

        Determines the correct scanner class and per-format risk threshold
        from the file's DETECTED content type — not its filename extension.
        If the content's detected type differs from what the extension
        claims, that mismatch is recorded as a finding (self.mismatch_finding)
        that GatekeeperPipeline folds into the scan's risk score, rather
        than silently routing based on a filename that may have been chosen
        specifically to evade a naive extension-based scanner.

        Args:
            file_path: Absolute or relative path to the file to scan.

        Raises:
            ValueError: If the file's content cannot be identified as any
                        supported format (regardless of what its extension
                        claims to be).
            FileNotFoundError: If the file does not exist.
        """
        self.file_path = os.path.abspath(file_path)

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        self.claimed_ext = os.path.splitext(self.file_path)[1].lower()

        detected = detect_format(self.file_path)

        if detected is None:
            # No binary/structural signature matched. If the file claims
            # to be one of the genuinely-unsniffable plain-text formats,
            # resolve it with the dedicated CSV-vs-Markdown heuristic
            # rather than rejecting it outright.
            if self.claimed_ext in AMBIGUOUS_TEXT_EXTENSIONS:
                detected = classify_ambiguous_text(self.file_path, self.claimed_ext)
            else:
                raise ValueError(
                    f"Could not identify file content as any supported format "
                    f"(filename claims '{self.claimed_ext}'). This file's actual "
                    f"content does not match a recognised signature and cannot "
                    f"be safely scanned."
                )

        if detected not in FORMAT_ROUTER:
            # Sniffer identified a format Gatekeeper doesn't have a scanner
            # for — should not normally happen since detect_format only
            # returns keys from this module's own OOXML/binary maps, but
            # guarded defensively.
            supported = ", ".join(sorted(FORMAT_ROUTER.keys()))
            raise ValueError(
                f"Detected content type '{detected}' has no registered scanner.\n"
                f"Supported formats: {supported}"
            )

        self.ext = detected
        self._scanner_class, self.threshold = FORMAT_ROUTER[detected]

        aliases = EXTENSION_ALIASES.get(detected, {detected})
        self.extension_mismatch = (
            self.claimed_ext not in aliases
            and self.claimed_ext in FORMAT_ROUTER  # only notable if the claimed
        )                                          # extension was itself a
                                                     # plausible, supported format

        self.mismatch_finding = None
        if self.extension_mismatch:
            self.mismatch_finding = {
                "rule":   "Extension_Content_Mismatch",
                "weight": WEIGHT_EXTENSION_MISMATCH,
                "desc":   (
                    f"Filename claims '{self.claimed_ext}' but content was "
                    f"identified as '{detected}' — file was scanned and routed "
                    f"according to its actual detected content."
                )
            }

    @property
    def format_label(self) -> str:
        """
        Returns a human-readable label for the detected file format.

        Reflects the DETECTED content type, not the claimed extension —
        this is what actually determined how the file was scanned.

        Returns:
            String describing the document type (e.g. 'Excel Workbook').
        """
        labels = {
            ".xlsm": "Excel Workbook (Macro-enabled)",
            ".xls":  "Excel Workbook (Legacy)",
            ".xlsb": "Excel Workbook (Binary)",
            ".xltm": "Excel Template (Macro-enabled)",
            ".doc":  "Word Document (Legacy)",
            ".docm": "Word Document (Macro-enabled)",
            ".dotm": "Word Template (Macro-enabled)",
            ".pdf":  "PDF Document",
            ".jpg":  "JPEG Image",
            ".jpeg": "JPEG Image",
            ".png":  "PNG Image",
            ".docx": "Word Document (Open XML)",
            ".xlsx": "Excel Workbook (Open XML)",
            ".msg":  "Outlook Email Message",
            ".eml":  "MIME Email Message",
            ".md":   "Markdown / Text Document",
            ".csv":  "CSV Data File",
            ".xml":  "XML Data File",
            ".html": "HTML Document",
            ".lnk":  "Windows Shortcut",
            ".url":  "Internet Shortcut",
        }
        label = labels.get(self.ext, f"Unknown ({self.ext})")
        if self.extension_mismatch:
            label += f" [renamed from {self.claimed_ext}]"
        return label

    def get_scanner(self):
        """
        Instantiates and returns the correct scanner for this file, based
        on its detected content type.

        Returns:
            Scanner instance appropriate for the file's actual format.
        """
        return self._scanner_class(self.file_path)
