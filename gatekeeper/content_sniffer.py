"""
gatekeeper.content_sniffer
===========================
Determines what a file actually IS, from its bytes, independent of what
its filename extension claims. This is the core piece of Gatekeeper's
content-based routing: an attacker who renames a malicious payload to
end in ".pdf" should not get PDFScanner's trust just because the
filename says so.

No external dependency (no python-magic / libmagic) is used, since
python-magic needs a compiled libmagic binary that is awkward to install
reliably on Windows. Every format Gatekeeper supports already has either
a well-documented magic-byte signature or a well-documented internal
structure, so a small hand-rolled sniffer covers the full format set
without adding install friction.

Detection tiers (checked in order, most reliable first):
    1. Binary magic bytes             — PDF, PNG, JPEG, LNK, ZIP, OLE2
    2. ZIP-container disambiguation   — reads [Content_Types].xml to tell
                                         .docx / .xlsx / .docm / .xlsm /
                                         .dotm / .xltm / .xlsb apart
    3. OLE2-container disambiguation  — reads internal stream names to
                                         tell legacy .doc / .xls / .msg apart
    4. Text-structure heuristics      — .xml, .html, .url, .eml have
                                         recognisable opening structure

Formats with NO reliable content signature at all — .csv, .md — are
handled separately by classify_ambiguous_text(), which is honest about
the fact that content alone cannot always distinguish them and uses the
claimed extension as a tiebreaker alongside lightweight structural checks.
"""

import os
import re
import zipfile

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

# ---------------------------------------------------------------------------
# Binary magic-byte signatures
# ---------------------------------------------------------------------------

SIG_OLE2 = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
SIG_PNG  = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
SIG_JPEG = bytes([0xFF, 0xD8, 0xFF])
SIG_PDF  = b"%PDF-"
SIG_ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

# LNK: 4-byte HeaderSize (always 0x4C) followed by the fixed LNK CLSID.
SIG_LNK_HEADER = bytes([0x4C, 0x00, 0x00, 0x00])
SIG_LNK_CLSID  = bytes([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46])

# OOXML Content-Type strings -> canonical extension. Checked as substrings
# against the [Content_Types].xml override for the main document part,
# since this is what actually distinguishes workbook vs template vs
# macro-enabled vs binary — far more reliable than "does vbaProject.bin exist".
OOXML_CONTENT_TYPE_MAP = [
    ("spreadsheetml.sheet.macroEnabled.main",    ".xlsm"),
    ("spreadsheetml.template.macroEnabled.main", ".xltm"),
    ("spreadsheetml.sheet.binary.macroEnabled",  ".xlsb"),
    ("spreadsheetml.sheet.main",                 ".xlsx"),
    ("wordprocessingml.document.macroEnabled.main", ".docm"),
    ("wordprocessingml.template.macroEnabled.main", ".dotm"),
    ("wordprocessingml.document.main",           ".docx"),
]

# Text-structure heuristics for formats with no binary signature.
RFC822_HEADER_RE = re.compile(
    rb'^(from|to|subject|date|received|return-path|message-id|mime-version)\s*:',
    re.IGNORECASE
)


def detect_format(file_path: str) -> str | None:
    """
    Determines the actual file format from its content.

    Returns:
        A canonical extension key (e.g. ".pdf", ".xlsm", ".docx") matching
        FORMAT_ROUTER's keys, or None if the content doesn't match any
        binary signature or structural heuristic — meaning it's either an
        ambiguous plain-text format (.csv/.md, resolved separately by
        classify_ambiguous_text) or genuinely unidentifiable content.
    """
    with open(file_path, "rb") as f:
        header = f.read(4096)

    if not header:
        return None

    # --- Tier 1: unambiguous binary signatures ---
    if header[:8] == SIG_PNG:
        return ".png"
    if header[:3] == SIG_JPEG:
        return ".jpg"
    if header[:5] == SIG_PDF or SIG_PDF in header[:1024]:
        return ".pdf"
    if header[:4] == SIG_LNK_HEADER and header[4:20] == SIG_LNK_CLSID:
        return ".lnk"

    if header[:8] == SIG_OLE2:
        return _detect_ole2_subtype(file_path)

    if header[:4] in SIG_ZIP_PREFIXES:
        return _detect_zip_subtype(file_path)

    # --- Tier 4: text-structure heuristics ---
    return _detect_text_structure(header)


def _detect_zip_subtype(file_path: str) -> str | None:
    """
    Disambiguates a ZIP container into its specific OOXML format by
    reading the Content-Type declared for the main document part in
    [Content_Types].xml — the authoritative source for "what is this
    file", per the OOXML spec, rather than inferring from which member
    files happen to be present.
    """
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            names = zf.namelist()

            if "[Content_Types].xml" not in names:
                return None  # Valid zip, but not an OOXML package we recognise

            ct_content = zf.read("[Content_Types].xml").decode("utf-8", errors="ignore")

            for marker, ext in OOXML_CONTENT_TYPE_MAP:
                if marker in ct_content:
                    return ext

            # Content-Types present but didn't match a known marker — fall
            # back to member-file presence as a second opinion.
            has_vba = "xl/vbaProject.bin" in names or "word/vbaProject.bin" in names
            if any(n.startswith("xl/") for n in names):
                return ".xlsm" if has_vba else ".xlsx"
            if any(n.startswith("word/") for n in names):
                return ".docm" if has_vba else ".docx"

            return None
    except (zipfile.BadZipFile, KeyError, OSError):
        return None


def _detect_ole2_subtype(file_path: str) -> str | None:
    """
    Disambiguates an OLE2 compound file into legacy .doc / .xls / .msg by
    checking for the stream names each format is documented to contain.
    Falls back to ".doc" (routes to the macro scanner, which safely
    handles a file with no macros) if the container is OLE2 but doesn't
    match a known stream signature — safer than returning None and
    losing the scan entirely.
    """
    if not OLEFILE_AVAILABLE:
        # oletools (a hard Gatekeeper dependency) pulls in olefile, so this
        # branch should not normally be reached — kept as a safety net.
        return ".doc"

    try:
        ole = olefile.OleFileIO(file_path)
        try:
            streams = {"/".join(s) for s in ole.listdir()}
        finally:
            ole.close()
    except Exception:
        return ".doc"

    if any("__properties_version1.0" in s or "__nameid_version1.0" in s for s in streams):
        return ".msg"
    if "WordDocument" in streams:
        return ".doc"
    if "Workbook" in streams or "Book" in streams:
        return ".xls"

    # OLE2 container, no recognised stream — most conservative safe choice
    # is still to run it through macro analysis rather than drop the scan.
    return ".doc"


def _detect_text_structure(header: bytes) -> str | None:
    """
    Checks for structural markers unique to .url, .xml, .html, and .eml.
    Returns None if the content is plain unstructured text — this is the
    genuinely ambiguous case handed off to classify_ambiguous_text().
    """
    stripped = header.lstrip()

    if stripped.lower().startswith(b"[internetshortcut]"):
        return ".url"

    if stripped.startswith(b"<?xml"):
        return ".xml"

    lowered_start = stripped[:512].lower()
    if b"<!doctype html" in lowered_start or b"<html" in lowered_start:
        return ".html"

    first_lines = stripped.split(b"\n", 10)
    for line in first_lines[:10]:
        if RFC822_HEADER_RE.match(line):
            return ".eml"

    return None


def classify_ambiguous_text(file_path: str, claimed_ext: str) -> str:
    """
    Resolves .csv vs .md when no binary/structural signature applies.

    Content alone cannot always tell these apart — a one-column CSV with
    no header looks like plain text, and a Markdown file with a table can
    look CSV-like. This uses the claimed extension as the starting
    assumption, then overrides it only when the content strongly and
    unambiguously contradicts that claim, rather than trying to be
    clever about weak signals.

    Args:
        file_path: Path to the file being classified.
        claimed_ext: The extension from the original filename.

    Returns:
        Either ".csv" or ".md" — always resolves to one of the two so
        the file still gets scanned.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            sample = f.read(4096)
    except Exception:
        return claimed_ext if claimed_ext in (".csv", ".md") else ".md"

    markdown_markers = ("# ", "## ", "```", "](", "*", "- ", "> ")
    has_markdown_syntax = any(marker in sample for marker in markdown_markers)

    lines = [l for l in sample.split("\n") if l.strip()][:10]
    delimiter_counts = [max(l.count(","), l.count("\t"), l.count(";")) for l in lines]
    looks_like_csv = (
        len(lines) >= 2
        and all(c > 0 for c in delimiter_counts)
        and len(set(delimiter_counts)) == 1  # consistent column count
    )

    if looks_like_csv and not has_markdown_syntax:
        return ".csv"
    if has_markdown_syntax and not looks_like_csv:
        return ".md"

    # Genuinely ambiguous or inconclusive — trust the claimed extension
    # rather than guess between two equally-plausible readings.
    return claimed_ext if claimed_ext in (".csv", ".md") else ".md"
