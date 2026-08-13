import os
import re

try:
    import defusedxml.ElementTree as ET
    DEFUSEDXML_AVAILABLE = True
except ImportError:
    import xml.etree.ElementTree as ET
    DEFUSEDXML_AVAILABLE = False

# ---------------------------------------------------------------------------
# XML scanner — ported from company validators.py (validate_xml_safety).
# Standalone .xml files are download-only, never rendered. The primary
# threat is XXE (XML External Entity) injection: a crafted DOCTYPE/ENTITY
# declaration can make the parser read local files or make outbound
# network requests during parsing. defusedxml blocks this while still
# allowing legitimate DOCTYPE/ENTITY usage that isn't attacker-controlled.
# ---------------------------------------------------------------------------

WEIGHT_MALFORMED_XML     = 20  # File does not parse as valid XML
WEIGHT_XXE_ATTEMPT       = 60  # External entity / DOCTYPE injection pattern detected
WEIGHT_SUSPICIOUS_URL    = 25  # Suspicious URL embedded in XML content

XML_THRESHOLD = 65  # Between OOXML (55) and Markdown (70)

SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".club"}

# Raw-text XXE indicators, checked before/alongside the parse attempt so a
# detection still fires even if defusedxml successfully neutralises the
# entity (i.e. the attempt itself is the signal, not just parser failure).
XXE_PATTERNS = [
    "<!doctype",
    "<!entity",
    "system \"",
    "system '",
    "file://",
]


class XMLScanner:
    def __init__(self, file_path: str):
        """
        Initialises the XML scanner for a single .xml file.

        Args:
            file_path: Absolute path to the XML file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Performs static analysis of an XML file.

        Analysis covers:
            1. XXE pattern scan — raw-text check for DOCTYPE/ENTITY/SYSTEM
               declarations that indicate an XXE injection attempt
            2. Safe parse — defusedxml.ElementTree blocks entity expansion;
               a parse failure here is flagged as malformed/invalid XML
            3. Suspicious URL scan — high-risk TLDs embedded in content

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        if not DEFUSEDXML_AVAILABLE:
            self.findings.append({
                "rule":   "XML_defusedxml_Unavailable",
                "weight": 0,
                "desc":   "defusedxml not installed — falling back to stdlib ElementTree, "
                          "which does not block XXE. Install with: pip install defusedxml"
            })

        try:
            with open(self.file_path, "rb") as f:
                raw_content = f.read()
        except Exception as e:
            self.findings.append({"rule": "XML_ReadError", "weight": 10, "desc": f"Could not read file: {e}"})
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": "", "threshold": XML_THRESHOLD}

        extracted_text = raw_content.decode("utf-8", errors="ignore")[:500]
        content_lower  = raw_content.decode("utf-8", errors="ignore").lower()

        # Layer 1: XXE pattern scan on raw text
        for pattern in XXE_PATTERNS:
            if pattern in content_lower:
                self._add_unique({
                    "rule":   "XML_XXE_Attempt",
                    "weight": WEIGHT_XXE_ATTEMPT,
                    "desc":   f"XXE injection indicator '{pattern}' found — external entity/DOCTYPE declaration."
                })

        # Layer 2: safe parse
        try:
            ET.fromstring(raw_content)
        except ET.ParseError as e:
            self.findings.append({
                "rule":   "XML_Malformed",
                "weight": WEIGHT_MALFORMED_XML,
                "desc":   f"Invalid or malformed XML file: {e}"
            })
            self.risk_score += WEIGHT_MALFORMED_XML
        except Exception as e:
            # defusedxml raises its own exception types (EntitiesForbidden,
            # ExternalReferenceForbidden, etc.) when it blocks an XXE attempt
            # mid-parse — treat any of these as a confirmed attempt, not just
            # a parse failure.
            self._add_unique({
                "rule":   "XML_XXE_Blocked",
                "weight": WEIGHT_XXE_ATTEMPT,
                "desc":   f"Parser blocked a potential XXE/entity expansion attempt: {e}"
            })

        # Layer 3: suspicious URL scan
        urls = re.findall(r'https?://[^\s\'"<>&]+', extracted_text)
        for url in set(urls):
            if any(tld in url.lower() for tld in SUSPICIOUS_TLDS):
                self._add_unique({
                    "rule":   "XML_Suspicious_URL",
                    "weight": WEIGHT_SUSPICIOUS_URL,
                    "desc":   f"Suspicious URL with high-risk TLD: {url[:100]}"
                })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text,
            "threshold":      XML_THRESHOLD
        }

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
