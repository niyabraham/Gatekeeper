import os
import re

# ---------------------------------------------------------------------------
# HTML scanner — ported from company validators.py (validate_html_safety).
# validators.py forces .html files to download as text/plain and never
# renders them in-browser, so this scanner mirrors that risk model: it
# doesn't need to fully sanitise the markup (the serving layer does that
# job), it just needs to flag whether dangerous markup is present so the
# finding shows up in the audit trail before the file reaches quarantine
# or clean_output.
#
# Implemented with the same regex-first approach used throughout the rest
# of Gatekeeper's scanners (text_scanner, office_scanner) rather than
# introducing bleach as a new dependency — the detection surface is the
# same tag/attribute set validators.py's bleach.clean() call strips.
# ---------------------------------------------------------------------------

WEIGHT_DANGEROUS_TAG    = 40  # <script>, <iframe>, <object>, <embed>
WEIGHT_EVENT_HANDLER    = 35  # onload=, onerror=, onclick=, onmouseover=
WEIGHT_DANGEROUS_SCHEME = 35  # javascript:, vbscript:, data:text/html
WEIGHT_SUSPICIOUS_URL   = 25

HTML_THRESHOLD = 60  # Never rendered, but still forced-download to the analyst

SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".club", ".ml", ".ga", ".cf"}

DANGEROUS_TAGS = [
    (r'<script[^>]*>', "<script> tag"),
    (r'<iframe[^>]*>',  "<iframe> tag"),
    (r'<object[^>]*>',  "<object> tag"),
    (r'<embed[^>]*>',   "<embed> tag"),
    (r'<applet[^>]*>',  "<applet> tag"),
    (r'<form[^>]*>',    "<form> tag — potential credential harvesting"),
]

EVENT_HANDLERS = [
    "onload=", "onerror=", "onclick=", "onmouseover=",
    "onfocus=", "onmouseout=", "onsubmit=",
]

DANGEROUS_SCHEMES = ["javascript:", "vbscript:", "data:text/html"]


class HTMLScanner:
    def __init__(self, file_path: str):
        """
        Initialises the HTML scanner for a single .html file.

        Args:
            file_path: Absolute path to the HTML file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Performs static analysis of an HTML file.

        Since the file is force-downloaded and never rendered by the
        consuming application, this scan exists to document what dangerous
        markup was present at intake time — matching validators.py's
        approach of flagging (not blocking) content that a serving-layer
        content-type override has already neutralised.

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            self.findings.append({"rule": "HTML_ReadError", "weight": 10, "desc": f"Could not read file: {e}"})
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": "", "threshold": HTML_THRESHOLD}

        content_lower  = content.lower()
        extracted_text = content[:500]

        for pattern, description in DANGEROUS_TAGS:
            if re.search(pattern, content_lower):
                self._add_unique({
                    "rule":   "HTML_Dangerous_Tag",
                    "weight": WEIGHT_DANGEROUS_TAG,
                    "desc":   f"Dangerous markup: {description}."
                })

        for handler in EVENT_HANDLERS:
            if handler in content_lower:
                self._add_unique({
                    "rule":   "HTML_Event_Handler",
                    "weight": WEIGHT_EVENT_HANDLER,
                    "desc":   f"Inline event handler '{handler}' found — executes JS on interaction."
                })

        for scheme in DANGEROUS_SCHEMES:
            if scheme in content_lower:
                self._add_unique({
                    "rule":   "HTML_Dangerous_Scheme",
                    "weight": WEIGHT_DANGEROUS_SCHEME,
                    "desc":   f"Dangerous URI scheme '{scheme}' found in markup."
                })

        urls = re.findall(r'https?://[^\s\'"<>&]+', content)
        for url in set(urls):
            if any(tld in url.lower() for tld in SUSPICIOUS_TLDS):
                self._add_unique({
                    "rule":   "HTML_Suspicious_URL",
                    "weight": WEIGHT_SUSPICIOUS_URL,
                    "desc":   f"Suspicious URL with high-risk TLD: {url[:100]}"
                })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text,
            "threshold":      HTML_THRESHOLD
        }

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
