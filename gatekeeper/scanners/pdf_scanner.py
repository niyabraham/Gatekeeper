import os
import re

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

WEIGHT_JS_DETECTED          = 50
WEIGHT_LAUNCH_ACTION        = 60
WEIGHT_OPENACTION           = 30
WEIGHT_EMBEDDED_FILE        = 40
WEIGHT_AUTO_ACTION          = 35
WEIGHT_URI_ACTION           = 20
WEIGHT_SUSPICIOUS_KEYWORD   = 30
WEIGHT_ENCRYPT_SUSPICIOUS   = 25
WEIGHT_FORM_ACTION          = 20
WEIGHT_RICH_MEDIA           = 25

PDF_THRESHOLD = 60

SUSPICIOUS_PDF_KEYWORDS = [
    "/JavaScript", "/JS", "/Launch", "/OpenAction", "/AA", "/EmbeddedFile",
    "/RichMedia", "/XFA", "/AcroForm", "eval(", "unescape(",
    "String.fromCharCode", "/JBIG2Decode", "/ASCIIHexDecode", "/FlateDecode",
    "app.alert", "this.exportDataObject", "util.printf", "Collab.collectEmailInfo",
]


class PDFScanner:
    def __init__(self, file_path: str):
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        extracted_text = ""

        try:
            with open(self.file_path, "rb") as f:
                raw_content = f.read().decode("latin-1", errors="ignore")
            extracted_text = raw_content

            for keyword in SUSPICIOUS_PDF_KEYWORDS:
                if keyword.lower() in raw_content.lower():
                    if keyword in {"/JavaScript", "/JS"}:
                        weight = WEIGHT_JS_DETECTED
                        desc   = "JavaScript detected in PDF — primary exploit delivery vector."
                    elif keyword == "/Launch":
                        weight = WEIGHT_LAUNCH_ACTION
                        desc   = "/Launch action detected — executes an external program on open."
                    elif keyword == "/OpenAction":
                        weight = WEIGHT_OPENACTION
                        desc   = "/OpenAction detected — PDF executes an action automatically on open."
                    elif keyword == "/EmbeddedFile":
                        weight = WEIGHT_EMBEDDED_FILE
                        desc   = "Embedded file object found — PDF contains a hidden attachment."
                    elif keyword == "/AA":
                        weight = WEIGHT_AUTO_ACTION
                        desc   = "/AA (Additional Actions) detected — triggers on page events."
                    elif keyword == "/RichMedia":
                        weight = WEIGHT_RICH_MEDIA
                        desc   = "Rich media annotation detected — embedded Flash or video content."
                    elif keyword in {"eval(", "unescape(", "String.fromCharCode"}:
                        weight = WEIGHT_JS_DETECTED
                        desc   = f"JavaScript obfuscation pattern '{keyword}' found in PDF stream."
                    elif keyword in {"/JBIG2Decode", "util.printf", "Collab.collectEmailInfo"}:
                        weight = WEIGHT_SUSPICIOUS_KEYWORD
                        desc   = f"Known exploit indicator '{keyword}' found in PDF content."
                    else:
                        weight = WEIGHT_SUSPICIOUS_KEYWORD
                        desc   = f"Suspicious PDF keyword '{keyword}' detected in document stream."

                    finding = {
                        "rule":   f"PDF_{keyword.strip('/').replace('.', '_')}",
                        "weight": weight,
                        "desc":   desc
                    }
                    if finding not in self.findings:
                        self.findings.append(finding)
                        self.risk_score += weight

        except Exception as e:
            self.findings.append({"rule": "PDF_ReadError", "weight": 20, "desc": f"Could not read raw PDF content: {e}"})

        if PYPDF_AVAILABLE:
            try:
                reader = pypdf.PdfReader(self.file_path)

                if reader.is_encrypted:
                    self.findings.append({"rule": "PDF_Encrypted", "weight": WEIGHT_ENCRYPT_SUSPICIOUS,
                                          "desc": "PDF is encrypted — may conceal malicious content from scanners."})
                    self.risk_score += WEIGHT_ENCRYPT_SUSPICIOUS

                for page_num, page in enumerate(reader.pages):
                    page_obj = page.get_object()

                    if "/AA" in page_obj:
                        self._add_unique({"rule": "PDF_Page_AdditionalAction", "weight": WEIGHT_AUTO_ACTION,
                                          "desc": f"Page {page_num+1} has Additional Actions (/AA) — triggers on page events."})

                    if "/Annots" in page_obj:
                        for annot in page_obj["/Annots"]:
                            try:
                                annot_obj = annot.get_object()
                                if "/A" in annot_obj:
                                    action = annot_obj["/A"]
                                    if hasattr(action, "get_object"):
                                        action = action.get_object()
                                    action_type = action.get("/S", "")
                                    if action_type == "/URI":
                                        uri = action.get("/URI", "")
                                        self._add_unique({"rule": "PDF_URI_Action", "weight": WEIGHT_URI_ACTION,
                                                          "desc": f"URI action found: {str(uri)[:100]}"})
                                    elif action_type == "/Launch":
                                        self._add_unique({"rule": "PDF_Launch_Action_Annot", "weight": WEIGHT_LAUNCH_ACTION,
                                                          "desc": "Launch action in annotation — executes external program."})
                                    elif action_type == "/SubmitForm":
                                        self._add_unique({"rule": "PDF_Form_Submit", "weight": WEIGHT_FORM_ACTION,
                                                          "desc": "Form submit action — may exfiltrate data to external server."})
                            except Exception:
                                continue

            except Exception as e:
                self.findings.append({"rule": "PDF_ParseError", "weight": 0,
                                      "desc": f"pypdf structural analysis error (non-fatal): {e}"})
        else:
            self.findings.append({"rule": "PDF_pypdf_Unavailable", "weight": 0,
                                  "desc": "pypdf not installed. Install with: pip install pypdf"})

        urls = re.findall(r'https?://[^\s\'">\]){]+', extracted_text)
        suspicious_tlds = {".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".club"}
        for url in set(urls):
            if any(tld in url.lower() for tld in suspicious_tlds):
                self._add_unique({"rule": "PDF_Suspicious_URL", "weight": 25,
                                  "desc": f"Suspicious URL with high-risk TLD found: {url[:100]}"})

        return {
            "risk_score": self.risk_score, "findings": self.findings,
            "extracted_code": extracted_text[:500], "threshold": PDF_THRESHOLD
        }

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
