import os
import configparser
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Shortcut scanners — ported from company validators.py
# (validate_lnk_safety, validate_url_file_safety).
#
# Windows shortcuts (.lnk) and Internet Shortcuts (.url) are never executed
# directly by opening them in a browser or document viewer, but a supplier
# could submit one that silently points at a dangerous local command or a
# malicious URL scheme — the danger is in what happens if someone
# double-clicks it later.
# ---------------------------------------------------------------------------

LNK_THRESHOLD = 50  # Same tier as macro-enabled Office — direct execution risk
URL_THRESHOLD = 55

WEIGHT_INVALID_LNK       = 50  # Magic bytes don't match the LNK file format
WEIGHT_DANGEROUS_TARGET  = 45  # Shortcut points at a shell/script interpreter
WEIGHT_UNC_PATH          = 30  # Points at a UNC path — used for hash-leak / NTLM relay attacks
WEIGHT_INVALID_URL_FILE  = 40  # Malformed INI structure or missing URL entry
WEIGHT_DANGEROUS_SCHEME  = 60  # file:// ftp:// javascript: data: vbscript: — no legitimate use in a .url shortcut

# Valid .lnk files begin with this 4-byte header (HeaderSize field = 0x4C).
LNK_MAGIC = b"\x4c\x00\x00\x00"

DANGEROUS_LNK_TARGETS = (
    b"cmd.exe", b"powershell", b"wscript",
    b"cscript", b"mshta", b"rundll32",
)

# Dangerous URL schemes for Internet Shortcut (.url) files — same set as
# validators.py's BLOCKED_SCHEMES.
DANGEROUS_URL_SCHEMES = {"file", "ftp", "javascript", "data", "vbscript"}


class LNKScanner:
    def __init__(self, file_path: str):
        """
        Initialises the scanner for a single Windows shortcut (.lnk) file.

        Args:
            file_path: Absolute path to the .lnk file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Validates the LNK magic bytes and scans the target path for
        dangerous interpreters and UNC paths.

        Unlike validators.py (which raises a hard ValidationError on an
        invalid LNK), Gatekeeper folds this into the weighted score/verdict
        model so every scan produces one consistent result shape — an
        invalid magic byte is scored heavily enough to block on its own.

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        with open(self.file_path, "rb") as f:
            content = f.read()

        extracted_text = content[:500].decode("latin-1", errors="ignore")

        if content[:4] != LNK_MAGIC:
            self.findings.append({
                "rule":   "LNK_Invalid_Format",
                "weight": WEIGHT_INVALID_LNK,
                "desc":   "File does not have a valid LNK header — corrupted or disguised file."
            })
            self.risk_score += WEIGHT_INVALID_LNK
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": extracted_text, "threshold": LNK_THRESHOLD}

        content_lower = content.lower()
        for target in DANGEROUS_LNK_TARGETS:
            if target in content_lower:
                self._add_unique({
                    "rule":   "LNK_Dangerous_Target",
                    "weight": WEIGHT_DANGEROUS_TARGET,
                    "desc":   f"Shortcut target references '{target.decode(errors='ignore')}'."
                })

        if b"\\\\" in content:
            self._add_unique({
                "rule":   "LNK_UNC_Path",
                "weight": WEIGHT_UNC_PATH,
                "desc":   "Shortcut references a UNC (\\\\server\\share) path — can be used "
                          "to leak NTLM credentials on open."
            })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text,
            "threshold":      LNK_THRESHOLD
        }

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]


class URLFileScanner:
    def __init__(self, file_path: str):
        """
        Initialises the scanner for a single Internet Shortcut (.url) file.

        Args:
            file_path: Absolute path to the .url file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Parses the .url file's INI structure and checks the target URL's
        scheme against a blocklist of dangerous schemes.

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
            self.findings.append({"rule": "URL_ReadError", "weight": 10, "desc": f"Could not read file: {e}"})
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": "", "threshold": URL_THRESHOLD}

        extracted_text = content[:500]

        config = configparser.ConfigParser()
        try:
            config.read_string(content)
        except configparser.Error as e:
            self.findings.append({
                "rule":   "URL_Invalid_Format",
                "weight": WEIGHT_INVALID_URL_FILE,
                "desc":   f"Malformed INI structure: {e}"
            })
            self.risk_score += WEIGHT_INVALID_URL_FILE
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": extracted_text, "threshold": URL_THRESHOLD}

        if "InternetShortcut" not in config:
            self.findings.append({
                "rule":   "URL_Missing_Section",
                "weight": WEIGHT_INVALID_URL_FILE,
                "desc":   "File is missing the required [InternetShortcut] section."
            })
            self.risk_score += WEIGHT_INVALID_URL_FILE
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": extracted_text, "threshold": URL_THRESHOLD}

        url = config["InternetShortcut"].get("URL", "")
        if not url:
            self.findings.append({
                "rule":   "URL_No_Target",
                "weight": WEIGHT_INVALID_URL_FILE,
                "desc":   "Shortcut contains no target URL."
            })
            self.risk_score += WEIGHT_INVALID_URL_FILE
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": extracted_text, "threshold": URL_THRESHOLD}

        scheme = urlparse(url).scheme.lower()
        if scheme in DANGEROUS_URL_SCHEMES:
            self._add_unique({
                "rule":   "URL_Dangerous_Scheme",
                "weight": WEIGHT_DANGEROUS_SCHEME,
                "desc":   f"Shortcut uses dangerous scheme '{scheme}://' — target: {url[:100]}"
            })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text,
            "threshold":      URL_THRESHOLD
        }

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
