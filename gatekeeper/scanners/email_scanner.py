import os
import re
import email
import email.policy

try:
    import extract_msg
    EXTRACT_MSG_AVAILABLE = True
except ImportError:
    EXTRACT_MSG_AVAILABLE = False

WEIGHT_SUSPICIOUS_ATTACHMENT = 50
WEIGHT_PHISHING_KEYWORD      = 25
WEIGHT_SUSPICIOUS_URL        = 35
WEIGHT_SPOOFED_SENDER        = 45
WEIGHT_MACRO_ATTACHMENT      = 60
WEIGHT_EXECUTABLE_ATTACHMENT = 70
WEIGHT_URGENCY_LANGUAGE      = 20
WEIGHT_CREDENTIAL_HARVESTING = 40
WEIGHT_SCRIPT_IN_BODY        = 50
WEIGHT_ENCODED_CONTENT       = 35

EMAIL_THRESHOLD = 55

# Ported from company validators.py (validate_msg_safety). An oversized
# .msg is itself a signal — legitimate business email rarely exceeds this,
# and very large files slow down extract_msg parsing disproportionately.
WEIGHT_OVERSIZED_FILE  = 30
MAX_EMAIL_SIZE_BYTES   = 50 * 1024 * 1024  # 50 MB

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".psd1", ".hta", ".jar", ".lnk",
    ".xlsm", ".xls", ".xlsb", ".docm", ".doc", ".dotm", ".pptm", ".ppam",
    ".iso", ".img", ".vhd",
}

PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "your account has been suspended",
    "unusual activity", "click here to restore", "update your payment",
    "your password will expire", "action required", "you have won", "claim your prize",
    "wire transfer", "urgent transfer", "invoice attached", "remittance advice",
    "kindly find attached", "please see attached",
]

CREDENTIAL_KEYWORDS = [
    "enter your password", "login credentials", "username and password", "sign in to verify",
    "banking details", "credit card number", "social security", "date of birth",
    "mother's maiden name", "security question",
]

URGENCY_KEYWORDS = [
    "immediate action", "within 24 hours", "account will be closed", "final notice",
    "last warning", "your account will be deleted", "respond immediately", "do not ignore",
    "failure to comply", "legal action", "action required",
]

SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".club", ".ml", ".ga", ".cf"}


class EmailScanner:
    def __init__(self, file_path: str):
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        # Size check — ported from validators.py. Flagged rather than hard
        # rejected here, consistent with Gatekeeper's score/threshold model;
        # a 50MB+ email is itself unusual enough to weigh into the verdict.
        file_size = os.path.getsize(self.file_path)
        if file_size > MAX_EMAIL_SIZE_BYTES:
            self._add_unique({
                "rule":   "Email_Oversized_File",
                "weight": WEIGHT_OVERSIZED_FILE,
                "desc":   (
                    f"Email file is {file_size / (1024*1024):.1f} MB, exceeding "
                    f"the {MAX_EMAIL_SIZE_BYTES / (1024*1024):.0f} MB expected size for legitimate mail."
                )
            })

        with open(self.file_path, "rb") as f:
            magic = f.read(8)
        is_ole2 = magic == bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        if is_ole2 and EXTRACT_MSG_AVAILABLE:
            return self._analyze_ole2_msg()
        return self._analyze_mime()

    def _analyze_ole2_msg(self) -> dict:
        extracted_text = ""
        try:
            msg          = extract_msg.openMsg(self.file_path)
            subject      = getattr(msg, "subject", "") or ""
            body         = getattr(msg, "body", "") or ""
            sender       = getattr(msg, "sender", "") or ""
            sender_email = getattr(msg, "senderEmail", "") or ""
            try:
                html_body = getattr(msg, "htmlBody", b"") or b""
                if isinstance(html_body, bytes):
                    html_body = html_body.decode("utf-8", errors="ignore")
                body += " " + html_body
            except Exception:
                pass
            extracted_text = f"Subject: {subject}\nSender: {sender} <{sender_email}>\nBody: {body[:300]}"
            self._scan_content(subject, body, sender, sender_email)
            self._scan_attachments_ole2(msg)
            msg.close()
        except Exception as e:
            self._add_unique({"rule": "Email_ParseError", "weight": 20, "desc": f"OLE2 .msg parsing error: {e}"})
        return {"risk_score": self.risk_score, "findings": self.findings,
                "extracted_code": extracted_text[:500], "threshold": EMAIL_THRESHOLD}

    def _analyze_mime(self) -> dict:
        extracted_text = ""
        try:
            with open(self.file_path, "rb") as f:
                raw = f.read()
            msg          = email.message_from_bytes(raw, policy=email.policy.default)
            subject      = str(msg.get("Subject", ""))
            sender       = str(msg.get("From", ""))
            sender_email = str(msg.get("From", ""))
            body         = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disposition  = str(part.get("Content-Disposition", ""))
                    if "attachment" in disposition:
                        self._scan_attachment_name(part.get_filename() or "")
                    elif content_type in ("text/plain", "text/html"):
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body += payload.decode("utf-8", errors="ignore") + " "
                        except Exception:
                            pass
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    body = payload.decode("utf-8", errors="ignore") if payload else str(msg.get_payload())
                except Exception:
                    body = str(msg.get_payload())
            extracted_text = f"Subject: {subject}\nFrom: {sender}\nBody preview: {body[:300]}"
            self._scan_content(subject, body, sender, sender_email)
            self._scan_raw_content(raw.decode("latin-1", errors="ignore"))
        except Exception as e:
            self._add_unique({"rule": "Email_MimeParseError", "weight": 20, "desc": f"MIME parsing error: {e}"})
        return {"risk_score": self.risk_score, "findings": self.findings,
                "extracted_code": extracted_text[:500], "threshold": EMAIL_THRESHOLD}

    def _scan_content(self, subject, body, sender, sender_email):
        full_text = (subject + " " + body).lower()
        for kw in PHISHING_KEYWORDS:
            if kw in full_text:
                self._add_unique({"rule": "Email_Phishing_Language", "weight": WEIGHT_PHISHING_KEYWORD,
                                  "desc": f"Phishing keyword detected: '{kw}'"})
        for kw in CREDENTIAL_KEYWORDS:
            if kw in full_text:
                self._add_unique({"rule": "Email_Credential_Harvesting", "weight": WEIGHT_CREDENTIAL_HARVESTING,
                                  "desc": f"Credential harvesting keyword: '{kw}'"})
        for kw in URGENCY_KEYWORDS:
            if kw in full_text:
                self._add_unique({"rule": "Email_Urgency_Manipulation", "weight": WEIGHT_URGENCY_LANGUAGE,
                                  "desc": f"Urgency manipulation language: '{kw}'"})
        if re.search(r'<script[^>]*>', body, re.IGNORECASE):
            self._add_unique({"rule": "Email_Script_In_Body", "weight": WEIGHT_SCRIPT_IN_BODY,
                              "desc": "Script tag found in email HTML body — possible XSS or JS injection."})
        for url in set(re.findall(r'https?://[^\s\'"<>&\]]+', body)):
            if any(tld in url.lower() for tld in SUSPICIOUS_TLDS):
                self._add_unique({"rule": "Email_Suspicious_URL", "weight": WEIGHT_SUSPICIOUS_URL,
                                  "desc": f"Suspicious URL with high-risk TLD: {url[:100]}"})
        if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', body):
            self._add_unique({"rule": "Email_Base64_Content", "weight": WEIGHT_ENCODED_CONTENT,
                              "desc": "Large base64-encoded block in email body — possible encoded payload."})
        if sender and sender_email:
            dm = re.search(r'@([\w.-]+)', sender)
            em = re.search(r'@([\w.-]+)', sender_email)
            if dm and em and dm.group(1).lower() != em.group(1).lower():
                self._add_unique({"rule": "Email_Sender_Spoofing", "weight": WEIGHT_SPOOFED_SENDER,
                                  "desc": f"Sender display domain '{dm.group(1)}' does not match actual domain '{em.group(1)}'"})

    def _scan_raw_content(self, raw_text):
        raw_lower = raw_text.lower()
        for tld in SUSPICIOUS_TLDS:
            if tld in raw_lower:
                self._add_unique({"rule": f"Email_Suspicious_Domain_{tld.strip('.')}", "weight": WEIGHT_SUSPICIOUS_URL,
                                  "desc": f"High-risk domain TLD '{tld}' found in email content."})
        for ext in [".xlsm", ".docm", ".xlsb", ".doc", ".xls"]:
            if ext in raw_lower:
                self._add_unique({"rule": f"Email_Macro_Attachment_Ref_{ext.strip('.')}", "weight": WEIGHT_MACRO_ATTACHMENT,
                                  "desc": f"Reference to macro-enabled attachment '{ext}' found in email."})

    def _scan_attachments_ole2(self, msg):
        for attachment in msg.attachments:
            try:
                att_name = (getattr(attachment, "longFilename", None)
                            or getattr(attachment, "shortFilename", "") or "")
                self._scan_attachment_name(att_name)
            except Exception:
                continue

    def _scan_attachment_name(self, filename):
        if not filename:
            return
        ext = os.path.splitext(filename.lower())[1]
        if ext in {".xlsm", ".xls", ".xlsb", ".docm", ".doc", ".dotm", ".pptm"}:
            self._add_unique({"rule": f"Email_Macro_Attachment_{ext.strip('.')}", "weight": WEIGHT_MACRO_ATTACHMENT,
                              "desc": f"Macro-enabled Office document attached: '{filename}'"})
        elif ext in {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".scr"}:
            self._add_unique({"rule": f"Email_Executable_Attachment_{ext.strip('.')}", "weight": WEIGHT_EXECUTABLE_ATTACHMENT,
                              "desc": f"Executable or script file attached: '{filename}'"})
        elif ext in DANGEROUS_EXTENSIONS:
            self._add_unique({"rule": f"Email_Suspicious_Attachment_{ext.strip('.')}", "weight": WEIGHT_SUSPICIOUS_ATTACHMENT,
                              "desc": f"Suspicious attachment type: '{filename}'"})
        parts = filename.lower().split(".")
        if len(parts) > 2 and parts[-1] in {"exe", "bat", "cmd", "vbs", "ps1"}:
            self._add_unique({"rule": "Email_Double_Extension", "weight": WEIGHT_EXECUTABLE_ATTACHMENT,
                              "desc": f"Double extension (disguised executable): '{filename}'"})

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
