import os
import re

WEIGHT_MALICIOUS_LINK        = 35
WEIGHT_SCRIPT_INJECTION      = 50
WEIGHT_SHELL_COMMAND         = 40
WEIGHT_SUSPICIOUS_URL        = 25
WEIGHT_ENCODED_PAYLOAD       = 45
WEIGHT_CREDENTIAL_PATTERN    = 30
WEIGHT_IP_ADDRESS_LINK       = 35
WEIGHT_REDIRECT_CHAIN        = 25

TEXT_THRESHOLD = 70

SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".pw", ".top", ".xyz", ".club", ".ml", ".ga", ".cf", ".icu", ".work", ".online"}
URL_SHORTENERS  = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "tiny.cc", "cli.gs", "url4.eu"]

DANGEROUS_SHELL_COMMANDS = [
    r'wget\s+http', r'curl\s+http', r'powershell\s+-', r'cmd\.exe\s+/c',
    r'bash\s+-c', r'eval\s*\$\(', r'python\s+-c\s+["\']import',
    r'base64\s+--decode', r'chmod\s+\+x', r'\.\/[a-zA-Z]+', r'nc\s+-[lnvz]', r'rm\s+-rf\s+/',
]

CREDENTIAL_PATTERNS = [
    r'password\s*[=:]\s*\S+', r'passwd\s*[=:]\s*\S+',
    r'api[_-]?key\s*[=:]\s*\S+', r'secret[_-]?key\s*[=:]\s*\S+',
    r'access[_-]?token\s*[=:]\s*\S+', r'private[_-]?key\s*[=:]\s*\S+',
    r'aws[_-]?secret\s*[=:]\s*\S+', r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
]


class TextScanner:
    def __init__(self, file_path: str):
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            self.findings.append({"rule": "Text_ReadError", "weight": 10, "desc": f"Could not read file: {e}"})
            return {"risk_score": self.risk_score, "findings": self.findings, "extracted_code": "", "threshold": TEXT_THRESHOLD}

        content_lower  = content.lower()
        extracted_text = content[:500]

        urls = re.findall(r'https?://[^\s\'")\]>]+', content)
        for url in set(urls):
            url_lower = url.lower()
            if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                self._add_unique({"rule": "Text_Direct_IP_Link", "weight": WEIGHT_IP_ADDRESS_LINK,
                                  "desc": f"Direct IP address URL found: {url[:100]} — bypasses DNS resolution."})
            elif any(tld in url_lower for tld in SUSPICIOUS_TLDS):
                self._add_unique({"rule": "Text_Suspicious_URL", "weight": WEIGHT_SUSPICIOUS_URL,
                                  "desc": f"URL with high-risk TLD: {url[:100]}"})
            elif any(s in url_lower for s in URL_SHORTENERS):
                self._add_unique({"rule": "Text_URL_Shortener", "weight": WEIGHT_REDIRECT_CHAIN,
                                  "desc": f"URL shortener detected: {url[:100]} — destination is obfuscated."})

        for link_text, link_url in re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content):
            if "http" in link_text.lower() and "http" in link_url:
                td = re.search(r'https?://([^/\s]+)', link_text)
                ud = re.search(r'https?://([^/\s]+)', link_url)
                if td and ud and td.group(1) != ud.group(1):
                    self._add_unique({"rule": "Text_Misleading_Link", "weight": WEIGHT_MALICIOUS_LINK,
                                      "desc": f"Misleading link: text shows '{td.group(1)}' but points to '{ud.group(1)}'"})

        for pattern, description in [
            (r'<script[^>]*>', "HTML script tag in markdown"),
            (r'javascript\s*:', "JavaScript protocol URL"),
            (r'vbscript\s*:', "VBScript protocol URL"),
            (r'onload\s*=', "HTML event handler (onload)"),
            (r'onerror\s*=', "HTML event handler (onerror)"),
            (r'onclick\s*=', "HTML event handler (onclick)"),
            (r'onmouseover\s*=', "HTML event handler (onmouseover)"),
            (r'data:text/html', "data: URI HTML injection"),
            (r'<iframe[^>]*>', "HTML iframe tag"),
            (r'<object[^>]*>', "HTML object tag"),
            (r'<embed[^>]*>', "HTML embed tag"),
        ]:
            if re.search(pattern, content_lower):
                self._add_unique({"rule": "Text_Script_Injection", "weight": WEIGHT_SCRIPT_INJECTION,
                                  "desc": f"Script injection: {description}"})

        code_blocks  = re.findall(r'```[^\n]*\n(.*?)```', content, re.DOTALL)
        inline_code  = re.findall(r'`([^`]+)`', content)
        all_code     = "\n".join(code_blocks + inline_code)
        for pattern in DANGEROUS_SHELL_COMMANDS:
            if re.search(pattern, all_code, re.IGNORECASE):
                self._add_unique({"rule": "Text_Dangerous_Command", "weight": WEIGHT_SHELL_COMMAND,
                                  "desc": f"Dangerous shell command pattern '{pattern}' found in code block."})

        for pattern in CREDENTIAL_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                self._add_unique({"rule": "Text_Credential_Exposure", "weight": WEIGHT_CREDENTIAL_PATTERN,
                                  "desc": f"Potential credential exposure: '{match.group(0)[:60]}'"})

        b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', content)
        if len(b64_matches) >= 2:
            self._add_unique({"rule": "Text_Encoded_Payload", "weight": WEIGHT_ENCODED_PAYLOAD,
                              "desc": f"Multiple large base64 blocks found ({len(b64_matches)}) — possible encoded payload."})

        return {"risk_score": self.risk_score, "findings": self.findings,
                "extracted_code": extracted_text, "threshold": TEXT_THRESHOLD}

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
