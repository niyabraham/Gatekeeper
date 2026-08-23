import os
import re
import zipfile
import xml.etree.ElementTree as ET

WEIGHT_EXTERNAL_RELATIONSHIP = 40
WEIGHT_EMBEDDED_OBJECT       = 45
WEIGHT_SUSPICIOUS_URL        = 30
WEIGHT_MACRO_REF             = 50
WEIGHT_DDE_ATTACK            = 65
WEIGHT_TEMPLATE_INJECTION    = 55
WEIGHT_SUSPICIOUS_FIELD      = 35
WEIGHT_HIDDEN_CONTENT        = 25
WEIGHT_SUSPICIOUS_CONTENT    = 20

OFFICE_THRESHOLD = 55

DANGEROUS_FIELD_CODES = ["DDEAUTO", "DDE", "INCLUDE", "INCLUDEPICTURE", "INCLUDETEXT", "LINK", "AUTOTEXT"]

SUSPICIOUS_CONTENT_KEYWORDS = [
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil",
    "bitsadmin", "wget", "curl", "invoke-expression",
    "downloadstring", "downloadfile",
]

# Ported from company validators.py (validate_ooxml_content). DOCX/XLSX are
# rendered via docx-preview, which converts the document XML to HTML in the
# browser — so markup like this can survive into the rendered page even
# though it has nothing to do with VBA macros or DDE fields.
WEIGHT_HTML_INJECTION = 45
OOXML_HTML_INJECTION_PATTERNS = [
    "javascript:", "vbscript:", "<script",
    "onload=", "onerror=", "onclick=", "onmouseover=", "onfocus=",
    "mso-hyperlink",
]


class OfficeScanner:
    def __init__(self, file_path: str):
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        if not zipfile.is_zipfile(self.file_path):
            self.findings.append({"rule": "Office_InvalidFormat", "weight": 20,
                                   "desc": "File does not appear to be a valid OOXML container."})
            self.risk_score += 20
            return {"risk_score": self.risk_score, "findings": self.findings,
                    "extracted_code": "", "threshold": OFFICE_THRESHOLD}

        extracted_text = ""

        try:
            with zipfile.ZipFile(self.file_path, "r") as zf:
                all_files = zf.namelist()

                for rel_file in [f for f in all_files if f.endswith(".rels")]:
                    try:
                        rel_content = zf.read(rel_file).decode("utf-8", errors="ignore")
                        extracted_text += rel_content + "\n"
                        root = ET.fromstring(rel_content)
                        for rel in root.findall(".//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship"):
                            rel_type    = rel.get("Type", "")
                            target      = rel.get("Target", "")
                            target_mode = rel.get("TargetMode", "Internal")
                            if target_mode == "External":
                                if "attachedTemplate" in rel_type:
                                    self._add_unique({"rule": "Office_Remote_Template_Injection", "weight": WEIGHT_TEMPLATE_INJECTION,
                                                      "desc": f"Remote template injection: document loads template from '{target}'"})
                                elif "oleObject" in rel_type:
                                    self._add_unique({"rule": "Office_External_OLE", "weight": WEIGHT_EMBEDDED_OBJECT,
                                                      "desc": f"External OLE object link: '{target}'"})
                                elif "externalLink" in rel_type:
                                    self._add_unique({"rule": "Office_External_Link", "weight": WEIGHT_EXTERNAL_RELATIONSHIP,
                                                      "desc": f"External workbook/data link: '{target}'"})
                                elif target.startswith("http"):
                                    self._add_unique({"rule": "Office_External_URL_Relationship", "weight": WEIGHT_SUSPICIOUS_URL,
                                                      "desc": f"External URL relationship: '{target[:100]}'"})
                            if "oleObject" in rel_type and target_mode == "Internal":
                                self._add_unique({"rule": "Office_Embedded_OLE_Object", "weight": WEIGHT_EMBEDDED_OBJECT,
                                                  "desc": f"Embedded OLE object found in document: '{target}'"})
                    except Exception:
                        continue

                for content_file in [f for f in all_files if f.endswith(".xml") and not f.endswith(".rels")]:
                    try:
                        content = zf.read(content_file).decode("utf-8", errors="ignore")
                        extracted_text += content + "\n"
                        for field_code in DANGEROUS_FIELD_CODES:
                            if field_code in content.upper():
                                weight = WEIGHT_DDE_ATTACK if "DDE" in field_code else WEIGHT_SUSPICIOUS_FIELD
                                self._add_unique({"rule": f"Office_Field_{field_code}", "weight": weight,
                                                  "desc": (f"Dangerous field code '{field_code}' found in {content_file}. "
                                                           f"DDE fields can execute arbitrary shell commands."
                                                           if "DDE" in field_code else
                                                           f"Suspicious field code '{field_code}' found in {content_file}.")})
                        content_lower = content.lower()
                        for keyword in SUSPICIOUS_CONTENT_KEYWORDS:
                            if keyword in content_lower:
                                self._add_unique({"rule": f"Office_Content_{keyword.replace('.','_').replace('-','_')}",
                                                  "weight": WEIGHT_SUSPICIOUS_CONTENT,
                                                  "desc": f"Shell command keyword '{keyword}' found in document content."})
                        for pattern in OOXML_HTML_INJECTION_PATTERNS:
                            if pattern in content_lower:
                                self._add_unique({"rule": f"Office_HTML_Injection_{pattern.strip(':=<').replace('.', '_').replace('-', '_')}",
                                                  "weight": WEIGHT_HTML_INJECTION,
                                                  "desc": (f"Script/markup injection pattern '{pattern}' found in {content_file} — "
                                                           f"can survive into the rendered preview.")})
                        urls = re.findall(r'https?://[^\s\'"<>&]+', content)
                        suspicious_tlds = {".ru", ".cn", ".tk", ".pw", ".xyz", ".top"}
                        for url in set(urls):
                            if any(tld in url.lower() for tld in suspicious_tlds):
                                self._add_unique({"rule": "Office_Suspicious_URL", "weight": WEIGHT_SUSPICIOUS_URL,
                                                  "desc": f"Suspicious URL with high-risk TLD: {url[:100]}"})
                    except Exception:
                        continue

                if "xl/vbaProject.bin" in all_files or "word/vbaProject.bin" in all_files:
                    self._add_unique({"rule": "Office_Unexpected_VBA", "weight": WEIGHT_MACRO_REF,
                                      "desc": "vbaProject.bin found in non-macro format — file may be mislabelled .xlsm/.docm."})

        except zipfile.BadZipFile:
            self.findings.append({"rule": "Office_CorruptZip", "weight": 20,
                                   "desc": "File appears corrupt or is not a valid ZIP/OOXML container."})
            self.risk_score += 20
        except Exception as e:
            self.findings.append({"rule": "Office_ScanError", "weight": 20, "desc": f"Office scan error: {e}"})
            self.risk_score += 20

        return {"risk_score": self.risk_score, "findings": self.findings,
                "extracted_code": extracted_text[:500], "threshold": OFFICE_THRESHOLD}

    def _add_unique(self, finding: dict):
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
