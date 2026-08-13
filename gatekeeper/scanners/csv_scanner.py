import os
import csv
import io

# ---------------------------------------------------------------------------
# CSV scanner — ported from company validators.py (validate_csv_safety).
# CSV files are download-only, never rendered, but the classic threat is
# formula injection: if a cell's content is later opened in Excel/Sheets
# by a human, a leading '=', '+', '@', tab, or CR can trigger formula
# execution (CSV injection / "DDE via spreadsheet" attacks).
# ---------------------------------------------------------------------------

WEIGHT_FORMULA_INJECTION = 35  # Cell begins with a formula-triggering character
CSV_THRESHOLD = 70  # Same tier as Markdown — low-risk, download-only data format

# '-' is intentionally excluded: too many false positives from negative
# numbers in real supplier data (matches validators.py's own comment).
DANGEROUS_STARTS = ("=", "+", "@", "\t", "\r")


class CSVScanner:
    def __init__(self, file_path: str):
        """
        Initialises the CSV scanner for a single .csv file.

        Args:
            file_path: Absolute path to the CSV file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Scans a CSV file for formula-injection patterns.

        Any cell whose content starts with '=', '+', '@', a tab, or a
        carriage return is flagged — these characters are interpreted as
        formula prefixes by Excel, Google Sheets, and LibreOffice Calc,
        letting a malicious supplier file execute code or exfiltrate data
        the moment an analyst opens it in a spreadsheet application.

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
            self.findings.append({
                "rule":   "CSV_ReadError",
                "weight": 10,
                "desc":   f"Could not read file: {e}"
            })
            return {
                "risk_score":     self.risk_score,
                "findings":       self.findings,
                "extracted_code": "",
                "threshold":      CSV_THRESHOLD
            }

        extracted_text = content[:500]

        try:
            reader = csv.reader(io.StringIO(content))
            for row_num, row in enumerate(reader, start=1):
                for cell in row:
                    if cell and cell[0] in DANGEROUS_STARTS:
                        self._add_unique({
                            "rule":   "CSV_Formula_Injection",
                            "weight": WEIGHT_FORMULA_INJECTION,
                            "desc":   (
                                f"Row {row_num}: cell starting with '{cell[0]!r}' "
                                f"may trigger formula execution when opened in a "
                                f"spreadsheet application: '{cell[:60]}'"
                            )
                        })
        except csv.Error as e:
            self.findings.append({
                "rule":   "CSV_ParseError",
                "weight": 15,
                "desc":   f"Malformed CSV structure: {e}"
            })
            self.risk_score += 15

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text,
            "threshold":      CSV_THRESHOLD
        }

    def _add_unique(self, finding: dict):
        """
        Adds a finding only if it has not already been recorded,
        and accumulates its weight into the risk score.

        Args:
            finding: Finding dict with keys rule, weight, desc.
        """
        if finding not in self.findings:
            self.findings.append(finding)
            self.risk_score += finding["weight"]
