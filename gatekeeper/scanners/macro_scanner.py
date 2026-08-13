import os
import json
from pathlib import Path

from gatekeeper.deobfuscator import MacroDeobfuscator

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from XLMMacroDeobfuscator.deobfuscator import process_file
    XLM_AVAILABLE = True
except ImportError:
    XLM_AVAILABLE = False

from oletools.olevba import VBA_Parser

# ---------------------------------------------------------------------------
# Rules directory — resolved relative to this file so the rules load
# correctly whether Gatekeeper is installed as a package or run from source.
# gatekeeper/scanners/macro_scanner.py  ->  .parent.parent = gatekeeper/
# ---------------------------------------------------------------------------
_RULES_DIR = Path(__file__).parent.parent / "rules"

# ---------------------------------------------------------------------------
# Risk weight constants
# ---------------------------------------------------------------------------

WEIGHT_AUTOEXEC_IOC       = 30
WEIGHT_STANDARD_KEYWORD   = 10
WEIGHT_SCAN_ERROR         = 40
WEIGHT_DEOBFUSCATION      = 20
WEIGHT_XLM_MACROS         = 30
WEIGHT_YARA_DEFAULT       = 30
WEIGHT_COOCCURRENCE       = 40
COOCCURRENCE_MIN_TRIGGERS = 2

EXCEL_FORMATS = {".xlsm", ".xls", ".xlsb", ".xltm"}


class DocumentScanner:
    def __init__(self, file_path: str):
        """
        Initialises the scanner for a single document.

        Loads custom JSON rules and compiles YARA rulesets at construction
        time so the work is done once per pipeline run, not per analysis call.

        Args:
            file_path: Absolute or relative path to the workbook to analyse.
        """
        self.file_path = os.path.abspath(file_path)
        self.findings = []
        self.risk_score = 0
        self.ignored_keywords = {"Hex Strings", "Base64 Strings", "vbNormalFocus"}
        self.custom_rules = self._load_custom_rules()
        self.yara_rules = self._load_yara_rules()

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_custom_rules(self) -> list:
        """
        Loads weighted substring detection rules from the bundled
        rules/macro_rules.json. Path is resolved relative to this file
        so it works correctly after pip install.

        Returns:
            List of rule dicts, or empty list on failure.
        """
        rule_path = _RULES_DIR / "macro_rules.json"
        if rule_path.exists():
            try:
                with open(rule_path, "r") as f:
                    data = json.load(f)
                    return data.get("rules", [])
            except Exception:
                return []
        return []

    def _load_yara_rules(self):
        """
        Compiles all .yar files found under the bundled rules/yara/ directory.
        Each file is loaded into its own namespace (filename without extension).

        Returns:
            Compiled yara.Rules object, or None if yara-python is not
            installed or no rule files exist.
        """
        if not YARA_AVAILABLE:
            return None

        yara_dir = _RULES_DIR / "yara"
        if not yara_dir.exists():
            return None

        rule_files = {}
        for fname in sorted(os.listdir(yara_dir)):
            if fname.endswith(".yar") or fname.endswith(".yara"):
                namespace = os.path.splitext(fname)[0]
                rule_files[namespace] = str(yara_dir / fname)

        if not rule_files:
            return None

        try:
            compiled = yara.compile(filepaths=rule_files)
            return compiled
        except yara.SyntaxError as e:
            print(f"[!] YARA syntax error in rule files: {e}")
            return None
        except Exception as e:
            print(f"[!] YARA load error: {e}")
            return None

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def analyze(self) -> dict:
        """
        Runs all six analysis layers against the document in sequence.

        Layer execution order is critical — deobfuscation (Layer 2) must
        run before custom rules (Layer 4), YARA (Layer 5), and the heuristic
        (Layer 6) so reconstructed strings are visible to all pattern matching.

        Layers:
            1. VBA extraction via olevba — keyword scoring
            2. Deobfuscation feedback — Chr(), concat collapse, base64
            3. XLM / Excel 4.0 macro detection
            4. Custom rule pattern matching (macro_rules.json)
            5. YARA signature matching (rules/yara/*.yar)
            6. Keyword co-occurrence heuristic

        Returns:
            dict with keys:
                risk_score (int)     — cumulative weighted score
                findings (list)      — list of finding dicts
                extracted_code (str) — full deobfuscated VBA corpus
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        extracted_code_corpus = ""

        # ----------------------------------------------------------------
        # Layer 1: VBA Macro Extraction and Keyword Scoring (olevba)
        # ----------------------------------------------------------------
        vba_parser = VBA_Parser(self.file_path)
        try:
            if vba_parser.detect_vba_macros():
                self.findings.append({
                    "rule": "VBA_Macros_Detected",
                    "weight": 0,
                    "desc": "The document contains embedded VBA macros."
                })

                for _, _, _, vba_code in vba_parser.extract_all_macros():
                    if vba_code:
                        extracted_code_corpus += vba_code + "\n"

                results = vba_parser.analyze_macros()
                for kw_type, keyword, description in results:
                    if keyword in self.ignored_keywords or kw_type in self.ignored_keywords:
                        continue

                    if kw_type in {"AutoExec", "IOC"} or keyword.lower() in {
                        "shell", "createobject", "environ", "exec"
                    }:
                        weight = WEIGHT_AUTOEXEC_IOC
                    else:
                        weight = WEIGHT_STANDARD_KEYWORD

                    finding_entry = {
                        "rule": f"SuspiciousKeyword_{kw_type}",
                        "weight": weight,
                        "desc": f"Found {kw_type} keyword '{keyword}': {description}"
                    }
                    if finding_entry not in self.findings:
                        self.findings.append(finding_entry)
                        self.risk_score += weight
            else:
                self.findings.append({
                    "rule": "No_VBA_Macros",
                    "weight": 0,
                    "desc": "No active VBA macros were detected in the document."
                })

        except Exception as e:
            self.findings.append({
                "rule": "ScanError",
                "weight": WEIGHT_SCAN_ERROR,
                "desc": f"Error parsing document macros: {str(e)}"
            })
            self.risk_score += WEIGHT_SCAN_ERROR
        finally:
            vba_parser.close()

        # ----------------------------------------------------------------
        # Layer 2: Deobfuscation Feedback Loop
        # ----------------------------------------------------------------
        if extracted_code_corpus:
            deobfuscator = MacroDeobfuscator([extracted_code_corpus])
            deobfuscated_output = deobfuscator.clean_strings()

            if deobfuscated_output:
                first = deobfuscated_output[0]
                extracted_code_corpus += "\n" + first.get("normalized_code", "")

                chr_count = first.get("chr_decoded_count", 0)
                b64_count = len(first.get("base64_artifacts", []))

                if chr_count > 0 or b64_count > 0:
                    self.findings.append({
                        "rule": "Deobfuscation_Payload_Extracted",
                        "weight": WEIGHT_DEOBFUSCATION,
                        "desc": (
                            f"Deobfuscator reconstructed strings: "
                            f"{chr_count} Chr() call(s) decoded, "
                            f"{b64_count} base64 artifact(s) found."
                        )
                    })
                    self.risk_score += WEIGHT_DEOBFUSCATION

        # ----------------------------------------------------------------
        # Layer 3: Excel 4.0 / XLM Macro Scanning
        # ----------------------------------------------------------------
        file_ext = os.path.splitext(self.file_path)[1].lower()
        if XLM_AVAILABLE and file_ext in EXCEL_FORMATS:
            try:
                xlm_results = process_file(file=self.file_path, noninteractive=True)
                if xlm_results:
                    self.findings.append({
                        "rule": "XLM_Macros_Detected",
                        "weight": WEIGHT_XLM_MACROS,
                        "desc": "Legacy Excel 4.0 (XLM) macro sheets or formulas detected."
                    })
                    self.risk_score += WEIGHT_XLM_MACROS
            except Exception:
                pass

        # ----------------------------------------------------------------
        # Layer 4: Custom Rule Pattern Matching (macro_rules.json)
        # ----------------------------------------------------------------
        for rule in self.custom_rules:
            rule_name = rule.get("name")
            weight    = rule.get("weight", WEIGHT_YARA_DEFAULT)
            patterns  = rule.get("patterns", [])
            desc      = rule.get("description", "")

            matched = any(
                p.lower() in extracted_code_corpus.lower()
                for p in patterns
            )

            if matched:
                self.findings.append({
                    "rule": f"Rule_{rule_name}",
                    "weight": weight,
                    "desc": desc
                })
                self.risk_score += weight

        # ----------------------------------------------------------------
        # Layer 5: YARA Signature Matching
        # ----------------------------------------------------------------
        if self.yara_rules and extracted_code_corpus:
            try:
                matches = self.yara_rules.match(data=extracted_code_corpus)
                for match in matches:
                    weight = int(match.meta.get("weight", WEIGHT_YARA_DEFAULT))
                    desc   = match.meta.get(
                        "description",
                        f"YARA rule '{match.rule}' matched in namespace '{match.namespace}'"
                    )
                    finding_entry = {
                        "rule": f"YARA_{match.namespace}_{match.rule}",
                        "weight": weight,
                        "desc": desc
                    }
                    if finding_entry not in self.findings:
                        self.findings.append(finding_entry)
                        self.risk_score += weight
            except Exception as e:
                self.findings.append({
                    "rule": "YARA_ScanError",
                    "weight": 0,
                    "desc": f"YARA matching error: {str(e)}"
                })
        elif not YARA_AVAILABLE:
            self.findings.append({
                "rule": "YARA_Unavailable",
                "weight": 0,
                "desc": "yara-python not installed. Install it with: pip install yara-python"
            })

        # ----------------------------------------------------------------
        # Layer 6: Keyword Co-occurrence Heuristic
        # ----------------------------------------------------------------
        if extracted_code_corpus:
            behavioral_triggers = [
                "shell", "createobject", "wscript.shell",
                "environ", "exec", "powershell"
            ]
            triggered = [
                t for t in behavioral_triggers
                if t in extracted_code_corpus.lower()
            ]

            if len(triggered) >= COOCCURRENCE_MIN_TRIGGERS:
                self.findings.append({
                    "rule": "Keyword_Cooccurrence_Heuristic",
                    "weight": WEIGHT_COOCCURRENCE,
                    "desc": (
                        f"Keyword co-occurrence heuristic detected chained risk "
                        f"indicators: {', '.join(triggered)}"
                    )
                })
                self.risk_score += WEIGHT_COOCCURRENCE

        return {
            "risk_score": self.risk_score,
            "findings": self.findings,
            "extracted_code": extracted_code_corpus
        }
