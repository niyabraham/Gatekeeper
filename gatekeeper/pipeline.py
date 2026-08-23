import os
import shutil
import json
from datetime import datetime

from gatekeeper.file_router import FileRouter
from gatekeeper.deobfuscator import MacroDeobfuscator
from gatekeeper.quarantine_manager import QuarantineManager

# ---------------------------------------------------------------------------
# Pipeline constants
# ---------------------------------------------------------------------------

WEIGHT_BASE64_PAYLOAD       = 40  # Weight for decoded base64 payload (second-pass deobfuscation)
DECODED_PAYLOAD_PREVIEW_LEN = 80  # Max characters of decoded payload shown in finding desc


class GatekeeperPipeline:
    def __init__(self, file_path: str, copy_files: bool = True):
        """
        Initialises the pipeline for a single document scan.

        Uses FileRouter to determine the correct scanner and per-format
        risk threshold based on the file's detected content type.

        Args:
            file_path: Path to the document to scan (absolute or relative).
            copy_files: If True (default), BLOCKED files are copied to
                        quarantine/ and CLEAN files are copied to
                        clean_output/, matching the original CLI behaviour.
                        If False, no files are copied anywhere — the scan
                        still runs in full and the audit log entry and
                        returned result dict are still fully populated;
                        only the physical file-copy step is skipped. This
                        is the mode a host application should use if it
                        already manages file storage/movement itself and
                        only wants Gatekeeper's verdict and findings.

        Raises:
            ValueError: If the file format is not supported.
            FileNotFoundError: If the file does not exist.
        """
        self.file_path      = os.path.abspath(file_path)
        self.filename        = os.path.basename(file_path)
        self.router          = FileRouter(self.file_path)
        self.risk_threshold  = self.router.threshold
        self.format_label    = self.router.format_label
        self.copy_files       = copy_files

        # QuarantineManager is only needed if a BLOCKED verdict will
        # actually copy the file — constructed lazily in run() rather
        # than here, so results-only mode never touches quarantine/ at all.
        self.quarantine_manager = None

        # Audit log lives in logs/ relative to the caller's working
        # directory. Results storage is the one thing that always happens
        # regardless of copy_files, so this path is always set up.
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        self.audit_log_path = os.path.join(logs_dir, "audit_log.jsonl")

    def _log_audit(self, verdict: str, risk_score: int, findings: list,
                   destination, file_copied: bool):
        """
        Appends a single scan record to logs/audit_log.jsonl.

        Uses JSON Lines format — each entry is a self-contained JSON object.
        A mid-write crash corrupts at most the current line; all previous
        entries remain valid. The log is append-only. This is written
        unconditionally, regardless of copy_files — storing the result of
        every scan is the one thing Gatekeeper always does.

        Args:
            verdict:     "CLEAN" or "BLOCKED".
            risk_score:  Final cumulative risk score for this scan.
            findings:    List of finding dicts produced by the scanner.
            destination: Path where the file was copied, or None if
                         copy_files was False for this scan.
            file_copied: Whether a physical copy was actually made.
        """
        log_entry = {
            "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filename":       self.filename,
            "file_path":      self.file_path,
            "format":         self.format_label,
            "verdict":        verdict,
            "risk_score":     risk_score,
            "risk_threshold": self.risk_threshold,
            "file_copied":    file_copied,
            "destination":    destination,
            "findings_count": len(findings),
            "findings":       findings
        }
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"[!] Error writing to audit log: {e}")

    def run(self) -> dict:
        """
        Executes the complete Gatekeeper pipeline for the initialised file.

        Steps:
            1. Format routing — FileRouter selects the correct scanner and
               per-format threshold based on the file's detected content.
            2. Static analysis — the format-specific scanner runs its full
               analysis suite and returns findings and risk score.
            3. Second-pass deobfuscation — runs MacroDeobfuscator on the
               extracted code corpus to catch base64 payloads not surfaced
               during the scanner's internal pass (meaningful for macro files).
            4. Verdict — files scoring >= per-format threshold are BLOCKED,
               otherwise CLEAN. This always happens regardless of copy_files;
               the verdict is a scoring decision, not a filesystem decision.
            5. Optional file copy — only performed if copy_files is True.
               BLOCKED files are copied to quarantine/, CLEAN files are
               copied to clean_output/ intact.
            6. Audit logging — appends the full scan record, including
               whether a file copy was made, to logs/audit_log.jsonl. This
               step always happens — it's the actual deliverable of a scan.

        Returns:
            dict with keys: risk_score, risk_threshold, verdict, format,
                            file_copied, destination, findings
        """
        # Steps 1 & 2: Route and scan
        scanner        = self.router.get_scanner()
        scan_results   = scanner.analyze()
        risk_score     = scan_results["risk_score"]
        findings       = scan_results["findings"]
        extracted_code = scan_results.get("extracted_code", "")

        # Step 1b: fold in the extension/content mismatch finding, if any.
        # Inserted first so it's the most visible entry in the audit trail —
        # a disguised file is itself the strongest signal in the scan.
        if self.router.mismatch_finding:
            findings.insert(0, self.router.mismatch_finding)
            risk_score += self.router.mismatch_finding["weight"]

        # Step 3: Second-pass deobfuscation
        if extracted_code:
            deobfuscator = MacroDeobfuscator(
                [extracted_code] if isinstance(extracted_code, str)
                else extracted_code
            )
            for res in deobfuscator.clean_strings():
                for b64 in res.get("base64_artifacts", []):
                    decoded = b64.get("decoded", "")
                    if decoded:
                        entry = {
                            "rule":   "Deobfuscated_Base64_Payload",
                            "weight": WEIGHT_BASE64_PAYLOAD,
                            "desc":   (
                                f"Decoded base64 payload reveals hidden string: "
                                f"{decoded[:DECODED_PAYLOAD_PREVIEW_LEN]}"
                            )
                        }
                        if entry not in findings:
                            findings.append(entry)
                            risk_score += WEIGHT_BASE64_PAYLOAD

        # Step 4: Verdict — always computed, independent of copy_files.
        verdict = "BLOCKED" if risk_score >= self.risk_threshold else "CLEAN"

        # Step 5: Optional file copy
        destination = None
        if self.copy_files:
            if verdict == "BLOCKED":
                if self.quarantine_manager is None:
                    self.quarantine_manager = QuarantineManager()
                destination = self.quarantine_manager.quarantine_file(self.file_path)
            else:
                clean_output_dir = os.path.join(os.getcwd(), "clean_output")
                os.makedirs(clean_output_dir, exist_ok=True)
                base_name, ext = os.path.splitext(self.filename)
                timestamp      = datetime.now().strftime("%Y%m%d%H%M%S")
                destination    = os.path.join(
                    clean_output_dir, f"{base_name}_{timestamp}{ext}"
                )
                shutil.copy(self.file_path, destination)

        # Step 6: Audit log — always written, this is the real deliverable.
        self._log_audit(verdict, risk_score, findings, destination, self.copy_files)

        return {
            "risk_score":     risk_score,
            "risk_threshold": self.risk_threshold,
            "verdict":        verdict,
            "format":         self.format_label,
            "file_copied":    self.copy_files,
            "destination":    destination,
            "findings":       findings
        }

    def execute(self) -> dict:
        """
        Public alias for run().

        Returns:
            The same dict returned by run().
        """
        return self.run()
