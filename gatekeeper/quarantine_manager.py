import os
import shutil
import hashlib
import json
from datetime import datetime

# ---------------------------------------------------------------------------
# Quarantine manager constants
# ---------------------------------------------------------------------------

SHA256_CHUNK_SIZE = 4096  # Bytes per read when streaming files for SHA-256 hashing


class QuarantineManager:
    def __init__(self, quarantine_dir: str = None):
        """
        Initialises the quarantine manager.

        The quarantine directory itself is NOT created here — only when
        quarantine_file() is actually called to copy a file into it. This
        keeps QuarantineManager safe to construct even when no file ends
        up needing quarantine, so an empty quarantine/ folder is never
        created as a side effect of merely running a scan (relevant now
        that GatekeeperPipeline's copy_files=False mode may construct
        this class without ever calling quarantine_file()).

        Output directories are resolved relative to the caller's working
        directory, not the installed package location — wherever the
        consuming application runs from is where Gatekeeper writes output.

        Args:
            quarantine_dir: Explicit path to the quarantine directory.
                            Defaults to 'quarantine/' in the current working
                            directory if not provided.
        """
        if quarantine_dir is None:
            quarantine_dir = os.path.join(os.getcwd(), "quarantine")

        self.quarantine_dir = os.path.abspath(quarantine_dir)

        # Audit log path — same working directory convention. logs/ IS
        # created eagerly since audit logging always happens, unlike
        # quarantine copying which is now optional.
        logs_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(logs_dir, exist_ok=True)
        self.audit_log_path = os.path.join(logs_dir, "audit_log.jsonl")

    def quarantine_file(self, file_path: str) -> str:
        """
        Isolates a malicious file by copying it into the quarantine directory
        with a unique timestamped filename. Creates the quarantine directory
        on first use if it doesn't already exist.

        Uses shutil.copy (not move) to preserve the original at its source
        location for chain-of-custody verification.

        Args:
            file_path: Absolute path to the file to quarantine.

        Returns:
            Absolute path of the quarantined copy.

        Raises:
            FileNotFoundError: If the source file does not exist.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File to quarantine not found: {file_path}")

        os.makedirs(self.quarantine_dir, exist_ok=True)

        filename = os.path.basename(file_path)
        base_name, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        target_filename = f"{base_name}_quarantined_{timestamp}{ext}"
        destination = os.path.join(self.quarantine_dir, target_filename)

        shutil.copy(file_path, destination)
        return destination

    def triage_quarantine(self) -> list:
        """
        Returns enriched metadata for every file currently in quarantine.

        Cross-references audit_log.jsonl to pull the original risk score,
        findings count, and scan timestamp for each quarantined file.

        Returns:
            List of dicts, one per quarantined file, each containing:
                filename, file_path, sha256_hash, size_bytes,
                risk_score, findings_count, scanned_at, status
        """
        if not os.path.exists(self.quarantine_dir):
            return []

        audit_lookup = self._build_audit_lookup()
        reports = []

        for filename in sorted(os.listdir(self.quarantine_dir)):
            file_path = os.path.join(self.quarantine_dir, filename)
            if not os.path.isfile(file_path):
                continue

            sha256 = self._compute_sha256(file_path)
            audit_entry = audit_lookup.get(filename, {})

            reports.append({
                "filename":       filename,
                "file_path":      file_path,
                "sha256_hash":    sha256,
                "size_bytes":     os.path.getsize(file_path),
                "risk_score":     audit_entry.get("risk_score", "N/A"),
                "findings_count": audit_entry.get("findings_count", "N/A"),
                "scanned_at":     audit_entry.get("timestamp", "N/A"),
                "status":         "Quarantined - Pending Analyst Review"
            })

        return reports

    def _compute_sha256(self, file_path: str) -> str:
        """
        Computes the SHA-256 hash of a file using streaming reads.

        Args:
            file_path: Absolute path to the file to hash.

        Returns:
            Lowercase hex digest string, or 'N/A' if the file cannot be read.
        """
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(SHA256_CHUNK_SIZE), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return "N/A"

    def _build_audit_lookup(self) -> dict:
        """
        Reads audit_log.jsonl and builds a filename -> audit entry mapping.

        Returns:
            Dict mapping quarantined filename (str) -> audit log entry (dict).
        """
        lookup = {}
        if not os.path.exists(self.audit_log_path):
            return lookup
        try:
            with open(self.audit_log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        dest = entry.get("destination", "")
                        if dest:
                            lookup[os.path.basename(dest)] = entry
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        return lookup
