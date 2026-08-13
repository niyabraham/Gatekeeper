import re
import base64

# ---------------------------------------------------------------------------
# Character range constants for Chr() decoding
# ---------------------------------------------------------------------------

CHR_MIN_PRINTABLE = 32   # Space — lowest printable ASCII codepoint
CHR_MAX_PRINTABLE = 126  # Tilde (~) — highest printable ASCII codepoint

# Minimum number of complete base64 groups (4 chars each) required before
# attempting a decode — filters coincidental base64-like substrings.
BASE64_MIN_GROUPS = 5


class MacroDeobfuscator:
    def __init__(self, code_snippets=None):
        """
        Initialises the deobfuscator with a list of code strings to process.

        Args:
            code_snippets: List of VBA code strings to deobfuscate.
                           Defaults to an empty list if not provided.
        """
        self.code_snippets = code_snippets or []

    def clean_strings(self, scan_results=None) -> list:
        """
        Cleans common VBA obfuscation techniques in this exact order:

          1. Underscore line continuation stripping
          2. Chr() / ChrW() / Chr$() character decoding
          3. String concatenation reconstruction ("A" & "B" -> "AB")
          4. Base64 payload extraction

        Order matters: Chr() decoding produces quoted single characters
        that must be collapsed by the concat step before rule matching
        can see them as complete keywords (e.g. "Shell", "powershell").

        Args:
            scan_results: Optional dict of scan findings. If provided,
                          finding descriptions are appended to the snippet
                          list for secondary deobfuscation coverage.

        Returns:
            List of result dicts, one per snippet, each containing:
                original_snippet (str)    — first 100 chars of input
                normalized_code (str)     — fully deobfuscated output
                chr_decoded_count (int)   — number of Chr() calls decoded
                base64_artifacts (list)   — decoded base64 payloads found
        """
        snippets = list(self.code_snippets)

        if scan_results and isinstance(scan_results, dict):
            for finding in scan_results.get("findings", []):
                desc = finding.get("desc", "")
                if desc:
                    snippets.append(desc)

        if not snippets:
            snippets = [""]

        cleaned_results = []

        for code in snippets:
            # Step 1: Strip VBA underscore line continuations
            normalized = re.sub(r'_\s*\r?\n', '', code)

            # Step 2: Decode Chr(n), ChrW(n), Chr$(n), Chr(&Hnn)
            normalized, chr_hits = self._decode_chr_sequences(normalized)

            # Step 3: Collapse string concatenations
            # Two passes: first handles direct "A" & "B",
            # second handles Chr-decoded residuals from step 2
            normalized = re.sub(r'"\s*&\s*"', '', normalized)
            normalized = re.sub(r'"\s*&\s*"', '', normalized)

            # Step 4: Base64 extraction on the now-clean corpus
            base64_candidates = self._extract_base64_strings(normalized)

            cleaned_results.append({
                "original_snippet": code[:100] + "..." if len(code) > 100 else code,
                "normalized_code": normalized,
                "chr_decoded_count": chr_hits,
                "base64_artifacts": base64_candidates
            })

        return cleaned_results

    def _decode_chr_sequences(self, code: str) -> tuple:
        """
        Decodes VBA Chr-family calls into their literal character equivalents.

        Handles all real-world variants seen in macro malware:
            Chr(83)    -> "S"   decimal argument
            ChrW(83)   -> "S"   wide-char variant (same Unicode codepoint)
            Chr$(83)   -> "S"   string-typed variant
            Chr(&H53)  -> "S"   hexadecimal argument

        Only printable ASCII (CHR_MIN_PRINTABLE to CHR_MAX_PRINTABLE) is
        decoded to a quoted character. Non-printable codepoints are left as
        the original Chr() call.

        Args:
            code: Raw VBA code string possibly containing Chr() calls.

        Returns:
            Tuple of (decoded_code: str, hit_count: int).
        """
        pattern = re.compile(
            r'Chr[W$]?\s*\(\s*(?:&H([0-9A-Fa-f]+)|(\d+))\s*\)',
            re.IGNORECASE
        )

        hit_count = 0

        def replace(match):
            nonlocal hit_count
            hex_part = match.group(1)
            dec_part = match.group(2)
            try:
                code_point = int(hex_part, 16) if hex_part else int(dec_part)
                if CHR_MIN_PRINTABLE <= code_point <= CHR_MAX_PRINTABLE:
                    hit_count += 1
                    return f'"{chr(code_point)}"'
                return match.group(0)
            except (ValueError, OverflowError):
                return match.group(0)

        decoded = pattern.sub(replace, code)
        return decoded, hit_count

    def _extract_base64_strings(self, text: str) -> list:
        """
        Finds and decodes potential base64-encoded payloads embedded in code.

        Args:
            text: Normalised VBA code string to scan for base64 blobs.

        Returns:
            List of dicts, each with keys:
                encoded (str)  — the original base64 string found
                decoded (str)  — the decoded plaintext payload
        """
        pattern = (
            r'(?:[A-Za-z0-9+/]{4}){' + str(BASE64_MIN_GROUPS) + r',}'
            r'(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        )
        matches = re.findall(pattern, text)
        decoded_strings = []

        for match in matches:
            try:
                decoded_bytes = base64.b64decode(match)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                if all(CHR_MIN_PRINTABLE <= ord(c) < 127 for c in decoded_text if c not in '\r\n\t'):
                    decoded_strings.append({
                        "encoded": match,
                        "decoded": decoded_text
                    })
            except Exception:
                continue

        return decoded_strings
