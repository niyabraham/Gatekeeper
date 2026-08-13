import os
import re

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ---------------------------------------------------------------------------
# Image scanner risk weight constants
# ---------------------------------------------------------------------------

WEIGHT_SCRIPT_INJECTION   = 40  # Script/eval/shell content found in binary data
WEIGHT_SUSPICIOUS_URL     = 30  # URL with suspicious TLD found in image data
WEIGHT_EXIF_KEYWORD       = 25  # Script keyword found in EXIF metadata field
WEIGHT_STEGHIDE_MARKER    = 20  # Known steganography tool signature in metadata
WEIGHT_DECOMPRESSION_BOMB = 35  # Pixel count exceeds safe decode threshold

IMAGE_THRESHOLD = 65  # Between OOXML (55) and Markdown (70) — rare threat vector

# Ported from company validators.py (validate_image_safety): images are
# rendered via a raw <img> tag, so an oversized bitmap can exhaust decoder
# memory client-side. 50 megapixels matches the existing company threshold.
MAX_SAFE_PIXELS = 50_000_000

SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".tk", ".pw", ".top",
    ".xyz", ".club", ".ml", ".ga", ".cf", ".icu"
}

# Patterns that indicate injected scripts or shell commands in image binary
SCRIPT_PATTERNS = [
    "<script",
    "eval(",
    "unescape(",
    "javascript:",
    "powershell",
    "cmd.exe",
    "wget ",
    "curl ",
    "/bin/sh",
    "/bin/bash",
    "base64",
    "certutil",
    "mshta",
    "rundll32",
]


class ImageScanner:
    def __init__(self, file_path: str):
        """
        Initialises the image scanner for a single .jpg, .jpeg, or .png file.

        Analysis targets two threat categories:
            - Polyglot files: valid images that also contain injected scripts,
              shell commands, or URLs in their binary stream
            - EXIF metadata abuse: malicious content smuggled in metadata
              fields (Comment, Author, Software, Description, etc.)

        Args:
            file_path: Absolute path to the image file to analyse.
        """
        self.file_path  = os.path.abspath(file_path)
        self.findings   = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """
        Performs static analysis of an image file.

        Analysis covers:
            1. Raw binary scan — reads the full image as latin-1 and checks
               for injected script tags, eval/unescape patterns, shell
               commands, and URLs with suspicious TLDs
            2. EXIF metadata scan (via Pillow) — checks metadata fields for
               script content and suspicious URLs that would survive image
               re-saves and stripper tools

        Returns:
            dict with keys: risk_score (int), findings (list),
                            extracted_code (str), threshold (int)

        Raises:
            FileNotFoundError: If the target file does not exist.
        """
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"File not found: {self.file_path}")

        extracted_text = ""

        # ----------------------------------------------------------------
        # Layer 1: Raw binary content scan
        # ----------------------------------------------------------------
        try:
            with open(self.file_path, "rb") as f:
                raw = f.read()

            raw_text  = raw.decode("latin-1", errors="ignore")
            raw_lower = raw_text.lower()
            extracted_text = raw_text[:500]

            for pattern in SCRIPT_PATTERNS:
                if pattern.lower() in raw_lower:
                    self._add_unique({
                        "rule":   "Image_Script_Injection",
                        "weight": WEIGHT_SCRIPT_INJECTION,
                        "desc":   f"Script content '{pattern}' found in image binary data."
                    })

            # URL detection in raw binary
            urls = re.findall(r'https?://[^\s\'">\]){]+', raw_text)
            for url in set(urls):
                if any(tld in url.lower() for tld in SUSPICIOUS_TLDS):
                    self._add_unique({
                        "rule":   "Image_Suspicious_URL",
                        "weight": WEIGHT_SUSPICIOUS_URL,
                        "desc":   f"Suspicious URL found in image data: {url[:100]}"
                    })

        except Exception as e:
            self.findings.append({
                "rule":   "Image_ReadError",
                "weight": 10,
                "desc":   f"Could not read image binary: {e}"
            })
            self.risk_score += 10

        # ----------------------------------------------------------------
        # Layer 2: EXIF metadata scanning via Pillow
        # ----------------------------------------------------------------
        if PIL_AVAILABLE:
            try:
                img  = Image.open(self.file_path)
                info = img.info or {}

                # ------------------------------------------------------------
                # Decompression bomb check — ported from validators.py.
                # A crafted image can declare huge pixel dimensions while
                # remaining tiny on disk, exhausting memory when decoded
                # for the <img> tag.
                # ------------------------------------------------------------
                pixel_count = img.width * img.height
                if pixel_count > MAX_SAFE_PIXELS:
                    self._add_unique({
                        "rule":   "Image_Decompression_Bomb",
                        "weight": WEIGHT_DECOMPRESSION_BOMB,
                        "desc":   (
                            f"Image dimensions ({img.width}x{img.height} = "
                            f"{pixel_count:,} px) exceed the {MAX_SAFE_PIXELS:,} "
                            f"px safe-decode threshold — possible decompression bomb."
                        )
                    })

                for key, value in info.items():
                    val_str   = str(value)
                    val_lower = val_str.lower()

                    for pattern in SCRIPT_PATTERNS:
                        if pattern.lower() in val_lower:
                            self._add_unique({
                                "rule":   "Image_EXIF_Script",
                                "weight": WEIGHT_EXIF_KEYWORD,
                                "desc":   (
                                    f"Script pattern '{pattern}' found in "
                                    f"EXIF field '{key}'."
                                )
                            })

                    # URLs in EXIF fields
                    exif_urls = re.findall(r'https?://[^\s]+', val_str)
                    for url in exif_urls:
                        if any(tld in url.lower() for tld in SUSPICIOUS_TLDS):
                            self._add_unique({
                                "rule":   "Image_EXIF_Suspicious_URL",
                                "weight": WEIGHT_SUSPICIOUS_URL,
                                "desc":   (
                                    f"Suspicious URL in EXIF field '{key}': "
                                    f"{url[:100]}"
                                )
                            })

                # Known steganography tool marker
                software = info.get("Software", "")
                if "steghide" in str(software).lower():
                    self._add_unique({
                        "rule":   "Image_Steghide_Marker",
                        "weight": WEIGHT_STEGHIDE_MARKER,
                        "desc":   "steghide signature in image metadata — possible hidden payload."
                    })

            except Exception:
                pass  # Pillow parse failures are non-fatal
        else:
            self.findings.append({
                "rule":   "Image_Pillow_Unavailable",
                "weight": 0,
                "desc":   "Pillow not installed — EXIF metadata scan skipped. "
                          "Install with: pip install Pillow"
            })

        return {
            "risk_score":     self.risk_score,
            "findings":       self.findings,
            "extracted_code": extracted_text,
            "threshold":      IMAGE_THRESHOLD
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
