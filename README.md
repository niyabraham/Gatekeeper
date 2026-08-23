# Gatekeeper — Multi-Format Document Security Scanner

Gatekeeper is a Python security pipeline that statically analyzes documents submitted by external suppliers and automatically routes them based on risk. Suspicious files are quarantined; clean files are forwarded with macros intact for downstream use.

It is packaged as a pip-installable library so it can be imported directly into existing company projects.

---

## Content-Based Routing

As of this version, Gatekeeper determines a file's format from its **actual content**, not its filename extension. Previously, a malicious file renamed from `payload.exe` to `invoice.pdf` would be routed to `PDFScanner` purely because of the `.pdf` name — the file's real content was never verified.

`FileRouter` now sniffs the file (via `gatekeeper/content_sniffer.py`) using:

- **Magic bytes** for binary formats — PDF (`%PDF-`), PNG, JPEG, LNK, ZIP, OLE2
- **ZIP-internal inspection** for OOXML — reads `[Content_Types].xml` to distinguish `.docx`/`.xlsx`/`.docm`/`.xlsm`/`.dotm`/`.xltm`/`.xlsb`, since they all share the same outer ZIP signature
- **OLE2-internal inspection** for legacy Office — reads internal stream names (`WordDocument`, `Workbook`/`Book`, MAPI property streams) to distinguish `.doc`/`.xls`/`.msg`, since they all share the same outer OLE2 signature
- **Structural heuristics** for text formats without magic bytes — `.xml` (`<?xml`), `.html` (`<!doctype html`), `.url` (`[InternetShortcut]`), `.eml` (RFC822 headers)

No new heavy dependency (no `python-magic`/libmagic) was introduced — `olefile` is already a transitive dependency of `oletools`, so detection stays dependency-light and Windows-install-friendly.

**When content and extension disagree:** the file is still scanned and routed according to its **real** detected content (not silently trusted based on the filename), and an `Extension_Content_Mismatch` finding (weight 50) is added to the top of the findings list — so the disguise itself becomes part of the audit trail and risk score, on top of whatever the real scanner finds.

### The one genuine limitation: CSV vs Markdown

`.csv` and `.md` are the two formats with no reliable content signature at all — plain delimited text and plain prose share no structural markers a sniffer can key on. `classify_ambiguous_text()` uses lightweight heuristics (consistent delimiter count across rows vs. Markdown syntax like `#`, `` ``` ``, `[text](url)`) and falls back to the claimed extension when the signal is genuinely inconclusive, rather than guessing. This is an intentional, documented gap — not an oversight.

### If content cannot be identified as anything

A file whose content matches no signature at all, and isn't a plausible ambiguous-text fallback, is **rejected outright** with a clear error — Gatekeeper no longer silently scans unidentifiable content just because its extension looked legitimate.

---

## Supported File Formats

| Format | Extensions | Scanner |
|---|---|---|
| Excel (macro-enabled) | `.xlsm` `.xls` `.xlsb` `.xltm` | VBA + YARA + XLM |
| Word (macro-enabled) | `.doc` `.docm` `.dotm` | VBA + YARA |
| PDF | `.pdf` | JS/action detection |
| Images | `.jpg` `.jpeg` `.png` | Binary + EXIF + decompression bomb scan |
| Office Open XML | `.docx` `.xlsx` | DDE + relationship + HTML-injection scan |
| Outlook / MIME email | `.msg` `.eml` | Phishing + attachment + oversized-file scan |
| Markdown / text | `.md` | Link + script injection scan |
| CSV data | `.csv` | Formula-injection scan |
| XML data | `.xml` | XXE + malformed-XML scan |
| HTML | `.html` | Dangerous markup + event-handler scan |
| Windows shortcut | `.lnk` | Magic-byte + dangerous-target scan |
| Internet shortcut | `.url` | Dangerous URL-scheme scan |

---

## Installation

**Requirements:** Python 3.12, Redis (for the optional Django portal)

```powershell
# Clone the repository
git clone https://github.com/niyabraham/gatekeeper.git
cd gatekeeper

# Install the package
py -3.12 -m pip install -e .
```

All dependencies (`oletools`, `yara-python`, `pypdf`, `Pillow`, `openpyxl`, `extract-msg`, `XLMMacroDeobfuscator`) are installed automatically.

---

## CLI Usage

### Scan a file

```powershell
gatekeeper sample_files\invoice.xlsm
```

Output:

```
[*] Initializing Gatekeeper Pipeline for: sample_files\invoice.xlsm
[+] Scan Complete.
    - Format         : Excel Workbook (Macro-enabled)
    - Verdict        : BLOCKED
    - Risk Score     : 400 / threshold 50
    - Destination    : quarantine\invoice_quarantined_20260811120000.xlsm
    - Findings Count : 13
```

Files scoring **at or above** the per-format threshold are **BLOCKED** and copied to `quarantine/`.
Files scoring **below** the threshold are **CLEAN** and copied to `clean_output/` with macros intact.

### Triage quarantined files

```powershell
gatekeeper --triage
```

Lists every quarantined file with its SHA-256 hash, file size, risk score, findings count, and scan timestamp — ready for analyst review.

---

## Python API Usage

Import Gatekeeper directly into an existing project:

```python
from gatekeeper import GatekeeperPipeline

result = GatekeeperPipeline("path/to/supplier_file.xlsm").execute()

print(result["verdict"])        # "CLEAN" or "BLOCKED"
print(result["risk_score"])     # e.g. 400
print(result["risk_threshold"]) # e.g. 50
print(result["format"])         # e.g. "Excel Workbook (Macro-enabled)"
print(result["file_copied"])    # True/False — whether a physical copy was made
print(result["destination"])    # path where file was copied, or None

for finding in result["findings"]:
    print(finding["rule"], finding["weight"], finding["desc"])
```

### Results-only mode (`copy_files=False`)

By default, `GatekeeperPipeline` copies BLOCKED files to `quarantine/` and CLEAN files to `clean_output/`, matching the original CLI behaviour. This copy step is **optional** — the scan result (verdict, risk score, findings, audit log entry) is the actual deliverable of a scan, and a host application that already manages its own file storage shouldn't be forced to accept a duplicate copy of every file it submits.

```python
result = GatekeeperPipeline("supplier_file.xlsm", copy_files=False).execute()

# verdict, risk_score, and findings are fully computed exactly as before
# result["file_copied"] is False, result["destination"] is None
# no file is written to quarantine/ or clean_output/
# the scan is STILL logged in full to logs/audit_log.jsonl — that part
# is unconditional, since storing the result is the core objective
```

Equivalent CLI flag:

```powershell
gatekeeper supplier_file.xlsm --no-copy
```

`--triage` only reflects scans that had `copy_files=True`, since it lists files that physically exist in `quarantine/`.

### Other importable classes

```python
from gatekeeper import FileRouter        # route a file to its scanner
from gatekeeper import QuarantineManager # manage quarantine directory
from gatekeeper import MacroDeobfuscator # deobfuscate VBA snippets directly
from gatekeeper import FORMAT_ROUTER     # dict of supported extensions
from gatekeeper import detect_format     # sniff a file's real content type
```

---

## Analysis Pipeline

Every file passes through a six-layer analysis pipeline:

```
GatekeeperPipeline.run()
│
├── FileRouter            — selects scanner and threshold by file extension
│
├── Scanner.analyze()
│   ├── Layer 1: VBA extraction (olevba) — keyword scoring
│   ├── Layer 2: Deobfuscation — Chr() decode, concat collapse, base64
│   ├── Layer 3: XLM / Excel 4.0 macro detection
│   ├── Layer 4: Custom rule matching (rules/macro_rules.json)
│   ├── Layer 5: YARA signature matching (rules/yara/*.yar)
│   └── Layer 6: Keyword co-occurrence heuristic
│
├── Second-pass deobfuscation (base64 feedback into risk score)
│
├── Verdict & routing
│   ├── score >= threshold → BLOCKED → quarantine/
│   └── score <  threshold → CLEAN  → clean_output/
│
└── Audit log → logs/audit_log.jsonl
```

**Layer 2 runs before Layers 4–6.** This is the critical architectural decision: deobfuscated strings (e.g. Chr() sequences reconstructed into `"Shell"`) are visible to all downstream rule matching. Without this ordering, obfuscated macros evade detection entirely.

---

## Detection Layers in Detail

### Layer 1 — VBA Extraction (olevba)
Extracts all VBA macro code streams and scores keywords by type:
- **AutoExec triggers** (`Auto_Open`, `Workbook_Open`, `Document_Open`): weight 30
- **Dangerous API calls** (`Shell`, `CreateObject`, `Environ`): weight 30
- **IOC keywords** (`cmd.exe`, `payload.exe`): weight 30
- **General suspicious keywords**: weight 10

### Layer 2 — Deobfuscation
Reconstructs hidden strings before any rule matching:
- **Chr() decoding**: `Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)` → `"Shell"`
- **String concatenation collapse**: `"She" & "ll"` → `"Shell"`
- **Base64 extraction**: detects and decodes embedded base64 payloads

### Layer 3 — XLM / Excel 4.0 Macro Detection
Detects legacy Excel 4.0 macro sheets (XLM), which are a separate execution path from VBA and commonly used to evade VBA-only scanners.

### Layer 4 — Custom Rule Matching
Weighted substring rules defined in `rules/macro_rules.json`. Externalized so new rules can be added without touching Python code.

### Layer 5 — YARA Signatures
33 YARA rules across 6 files covering:

| File | Coverage |
|---|---|
| `vba_autoexec.yar` | Auto-execution entry points |
| `vba_shell_execution.yar` | Shell, PowerShell, CMD, COM object abuse |
| `vba_download_cradles.yar` | HTTP download, WebClient, URLDownloadToFile |
| `vba_obfuscation.yar` | Chr(), base64, StrReverse, hex construction |
| `vba_persistence.yar` | Registry Run keys, startup folder, scheduled tasks |
| `vba_process_injection.yar` | VirtualAlloc, WriteProcessMemory, NT APIs |

Each YARA rule carries its own `weight` in rule metadata — no weights are hardcoded in Python.

### Layer 6 — Keyword Co-occurrence Heuristic
Fires when 2 or more behavioural trigger keywords appear together in the same document (`shell`, `createobject`, `wscript.shell`, `environ`, `exec`, `powershell`). Co-occurrence signals chained behaviour rather than isolated keyword presence: weight 40.

---

## Per-Format Risk Thresholds

Thresholds vary by format because threat severity and false-positive rates differ:

| Format | Threshold | Rationale |
|---|---|---|
| Macro-enabled Office | 50 | Highest risk — direct code execution |
| PDF | 60 | Higher FP rate — many legitimate PDFs use JS/forms |
| OOXML (docx/xlsx) | 55 | DDE and external links — moderate risk |
| Outlook email | 55 | Phishing + attachment risk |
| Images | 65 | Rare threat vector — polyglot/EXIF abuse |
| Markdown | 70 | Lowest risk — requires most evidence to block |

---

## Output Directories

Both are optional and only created when actually needed. Pass `copy_files=False` to `GatekeeperPipeline` (or `--no-copy` on the CLI) to skip file copying entirely — see the Python API section above. When `copy_files=True` (the default), directories are created automatically in the **caller's working directory** — not inside the installed package — the first time a file actually needs to land in them.

```
quarantine/       BLOCKED files copied here (original preserved at source)
clean_output/     CLEAN files copied here with macros intact
logs/             audit_log.jsonl — append-only scan records, ALWAYS written
```

`logs/` is the one directory that's always created and always written to, regardless of `copy_files` — storing the scan result is Gatekeeper's core objective; copying the file itself is a convenience on top of that.

### Audit Log Format

Every scan appends one JSON line to `logs/audit_log.jsonl`:

```json
{
    "timestamp": "2026-08-11 23:57:32",
    "filename": "chr_obfuscated_macro.xlsm",
    "file_path": "C:\\...\\sample_files\\chr_obfuscated_macro.xlsm",
    "format": "Excel Workbook (Macro-enabled)",
    "verdict": "BLOCKED",
    "risk_score": 400,
    "risk_threshold": 50,
    "destination": "C:\\...\\quarantine\\chr_obfuscated_macro_quarantined_20260811235732.xlsm",
    "findings_count": 13,
    "findings": [...]
}
```

---

## Project Structure

```
gatekeeper/
├── pyproject.toml                  pip packaging configuration
├── generate_test_samples.py        generates 11 test files (dev only)
│
├── gatekeeper/                     installable package
│   ├── __init__.py                 public API (GatekeeperPipeline, FileRouter, ...)
│   ├── __main__.py                 enables python -m gatekeeper
│   ├── cli.py                      gatekeeper console script entry point
│   ├── pipeline.py                 end-to-end orchestration + audit logging
│   ├── file_router.py              format detection and scanner dispatch
│   ├── deobfuscator.py             Chr(), concat, base64 reconstruction
│   ├── quarantine_manager.py       file isolation + triage reporting
│   │
│   ├── scanners/
│   │   ├── macro_scanner.py        VBA + XLM + YARA (Excel/Word macro files)
│   │   ├── pdf_scanner.py          PDF JS/action/URL analysis
│   │   ├── office_scanner.py       OOXML DDE + relationship analysis
│   │   ├── image_scanner.py        binary + EXIF metadata analysis
│   │   ├── email_scanner.py        phishing + attachment analysis
│   │   └── text_scanner.py         link + script injection analysis
│   │
│   └── rules/
│       ├── macro_rules.json        weighted custom detection rules
│       └── yara/
│           ├── vba_autoexec.yar
│           ├── vba_shell_execution.yar
│           ├── vba_download_cradles.yar
│           ├── vba_obfuscation.yar
│           ├── vba_persistence.yar
│           └── vba_process_injection.yar
│
├── sample_files/                   test documents (generated by generate_test_samples.py)
├── quarantine/                     blocked files (created at runtime)
├── clean_output/                   clean files (created at runtime)
└── logs/                           audit_log.jsonl (created at runtime)
```

---

## Adding Detection Rules

### Custom rules (no Python required)

Edit `gatekeeper/rules/macro_rules.json`:

```json
{
  "rules": [
    {
      "name": "My_New_Rule",
      "weight": 40,
      "patterns": ["SuspiciousFunction", "DangerousKeyword"],
      "description": "Detects my new threat pattern."
    }
  ]
}
```

### YARA rules

Add a `.yar` file to `gatekeeper/rules/yara/`. It is picked up automatically on the next run — no Python changes needed. Include a `weight` field in rule metadata:

```yara
rule My_New_YARA_Rule
{
    meta:
        description = "Detects something suspicious"
        weight      = 50

    strings:
        $s1 = "SuspiciousString" nocase

    condition:
        any of them
}
```

---

## Generating Test Samples

```powershell
# Install COM automation support (Windows only, required for .xlsm/.xls/.docm/.doc)
py -3.12 -m pip install pywin32

# Enable VBA project access in Excel and Word:
# File → Options → Trust Center → Trust Center Settings
# → Macro Settings → check "Trust access to the VBA project object model"

py -3.12 generate_test_samples.py
```

Generates 11 test files covering all supported formats with realistic malicious patterns.

---

## Dependencies

| Package | Purpose |
|---|---|
| `oletools` | VBA macro extraction (olevba) |
| `yara-python` | YARA signature matching |
| `XLMMacroDeobfuscator` | Excel 4.0 / XLM macro detection |
| `pypdf` | PDF structural analysis |
| `Pillow` | Image EXIF metadata scanning |
| `openpyxl` | XLSX content analysis |
| `extract-msg` | Outlook OLE2 .msg parsing |

---

## Gap Analysis Against `validators.py`

The company's existing `validators.py` (used as the synchronous upload gate) was reviewed against Gatekeeper's checks. The following checks existed in `validators.py` but not in Gatekeeper, and have now been added:

| Check | Where it was added |
|---|---|
| Image decompression bomb (pixel count > 50MP) | `image_scanner.py` |
| Expanded HTML-injection patterns (`vbscript:`, `onclick=`, `onmouseover=`, `data:text/html`, `<embed>`) | `text_scanner.py` |
| Script/HTML-injection scan inside OOXML XML content | `office_scanner.py` |
| CSV formula-injection scan | new `csv_scanner.py` |
| XML XXE / malformed-XML scan | new `xml_scanner.py` |
| HTML dangerous-markup scan | new `html_scanner.py` |
| Windows shortcut (.lnk) magic-byte + dangerous-target scan | new `shortcut_scanner.py` |
| Internet shortcut (.url) dangerous-scheme scan | new `shortcut_scanner.py` |
| `.eml` registered as a distinct routable extension | `file_router.py` |
| MSG oversized-file check (50MB) | `email_scanner.py` |

Checks already present in Gatekeeper that exceed `validators.py`'s equivalent (VBA/YARA macro analysis, PDF structural analysis, co-occurrence heuristics, Chr()/base64 deobfuscation) were left unchanged — `validators.py`'s versions of those checks are a subset of what Gatekeeper already does.

One structural difference remains by design: `validators.py` sniffs the actual MIME type via `python-magic` and cross-checks it against the extension, while Gatekeeper routes purely on file extension. This wasn't ported because it would be a significant behavioural change to `FileRouter`'s core design — worth a discussion with Sankaran before implementing rather than silently added.

---

## Known Limitations

- **ViperMonkey** (VBA emulation) is not integrated due to a `pyparsing` version conflict with Python 3.12. It is documented as a future roadmap item.
- The PDF test sample produces a benign `incorrect startxref pointer` warning from pypdf — this is an artifact of the hand-crafted test file, not a scanner bug.
- `generate_test_samples.py` requires a Windows machine with Excel and Word installed for the COM-dependent file types (`.xlsm`, `.xls`, `.docm`, `.doc`). The remaining 6 formats generate on any platform.
