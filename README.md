# 📖 SIM Card Reader

A web-based tool for reading, decoding, and modifying SIM/USIM/ISIM card file systems.

---

## Requirements

- **Python 3.10+** — Download from [python.org](https://www.python.org/downloads/) if not installed
- PC/SC compatible smart card reader (e.g. HID OMNIKEY 3x21)
- SIM card

> All other dependencies (Flask, openpyxl, etc.) are installed automatically on first run.

---

## Installation

```bash
git clone https://github.com/joostone-ahn/sim-reader.git
cd sim-reader
```

### Update to Latest Version

```bash
git pull
```

---

## Getting Started

### macOS

Double-click `run.command` to launch.

### Windows

Double-click `run.bat` to launch.

### After Launch

Your browser will automatically open `http://127.0.0.1:8082`.

---

## How to Use

### 1. Connect

Click **Connect** to connect to the card reader. Card info (ICCID, IMSI, MSISDN, HPLMNwAcT, IMPI, IMPU) is displayed automatically.

### 2. Read All Files

Click **READ ALL FILES** to read the entire SIM file system. This walks through all DFs (MF, ADF.USIM, ADF.ISIM, DF.GSM, DF.5GS, etc.) and attempts to read every EF within them — typically around 200~300 files depending on the card profile.

> **Note:** The dump is automatically exported to `logs/<ICCID>/` as dump.json, dump.xlsx, and individual decoded JSON files.

### 3. Verify ADM

Click **VERIFY ADM** to open the verification popup. ADM1 through ADM4 can be verified independently. Status dots next to the button show each ADM key's verification state (gray = not verified, green = verified). ADM keys can be verified before or after Read All Files.

> **Note:** After a successful verification, any 6982 (security-protected) files that require the verified key are automatically re-read in the background. The dump is re-saved with updated data and verification state.

### 4. Load Dump (Offline Mode)

Click **Load Dump** to open a previously exported `dump.json` and browse file contents without a SIM card.

> **Note:** ADM verification state from the original session is restored.

### 5. Browse Files

The **File List** shows all files with the following columns:

| Column | Description |
|--------|-------------|
| Level 1/2/3 | File path hierarchy |
| FID | File Identifier (hex) |
| Type | DF, TF (transparent), LF (linear fixed), CF (cyclic), BER-TLV |
| ARR | Access Rule Reference record number |
| Size | File size in bytes |
| Rec# | Number of records (for record-based files) |

### 6. View File Contents

Select a file to view its contents in the **File Contents** panel.

- **Decode / Raw toggle** — Switch between decoded view and raw hex data
- **Copy** — Copy current view content to clipboard

Special decode views for specific file types:

| File Type | Decode View |
|-----------|-------------|
| PLMN files (PLMNwAcT, OPLMNwAcT, etc.) | Table with MCC, MNC, AcT |
| Service tables (UST, IST, EST) | Table with service name and ON/OFF status |
| ACC | Table with access control class and ON/OFF status |
| ARR | Table with Read/Update/Write/Activate/Deactivate conditions per record |
| URSP | Tree-formatted decode view |
| Other EFs | JSON decode view |

### 7. Write

Click **Write** to modify an EF's hex data.

> For files protected by ADM, the Write button is disabled until the required ADM key is verified. A tooltip on the disabled button shows which ADM key is needed.

### 8. 6982 Error Files

Files that returned 6982 (security status not satisfied) during Read All Files are displayed with an error message. In connected mode, an info panel shows the ARR-based access conditions (required ADM type and current verification status).

---

## Project Structure

```
run.command          # macOS launcher
run.bat              # Windows launcher
requirements.txt     # Python dependencies
src/
  app.py             # Flask web server (GUI)
  pysim_wrapper.py   # pySim integration module
  export_to_excel.py # JSON to Excel converter
  templates/
    index.html       # Web GUI frontend
pysim/               # pySim open source (modified)
logs/                # Export output directory (auto-created)
```

---

## pySim Modifications

The `pysim/` directory contains a modified version of pySim with the following custom changes:

- **`pySim-shell.py`** — `fsdump_custom` command: raw hex + decoded JSON in single pass
- **`pySim/filesystem.py`** — `read_binary_raw_dec`, `read_records_raw_dec`, `retrieve_data_raw_dec` helper functions
- **`pySim/ts_24_526.py`** — URSP decoder (3GPP TS 24.526)
- **`pySim/ts_31_102.py`** — EF.URSP changed to BerTlvEF with `decode_tag_data`
- **`pySim/ts_102_221.py`** — `SecurityAttribReferenced` fix: handles 6-byte long format with SEID for correct ARR record number
- **`pySim/commands.py`** — APDU logging (`INFO: ->` / `INFO: <-`) for all commands
- **`setup.py`** — Removed `smpp.twisted3` dependency (Windows build fix)

---

## License

### This Project
© 2026 JUSEOK AHN. All rights reserved.

### pySim (Third-party, modified)
The `pysim/` directory contains a modified version of pySim, an open source project by Osmocom.

- Original project: [pySim - Osmocom](https://osmocom.org/projects/pysim/wiki)
- Original source: [https://gitea.osmocom.org/sim-card/pysim](https://gitea.osmocom.org/sim-card/pysim)
- License: **GNU General Public License v2.0 (GPLv2)**

See `pysim/COPYING` for the full license text.
