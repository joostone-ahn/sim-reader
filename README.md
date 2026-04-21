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

#### SIM Card Mode

1. **Connect** — Connect to reader and view card info (ICCID, IMSI, MSISDN, HPLMNwAcT, IMPI, IMPU)
2. **Read All Files** — Read the entire SIM file system and auto-export to `logs/<ICCID>/` (dump.json, dump.xlsx, decoded JSONs)
3. **Verify ADM** — Verify ADM1~4 keys independently; auto-reads 6982 protected files after verification

#### Offline Mode

4. **Load Dump** — Open a previously exported `dump.json` to browse without a SIM card

#### File List

- **Columns** — Level 1/2/3, FID, Type (DF/TF/LF/CF/BER-TLV), ARR record number, Size, Rec#
- **Search** — Filter files by FID or name

#### File Contents Panel

- **Decode / Raw toggle** — Switch between decoded view and raw hex data
- **PLMN files** (PLMNwAcT, OPLMNwAcT, HPLMNwAcT, FPLMN, EHPLMN) — Table view with MCC, MNC, AcT columns
- **Service tables** (UST, IST, EST) — Table view with service name and ON/OFF status
- **ACC** — Table view with access control class and ON/OFF status
- **ARR** — Table view with Read/Update/Write/Activate/Deactivate access conditions per record
- **URSP** — Tree-formatted decode view
- **Other EFs** — JSON decode view
- **Copy** — Copy current view content to clipboard
- **Write** — Write hex data to an EF (ADM verification required for protected files; tooltip shows required ADM type)

#### ADM Verification

- Supports ADM1, ADM2, ADM3, ADM4 independently
- Status indicators (colored dots) show verification state per ADM key
- After verification, 6982 protected files are automatically re-read in the background
- Dump files are auto-saved with updated data and ADM verification state
- 6982 error display shows ARR-based access condition info (required ADM type, verification status)

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
