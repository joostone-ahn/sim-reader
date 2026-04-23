# 📖 SIM Card Reader

A web-based tool for reading, decoding, and modifying SIM/USIM/ISIM card file systems.

---

## Requirements

- **Python 3.10+** — Download from [python.org](https://www.python.org/downloads/) if not installed
- PC/SC compatible smart card reader (e.g. HID OMNIKEY 3x21)
- SIM card

> All other dependencies (Flask, openpyxl, etc.) are installed automatically on first run.

---

## Installation & Launch

```bash
git clone https://github.com/joostone-ahn/sim-reader.git
cd sim-reader
```

- **macOS** — Double-click `run.command`
- **Windows** — Double-click `run.bat`

Your browser will automatically open `http://127.0.0.1:8082`.

To update: `git pull`

---

## How to Use

### 1. Connect

Click **Connect** to connect to the card reader. Card info (ICCID, IMSI, MSISDN, HPLMNwAcT, IMPI, IMPU) is displayed automatically.

### 2. Read All Files

Click **READ ALL FILES** to read the entire SIM file system. This walks through all DFs (MF, ADF.USIM, ADF.ISIM, DF.GSM, DF.5GS, etc.) and attempts to read every EF — typically 200~300 files depending on the card profile.

> **Note:** The dump is automatically exported to `logs/<ICCID>/` as dump.json, dump.xlsx, and individual decoded JSON files.

### 3. Verify ADM

Click **VERIFY ADM** to verify ADM1~4 keys independently. Status dots show each key's state (gray = not verified, green = verified). Can be done before or after Read All Files.

> **Note:** After verification, 6982 (security-protected) files requiring the verified key are automatically re-read and the dump is re-saved.

### 4. Load Dump (Offline Mode)

Click **Load Dump** to browse a previously exported `dump.json` without a SIM card. ADM verification state from the original session is restored.

### 5. Browse Files

| Column | Description |
|--------|-------------|
| Level 1/2/3 | File path hierarchy |
| FID | File Identifier (hex), AID for application DFs |
| Type | DF, TF (transparent), LF (linear fixed), CF (cyclic), BER-TLV |
| ARR | Access Rule Reference record number |
| Size | File size in bytes |
| Rec# | Number of records (linear fixed / cyclic) |

### 6. View File Contents

- **Decode / Raw toggle** — Switch between decoded view and raw hex
- **Copy** — Copy current view to clipboard

| File Type | Decode View |
|-----------|-------------|
| PLMN files | Table with MCC, MNC, AcT |
| Service tables (UST, IST, EST) | Service name and ON/OFF status |
| ACC | Access control class and ON/OFF status |
| ARR | Read/Update/Write/Activate/Deactivate conditions per record |
| URSP | Tree-formatted decode |
| Other EFs | JSON decode (pySim-based) |

### 7. Write

Specialized editors depending on file type:

- **Hex editor** — Direct hex input for any writable EF
- **PLMN editor** — Edit MCC/MNC/AcT per entry (table or hex mode)
- **Service table editor** — Toggle services ON/OFF (UST, IST, EST)
- **ACC editor** — True/False toggles per access control class (0~15)
- **BER-TLV editor** — Tag-based write with tag selector (URSP etc.)

> **Note:** For ADM-protected files, the Write button is disabled until the required key is verified. A tooltip shows which ADM key is needed.

---

## Project Structure

```
run.command          # macOS launcher
run.bat              # Windows launcher
requirements.txt     # Python dependencies
src/
  app.py             # Flask web server
  export_to_excel.py # JSON to Excel converter
  templates/
    index.html       # Web GUI frontend
pysim/               # pySim (modified)
logs/                # Export output (auto-created)
```

---

## pySim Modifications

Custom changes to the `pysim/` directory:

- **`pySim-shell.py`** — `fsdump_custom`: raw hex + decoded JSON in single pass
- **`pySim/filesystem.py`** — `read_binary_raw_dec`, `read_records_raw_dec`, `retrieve_data_raw_dec`
- **`pySim/ts_24_526.py`** — URSP decoder (3GPP TS 24.526)
- **`pySim/ts_31_102.py`** — EF.URSP as BerTlvEF with `decode_tag_data`
- **`pySim/ts_102_221.py`** — `SecurityAttribReferenced`: 6-byte long format fix for correct ARR record number
- **`pySim/commands.py`** — APDU logging for all commands
- **`setup.py`** — Removed `smpp.twisted3` dependency (Windows fix)

---

## License

### This Project
© 2026 JUSEOK AHN. All rights reserved.

### pySim (Third-party, modified)
Modified version of [pySim by Osmocom](https://osmocom.org/projects/pysim/wiki) ([source](https://gitea.osmocom.org/sim-card/pysim)). License: **GPLv2** — see `pysim/COPYING`.
