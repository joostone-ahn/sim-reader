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

1. **Connect** — Connect to reader and view card info (ICCID, IMSI, MSISDN, HPLMNwAcT)
2. **Read All Files** — Read the entire SIM file system
3. **Export Dump** — Save to `logs/<ICCID>/` (dump.json, dump.xlsx, decoded JSONs)

#### Offline Mode

4. **Load Dump** — Open a previously exported `dump.json` to browse without a SIM card

#### File Contents Panel

- **Decode / Raw toggle** — Switch between decoded view and raw hex data
- **PLMN files** (PLMNwAcT, OPLMNwAcT, HPLMNwAcT, FPLMN, EHPLMN) — Table view with MCC, MNC, AcT columns
- **Service tables** (UST, IST, EST) — Table view with service name and ON/OFF status
- **ACC** — Table view with access control class and ON/OFF status
- **URSP** — Tree-formatted decode view
- **Other EFs** — JSON decode view
- **Search** — Filter files by FID or name
- **Copy** — Copy current view content to clipboard
- **Write** — Write hex data to an EF (ADM verification required)

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

## License

### This Project
© 2026 JUSEOK AHN. All rights reserved.

### pySim (Third-party, modified)
The `pysim/` directory contains a modified version of pySim, an open source project by Osmocom.
Modifications were made to support URSP-related functionality.

- Original project: [pySim - Osmocom](https://osmocom.org/projects/pysim/wiki)
- Original source: [https://gitea.osmocom.org/sim-card/pysim](https://gitea.osmocom.org/sim-card/pysim)
- License: **GNU General Public License v2.0 (GPLv2)**

See `pysim/COPYING` for the full license text.
