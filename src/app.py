#!/usr/bin/env python3
"""SIM Card Reader Web Application."""

import json
import sys
import os
import subprocess
import zipfile
import tempfile
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session, send_file

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent))
from export_to_excel import convert_to_excel

app = Flask(__name__)
app.secret_key = 'sim_reader_secret_key_2024'

PYSIM_SHELL = Path(__file__).parent.parent / "pysim" / "pySim-shell.py"
DATA_DIR = Path(__file__).parent.parent / "data"


def _run_pysim(reader_num: int, exec_cmds: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PYSIM_SHELL), "-p", str(reader_num), "--noprompt"]
    for ec in exec_cmds:
        cmd.extend(["-e", ec])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _extract_json(stdout: str) -> dict | None:
    json_start = stdout.find('{')
    if json_start < 0:
        return None
    try:
        return json.loads(stdout[json_start:])
    except json.JSONDecodeError:
        return None


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/sim/connect', methods=['POST'])
def sim_connect():
    try:
        reader = request.json.get('reader', 0)
        # Quick select to check reader + card
        result = _run_pysim(reader, [
            "select MF",
            "select EF.ICCID", "read_binary_decoded",
            "select ADF.USIM",
            "select EF.IMSI", "read_binary_decoded",
            "select EF.MSISDN", "read_records_decoded",
        ], timeout=30)

        if "ReaderError" in result.stderr or "No reader found" in result.stdout:
            return jsonify({'success': False, 'error': 'Reader not found'})
        if "NoCardException" in result.stderr or "Card initialization" in result.stdout:
            return jsonify({'success': False, 'error': 'No card in reader'})

        # Parse output for key values
        stdout = result.stdout
        info = {'iccid': '', 'imsi': '', 'msisdn': ''}

        # Extract ICCID
        if '"iccid"' in stdout.lower():
            for line in stdout.split('\n'):
                if '"iccid"' in line.lower():
                    val = line.split(':', 1)[-1].strip().strip('",')
                    if val and val != 'null':
                        info['iccid'] = val

        # Extract IMSI
        if '"imsi"' in stdout.lower():
            for line in stdout.split('\n'):
                if '"imsi"' in line.lower():
                    val = line.split(':', 1)[-1].strip().strip('",')
                    if val and val != 'null':
                        info['imsi'] = val

        # Extract MSISDN - check for dialing_nr field in records
        if '"dialing_nr"' in stdout.lower():
            for line in stdout.split('\n'):
                if '"dialing_nr"' in line.lower():
                    val = line.split(':', 1)[-1].strip().strip('",')
                    if val and val != 'null' and len(val) > 3:
                        info['msisdn'] = val
                        break
        # Fallback: check for "number" field
        elif '"number"' in stdout.lower():
            for line in stdout.split('\n'):
                if '"number"' in line.lower():
                    val = line.split(':', 1)[-1].strip().strip('",')
                    if val and val != 'null' and len(val) > 3:
                        info['msisdn'] = val
                        break

        session['reader'] = reader
        session['connected'] = True
        return jsonify({'success': True, 'info': info})

    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Connection timeout'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/sim/verify_adm', methods=['POST'])
def verify_adm():
    try:
        reader = session.get('reader', 0)
        adm_input = request.json.get('adm', '').strip()

        # Determine candidates to try
        candidates = []
        if len(adm_input) == 16 and all(c in '0123456789abcdefABCDEF' for c in adm_input):
            # 16-char hex string: try ASCII conversion first, then raw hex
            try:
                adm_ascii = bytes.fromhex(adm_input).decode('ascii')
                candidates.append(adm_ascii)
            except (ValueError, UnicodeDecodeError):
                pass
            candidates.append(adm_input)
        else:
            candidates.append(adm_input)

        for adm in candidates:
            if len(adm) > 16:
                continue
            result = _run_pysim(reader, [f"verify_adm {adm}"], timeout=15)
            if result.returncode == 0 and "EXCEPTION" not in result.stdout:
                session['adm_verified'] = True
                return jsonify({'success': True})

        # All candidates failed
        err = result.stdout if "EXCEPTION" in result.stdout else result.stderr
        return jsonify({'success': False, 'error': f'ADM verification failed: {err[:200]}'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/sim/read_all', methods=['POST'])
def read_all():
    try:
        reader = session.get('reader', 0)
        adm = request.json.get('adm', '')

        cmds = []
        if adm:
            if len(adm) == 16:
                try:
                    adm = bytes.fromhex(adm).decode('ascii')
                except (ValueError, UnicodeDecodeError):
                    pass
            cmds.append(f"verify_adm {adm}")

        cmds.append("fsdump --json")
        print(f"[read_all] Starting fsdump, reader={reader}")
        result = _run_pysim(reader, cmds, timeout=600)
        print(f"[read_all] fsdump done, rc={result.returncode}, stdout={len(result.stdout)}B, stderr={len(result.stderr)}B")

        stdout = result.stdout
        json_start = stdout.find('{')
        if json_start < 0:
            print(f"[read_all] ERROR: No JSON. stdout[:300]={stdout[:300]}")
            print(f"[read_all] stderr[:300]={result.stderr[:300]}")
            return jsonify({'success': False, 'error': 'No JSON output from fsdump',
                            'stderr': result.stderr[:500]})

        data = json.loads(stdout[json_start:])
        print(f"[read_all] JSON parsed, {len(data.get('files', {}))} files")

        # Process files: separate raw/body/bytes
        files = {}
        for path, fd in data.get("files", {}).items():
            raw = fd.pop("raw", None)
            body = fd.get("body")
            error = fd.get("error")

            # Build bytes from raw or body
            if raw is not None:
                fd["bytes"] = raw
            elif body is not None:
                if isinstance(body, dict) and all(k.isdigit() for k in body.keys()):
                    # BER-TLV: reconstruct raw hex
                    raw_hex = ""
                    for tag_str, val_hex in body.items():
                        tag = int(tag_str)
                        val_bytes = bytes.fromhex(val_hex)
                        raw_hex += f"{tag:02x}" if tag <= 0xFF else f"{tag:04x}"
                        length = len(val_bytes)
                        if length <= 0x7F:
                            raw_hex += f"{length:02x}"
                        elif length <= 0xFF:
                            raw_hex += f"81{length:02x}"
                        else:
                            raw_hex += f"82{length:04x}"
                        raw_hex += val_hex
                    fd["bytes"] = raw_hex
            files[path] = fd

        data["files"] = files
        print(f"[read_all] Processed {len(files)} files, sending response")

        return jsonify({'success': True, 'data': data})

    except subprocess.TimeoutExpired:
        print("[read_all] TIMEOUT")
        return jsonify({'success': False, 'error': 'Read timeout (10 min)'})
    except Exception as e:
        print(f"[read_all] EXCEPTION: {e}")
        return jsonify({'success': False, 'error': str(e)})


def _path_to_select_cmds(file_path: str) -> list[str]:
    """Convert a file path like MF/ADF.USIM/DF.5GS/EF.URSP to pySim select commands."""
    parts = file_path.split('/')
    cmds = []
    for part in parts:
        cmds.append(f"select {part}")
    return cmds


@app.route('/sim/write_ef', methods=['POST'])
def write_ef():
    try:
        reader = session.get('reader', 0)
        file_path = request.json.get('path', '')
        hex_data = request.json.get('hex', '').strip().replace(' ', '')
        adm = request.json.get('adm', '')
        record_nr = request.json.get('record_nr', 0)
        structure = request.json.get('structure', 'transparent')

        if not file_path or not hex_data:
            return jsonify({'success': False, 'error': 'Missing path or hex data'})

        # Prepare ADM
        if adm and len(adm) == 16 and all(c in '0123456789abcdefABCDEF' for c in adm):
            try:
                adm = bytes.fromhex(adm).decode('ascii')
            except (ValueError, UnicodeDecodeError):
                pass

        cmds = []
        if adm:
            cmds.append(f"verify_adm {adm}")

        # Navigate to the file
        cmds.extend(_path_to_select_cmds(file_path))

        # Write command depends on structure
        if structure in ('linear_fixed', 'cyclic') and record_nr > 0:
            cmds.append(f"update_record {record_nr} {hex_data}")
        else:
            cmds.append(f"update_binary {hex_data}")

        result = _run_pysim(reader, cmds, timeout=30)

        if "EXCEPTION" in result.stdout or "Error" in result.stdout:
            err_msg = result.stdout[:300]
            return jsonify({'success': False, 'error': err_msg})

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/sim/export', methods=['POST'])
def export_sim():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({'success': False, 'error': 'No data'}), 400

        iccid = data.get('iccid', 'unknown')

        # Use temp directory only — don't write to project data/
        with tempfile.TemporaryDirectory() as tmpdir:
            card_dir = Path(tmpdir) / iccid
            card_dir.mkdir()

            # Save dump.json
            json_path = card_dir / "dump.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Convert to Excel (also creates decoded/ directory)
            xlsx_path = convert_to_excel(str(json_path))

            # Create zip with all generated files
            zip_path = Path(tmpdir) / f"{iccid}.zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(card_dir):
                    for fname in files:
                        fpath = Path(root) / fname
                        arcname = str(fpath.relative_to(Path(tmpdir)))
                        zf.write(fpath, arcname)

            return send_file(str(zip_path), as_attachment=True,
                             download_name=f"{iccid}.zip",
                             mimetype='application/zip')

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    print("Starting SIM Card Reader Web App...")
    print("Access: http://127.0.0.1:8082")
    app.run(host='0.0.0.0', port=8082, debug=False)
