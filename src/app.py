#!/usr/bin/env python3
"""SIM Card Reader Web Application."""

import json
import re
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


def _run_pysim(reader_num: int, exec_cmds: list[str], timeout: int = 60, apdu_trace: bool = False) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PYSIM_SHELL), "-p", str(reader_num), "--noprompt"]
    if apdu_trace:
        cmd.append("--apdu-trace")
    for ec in exec_cmds:
        cmd.extend(["-e", ec])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if apdu_trace:
        if result.stderr:
            print(f"[APDU-ERR]\n{result.stderr}")
        # Print APDU trace lines from stdout
        for line in result.stdout.split('\n'):
            if line.startswith('INFO: ->') or line.startswith('INFO: <-'):
                print(f"[APDU] {line}")
    return result


def _run_pysim_raw(reader_num: int, apdu_cmds: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Run pySim with --skip-card-init and raw APDU commands."""
    cmd = [sys.executable, str(PYSIM_SHELL), "-p", str(reader_num), "--noprompt", "--skip-card-init", "--apdu-trace"]
    for apdu in apdu_cmds:
        cmd.extend(["-e", f"apdu {apdu}"])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.stderr:
        print(f"[APDU-ERR]\n{result.stderr}")
    for line in result.stdout.split('\n'):
        if line.startswith('INFO: ->') or line.startswith('INFO: <-'):
            print(f"[APDU] {line}")
    return result


def _parse_sw(result: subprocess.CompletedProcess) -> str:
    """Extract last SW from pySim raw APDU output."""
    for line in reversed(result.stdout.split('\n')):
        line = line.strip()
        if line.startswith('SW:'):
            return line.split(':')[1].strip()
    return ''


# Key reference mapping for ADM types
_ADM_KEY_REF = {
    'ADM1': '0a', 'ADM2': '0b', 'ADM3': '0c', 'ADM4': '0d', 'ADM5': '0e',
}


def _get_usim_aid(reader_num: int) -> str:
    """Get USIM AID from EF.DIR. Returns hex AID string."""
    # Default USIM AID
    return session.get('usim_aid', 'a0000000871002ffffffff8903000000')


def _extract_json(stdout: str) -> dict | None:
    """Extract the last JSON object or array from stdout."""
    last_json = None
    i = 0
    while i < len(stdout):
        if stdout[i] in ('{', '['):
            bracket = stdout[i]
            close = '}' if bracket == '{' else ']'
            depth = 0
            start = i
            while i < len(stdout):
                if stdout[i] == bracket:
                    depth += 1
                elif stdout[i] == close:
                    depth -= 1
                    if depth == 0:
                        try:
                            last_json = json.loads(stdout[start:i+1])
                        except json.JSONDecodeError:
                            pass
                        break
                i += 1
        i += 1
    return last_json


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
            "select ADF.USIM",
            "select EF.HPLMNwAcT", "read_binary",
        ], timeout=30)

        if "ReaderError" in result.stderr or "No reader found" in result.stdout:
            return jsonify({'success': False, 'error': 'Reader not found'})
        if "NoCardException" in result.stderr or "Card initialization" in result.stdout:
            return jsonify({'success': False, 'error': 'No card in reader'})

        # Parse all JSON objects from stdout
        stdout = result.stdout
        json_objects = []
        i = 0
        while i < len(stdout):
            if stdout[i] in ('{', '['):
                bracket = stdout[i]
                close = '}' if bracket == '{' else ']'
                depth = 0
                start = i
                while i < len(stdout):
                    if stdout[i] == bracket:
                        depth += 1
                    elif stdout[i] == close:
                        depth -= 1
                        if depth == 0:
                            try:
                                obj = json.loads(stdout[start:i+1])
                                json_objects.append(obj)
                            except json.JSONDecodeError:
                                pass
                            break
                    i += 1
            i += 1

        info = {'iccid': '', 'imsi': '', 'msisdn': '', 'hplmn': ''}

        for obj in json_objects:
            if isinstance(obj, dict):
                if 'iccid' in obj:
                    info['iccid'] = obj['iccid']
                elif 'imsi' in obj:
                    info['imsi'] = obj['imsi']
            elif isinstance(obj, list):
                # MSISDN records
                for rec in obj:
                    if not isinstance(rec, dict):
                        continue
                    if 'dialing_nr' in rec and rec['dialing_nr'] and not info['msisdn']:
                        nr = rec['dialing_nr']
                        alpha = rec.get('alpha_id', '')
                        if alpha:
                            info['msisdn'] = f"{nr}({alpha})"
                        else:
                            info['msisdn'] = nr

        # Parse HPLMNwAcT from raw hex line (read_binary output)
        for line in stdout.split('\n'):
            line = line.strip()
            if len(line) >= 10 and all(c in '0123456789abcdefABCDEF' for c in line):
                raw = line.upper()
                if raw[:6] != 'FFFFFF':
                    plmn_hex = raw[:6]
                    act_hex = raw[6:10]
                    # Decode PLMN: nibble-swapped BCD
                    mcc = plmn_hex[1] + plmn_hex[0] + plmn_hex[3]
                    mnc_d3 = plmn_hex[2]
                    mnc = plmn_hex[5] + plmn_hex[4]
                    if mnc_d3 != 'F':
                        mnc += mnc_d3
                    info['hplmn'] = f"{mcc}/{mnc}({act_hex})"
                break

        session['reader'] = reader
        session['connected'] = True
        # Store USIM AID from EF.DIR for raw APDU usage
        for obj in json_objects:
            if isinstance(obj, list):
                for rec in obj:
                    if isinstance(rec, dict) and 'dialing_nr' not in rec:
                        continue
        # Extract AID from stdout
        for line in stdout.split('\n'):
            if 'USIM:' in line and '(EF.DIR)' in line:
                aid = line.split('USIM:')[1].split('(')[0].strip()
                if aid:
                    session['usim_aid'] = aid
                break
        return jsonify({'success': True, 'info': info})

    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Connection timeout'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def _prepare_adm(adm_input: str) -> str:
    """Return ADM hex value for --pin-is-hex usage. Always 16 hex chars."""
    adm = adm_input.strip().replace(' ', '')
    if len(adm) != 16 or not all(c in '0123456789abcdefABCDEF' for c in adm):
        return ''
    return adm


@app.route('/sim/verify_adm', methods=['POST'])
def verify_adm():
    try:
        reader = session.get('reader', 0)
        adm_hex = _prepare_adm(request.json.get('adm', ''))
        adm_type = request.json.get('adm_type', 'ADM1')

        if not adm_hex:
            return jsonify({'success': False, 'error': '⚠️ Invalid ADM value'})

        cmd = f"verify_adm --pin-is-hex --adm-type {adm_type} {adm_hex}"
        print(f"[verify_btn] cmd: {cmd}")
        result = _run_pysim(reader, [cmd], timeout=15)
        # Print APDU trace lines — after init (ICCID read + select MF)
        all_lines = result.stdout.split('\n')
        init_end = -1
        for i in range(len(all_lines)):
            if all_lines[i].startswith('INFO: ->') and '00b000000a' in all_lines[i].lower():
                for j in range(i + 1, len(all_lines)):
                    if all_lines[j].startswith('INFO: ->') and '00a4000402 3f00' in all_lines[j].lower():
                        init_end = j + 2
                        break
        if init_end >= 0:
            show_next = False
            for line in all_lines[init_end:]:
                if line.startswith('INFO: ->'):
                    print(f"[verify_btn] {line}")
                    show_next = True
                elif line.startswith('INFO: <-') and show_next:
                    print(f"[verify_btn] {line}")
                    show_next = False

        if "EXCEPTION" not in result.stdout and "EXCEPTION" not in result.stderr:
            session['adm_verified'] = True
            print(f"[verify_btn] SUCCESS")
            return jsonify({'success': True})

        err = result.stderr if "EXCEPTION" in result.stderr else result.stdout
        error_line = err
        for line in err.split('\n'):
            line = line.strip()
            if 'SW match failed' in line or 'EXCEPTION' in line:
                error_line = line
                break
        sw_m = re.search(r'got (\w{4}):\s*(.+)', error_line)
        if sw_m:
            error_line = f"⚠️ {sw_m.group(1)}: {sw_m.group(2).strip()}"
        print(f"[verify_btn] FAILED: {error_line[:200]}")
        return jsonify({'success': False, 'error': error_line[:300]})

    except Exception as e:
        print(f"[verify_btn] EXCEPTION: {e}")
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
        print(f"[read_all_files_btn] Starting fsdump, reader={reader}")
        # Use Popen for real-time SELECT APDU logging
        cmd = [sys.executable, str(PYSIM_SHELL), "-p", str(reader), "--noprompt"]
        for ec in cmds:
            cmd.extend(["-e", ec])
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_lines = []
        for line in proc.stdout:
            stdout_lines.append(line)
            if line.startswith('INFO: ->') or line.startswith('INFO: <-'):
                pass  # print(f"[read_all_files_btn] {line.rstrip()}")
        proc.wait()
        stderr = proc.stderr.read()
        stdout = ''.join(stdout_lines)
        if proc.returncode is None:
            proc.kill()
        print(f"[read_all_files_btn] fsdump done, rc={proc.returncode}, stdout={len(stdout)}B, stderr={len(stderr)}B")

        json_start = stdout.find('{')
        if json_start < 0:
            print(f"[read_all_files_btn] ERROR: No JSON. stdout[:300]={stdout[:300]}")
            print(f"[read_all_files_btn] stderr[:300]={stderr[:300]}")
            return jsonify({'success': False, 'error': 'No JSON output from fsdump',
                            'stderr': stderr[:500]})

        data = json.loads(stdout[json_start:])
        print(f"[read_all_files_btn] JSON parsed, {len(data.get('files', {}))} files")

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
        print(f"[read_all_files_btn] Processed {len(files)} files, sending response")

        return jsonify({'success': True, 'data': data})

    except subprocess.TimeoutExpired:
        print("[read_all_files_btn] TIMEOUT")
        return jsonify({'success': False, 'error': 'Read timeout (10 min)'})
    except Exception as e:
        print(f"[read_all_files_btn] EXCEPTION: {e}")
        return jsonify({'success': False, 'error': str(e)})


def _path_to_select_cmds(file_path: str) -> list[str]:
    """Convert a file path like MF/ADF.USIM/DF.5GS/EF.URSP to pySim select commands."""
    parts = file_path.split('/')
    cmds = []
    for part in parts:
        cmds.append(f"select {part}")
    return cmds


@app.route('/sim/read_ef', methods=['POST'])
def read_ef():
    """Read a single EF after authentication."""
    try:
        reader = session.get('reader', 0)
        file_path = request.json.get('path', '')
        structure = request.json.get('structure', 'transparent')

        if not file_path:
            return jsonify({'success': False, 'error': 'Missing path'})

        cmds = _path_to_select_cmds(file_path)

        if structure in ('linear_fixed', 'cyclic'):
            cmds.append("read_records_decoded")
        else:
            cmds.append("read_binary_decoded")

        result = _run_pysim(reader, cmds, timeout=30)
        stdout = result.stdout

        # Try to extract JSON
        json_data = _extract_json(stdout)

        # Also get raw hex: re-read without decode
        cmds2 = _path_to_select_cmds(file_path)
        if structure in ('linear_fixed', 'cyclic'):
            cmds2.append("read_records")
        else:
            cmds2.append("read_binary")

        result2 = _run_pysim(reader, cmds2, timeout=30)
        stdout2 = result2.stdout

        # Parse raw hex from output
        raw_bytes = None
        if structure in ('linear_fixed', 'cyclic'):
            # Records: each line after select has hex data
            records = []
            for line in stdout2.split('\n'):
                line = line.strip()
                if line and all(c in '0123456789abcdefABCDEF' for c in line):
                    records.append(line)
            if records:
                raw_bytes = records
        else:
            for line in stdout2.split('\n'):
                line = line.strip()
                if line and all(c in '0123456789abcdefABCDEF' for c in line) and len(line) >= 2:
                    raw_bytes = line
                    break

        return jsonify({
            'success': True,
            'bytes': raw_bytes,
            'body': json_data,
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/sim/service_map', methods=['POST'])
def service_map():
    """Return service table map for EF.UST or EF.IST."""
    try:
        ef_name = request.json.get('ef', '')
        if 'UST' in ef_name:
            from pySim.ts_31_102 import EF_UST_map
            return jsonify({'success': True, 'map': {str(k): v for k, v in EF_UST_map.items()}})
        elif 'IST' in ef_name:
            from pySim.ts_31_103 import EF_IST_map
            return jsonify({'success': True, 'map': {str(k): v for k, v in EF_IST_map.items()}})
        else:
            return jsonify({'success': False, 'error': 'Unknown service table'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/sim/re_read', methods=['POST'])
def re_read():
    """Re-read files that failed with 6982 after ADM verification."""
    try:
        reader = session.get('reader', 0)
        adm_hex = request.json.get('adm', '')
        adm_type = request.json.get('adm_type', 'ADM1')
        paths = request.json.get('paths', [])

        if not adm_hex or not paths:
            return jsonify({'success': False, 'error': 'Missing ADM or paths'})

        results = {}
        for file_path in paths:
            try:
                structure = request.json.get('structures', {}).get(file_path, 'transparent')

                # Read raw
                cmds = [f"verify_adm --pin-is-hex --adm-type {adm_type} {adm_hex}"]
                cmds.extend(_path_to_select_cmds(file_path))
                if structure in ('linear_fixed', 'cyclic'):
                    cmds.append("read_records")
                else:
                    cmds.append("read_binary")

                result = _run_pysim(reader, cmds, timeout=30)
                stdout = result.stdout

                raw_bytes = None
                if structure in ('linear_fixed', 'cyclic'):
                    records = []
                    for line in stdout.split('\n'):
                        line = line.strip()
                        if line and all(c in '0123456789abcdefABCDEF' for c in line):
                            records.append(line)
                    if records:
                        raw_bytes = records
                else:
                    for line in stdout.split('\n'):
                        line = line.strip()
                        if line and all(c in '0123456789abcdefABCDEF' for c in line) and len(line) >= 2:
                            raw_bytes = line
                            break

                if not raw_bytes:
                    print(f"[read_btn] {file_path}: no data")
                    continue

                # Read decoded
                cmds2 = [f"verify_adm --pin-is-hex --adm-type {adm_type} {adm_hex}"]
                cmds2.extend(_path_to_select_cmds(file_path))
                if structure in ('linear_fixed', 'cyclic'):
                    cmds2.append("read_records_decoded")
                else:
                    cmds2.append("read_binary_decoded")

                result2 = _run_pysim(reader, cmds2, timeout=30)
                body = _extract_json(result2.stdout)
                print(f"[read_btn] {file_path}: decoded body={'found' if body else 'None'}, stdout2_len={len(result2.stdout)}")
                if body is None and result2.stdout:
                    # Log more to debug
                    print(f"[read_btn] {file_path}: stdout2[:500]={result2.stdout[:500]}")
                    print(f"[read_btn] {file_path}: stdout2[-300:]={result2.stdout[-300:]}")
                if result2.stderr:
                    print(f"[read_btn] {file_path}: stderr2={result2.stderr[:200]}")

                entry = {'bytes': raw_bytes}
                if body is not None:
                    entry['body'] = body
                results[file_path] = entry
                print(f"[read_btn] {file_path}: OK")
            except Exception as e:
                print(f"[read_btn] {file_path}: {e}")

        return jsonify({'success': True, 'results': results})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/sim/write_ef', methods=['POST'])
def write_ef():
    try:
        reader = session.get('reader', 0)
        file_path = request.json.get('path', '')
        hex_data = request.json.get('hex', '').strip().replace(' ', '')
        adm = request.json.get('adm', '')
        adm_type = request.json.get('adm_type', 'ADM1')
        record_nr = request.json.get('record_nr', 0)
        structure = request.json.get('structure', 'transparent')

        if not file_path or not hex_data:
            return jsonify({'success': False, 'error': '⚠️ Missing path or hex data'})

        # If ADM provided, include verify in the command chain
        adm_hex = _prepare_adm(adm) if adm else ''

        cmds = ['set conserve_write false']
        if adm_hex:
            cmds.append(f"verify_adm --pin-is-hex --adm-type {adm_type} {adm_hex}")

        # Navigate to the file
        cmds.extend(_path_to_select_cmds(file_path))
        if structure in ('linear_fixed', 'cyclic') and record_nr > 0:
            cmds.append(f"update_record {record_nr} {hex_data}")
        else:
            cmds.append(f"update_binary {hex_data}")

        write_cmd = 'update_record' if (structure in ('linear_fixed', 'cyclic') and record_nr > 0) else 'update_binary'
        print(f"[write_btn] cmds: {cmds}")
        result = _run_pysim(reader, cmds, timeout=30)
        # Print APDU trace lines — after init (ICCID read + select MF)
        all_lines = result.stdout.split('\n')
        init_end = -1
        for i in range(len(all_lines)):
            if all_lines[i].startswith('INFO: ->') and '00b000000a' in all_lines[i].lower():
                # Next select MF after ICCID read marks end of init
                for j in range(i + 1, len(all_lines)):
                    if all_lines[j].startswith('INFO: ->') and '00a4000402 3f00' in all_lines[j].lower():
                        # Skip this select MF and its response
                        init_end = j + 2
                        break
        if init_end >= 0:
            show_next = False
            for line in all_lines[init_end:]:
                if line.startswith('INFO: ->'):
                    print(f"[write_btn] {line}")
                    show_next = True
                elif line.startswith('INFO: <-') and show_next:
                    print(f"[write_btn] {line}")
                    show_next = False

        stdout = result.stdout
        stderr = result.stderr

        has_error = False
        err_msg = ''

        if "EXCEPTION" in stdout or "EXCEPTION" in stderr:
            has_error = True
            err_msg = stdout if "EXCEPTION" in stdout else stderr
        elif "SW match failed" in stdout or "SW match failed" in stderr:
            has_error = True
            err_msg = stdout if "SW match failed" in stdout else stderr
        elif "Error" in stdout:
            has_error = True
            err_msg = stdout

        if has_error:
            error_line = err_msg
            for line in err_msg.split('\n'):
                line = line.strip()
                if 'SW match failed' in line or 'EXCEPTION' in line:
                    error_line = line
                    break
            sw_m = re.search(r'got (\w{4}):\s*(.+)', error_line)
            if sw_m:
                error_line = f"⚠️ {sw_m.group(1)}: {sw_m.group(2).strip()}"
            return jsonify({'success': False, 'error': error_line[:300]})

        print(f"[write_btn] SUCCESS")
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
