#!/usr/bin/env python3
"""SIM 카드 전체 파일시스템을 JSON으로 덤프."""

import subprocess
import json
import sys
import re
import logging
from pathlib import Path

PYSIM_SHELL = Path(__file__).parent.parent / "pysim" / "pySim-shell.py"
DATA_DIR = Path(__file__).parent.parent / "data"

logger = logging.getLogger(__name__)


def _extract_imsi(data: dict) -> str:
    for path, fd in data.get("files", {}).items():
        if path.endswith("EF.IMSI"):
            body = fd.get("body")
            if isinstance(body, dict):
                return body.get("imsi", "unknown")
            if isinstance(body, str):
                return body
    return "unknown"


def _get_card_dir(data: dict) -> Path:
    iccid = data.get("iccid", "unknown")
    card_dir = DATA_DIR / iccid
    card_dir.mkdir(parents=True, exist_ok=True)
    return card_dir


def _run_pysim(reader_num: int, exec_cmds: list[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PYSIM_SHELL), "-p", str(reader_num), "--noprompt"]
    for ec in exec_cmds:
        cmd.extend(["-e", ec])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=600)


def _run_fsdump(reader_num: int, as_json: bool = False) -> tuple[dict, str, str]:
    cmd_flag = "fsdump_custom --json" if as_json else "fsdump_custom"
    result = _run_pysim(reader_num, [cmd_flag])
    stdout = result.stdout
    logger.debug("fsdump stdout (first 500): %s", stdout[:500])
    if result.stderr:
        logger.debug("fsdump stderr (first 500): %s", result.stderr[:500])
    json_start = stdout.find('{')
    if json_start < 0:
        raise RuntimeError(
            f"SIM 덤프 실패: JSON 출력 없음\n"
            f"--- stdout (first 1000) ---\n{stdout[:1000]}\n"
            f"--- stderr (first 1000) ---\n{result.stderr[:1000]}"
        )
    return json.loads(stdout[json_start:]), result.stdout, result.stderr


def _run_tree(reader_num: int, select_cmds: list[str]) -> list[dict]:
    """tree 명령으로 파일 목록 추출."""
    cmds = select_cmds + ["tree"]
    result = _run_pysim(reader_num, cmds)
    files = []
    pattern = re.compile(r'^\s*((?:EF|DF)\.\S+)\s+([0-9a-fA-F]{4})\s+(.*)$')
    for line in result.stdout.splitlines():
        m = pattern.match(line)
        if m:
            files.append({"name": m.group(1), "fid": m.group(2), "desc": m.group(3).strip()})
    return files


def _fill_missing_files(raw_data: dict, reader_num: int):
    """fsdump에서 빠진 파일을 tree 결과로 보충."""
    known_fids = set()
    for fd in raw_data.get("files", {}).values():
        fid = fd.get("fcp", {}).get("file_identifier", "")
        if fid:
            known_fids.add(fid.lower())

    df_paths = [
        (["select ADF.USIM", "select DF.5GS"], "MF/ADF.USIM/DF.5GS"),
        (["select ADF.USIM", "select DF.PHONEBOOK"], "MF/ADF.USIM/DF.PHONEBOOK"),
        (["select ADF.USIM", "select DF.WLAN"], "MF/ADF.USIM/DF.WLAN"),
        (["select ADF.USIM", "select DF.ProSe"], "MF/ADF.USIM/DF.ProSe"),
        (["select ADF.USIM", "select DF.SAIP"], "MF/ADF.USIM/DF.SAIP"),
        (["select ADF.USIM", "select DF.SNPN"], "MF/ADF.USIM/DF.SNPN"),
        (["select ADF.USIM", "select DF.5G_ProSe"], "MF/ADF.USIM/DF.5G_ProSe"),
        (["select DF.TELECOM", "select DF.PHONEBOOK"], "MF/DF.TELECOM/DF.PHONEBOOK"),
    ]

    added = 0
    for select_cmds, parent_path in df_paths:
        try:
            tree_files = _run_tree(reader_num, select_cmds)
        except Exception:
            continue

        for tf in tree_files:
            if tf["fid"].lower() not in known_fids:
                file_path = f"{parent_path}/{tf['name']}"
                is_df = tf["name"].startswith("DF.")
                raw_data["files"][file_path] = {
                    "path": file_path.split("/"),
                    "fcp": {
                        "file_descriptor": {
                            "file_descriptor_byte": {
                                "file_type": "df" if is_df else "working_ef",
                                "structure": "no_info_given"
                            }
                        },
                        "file_identifier": tf["fid"],
                    },
                    "description": tf["desc"],
                    "note": "not_in_fsdump",
                }
                known_fids.add(tf["fid"].lower())
                added += 1

    if added:
        # 보충된 파일을 해당 DF 내 FID 순서에 맞게 재배치
        from collections import OrderedDict
        new_files = OrderedDict()
        pending = {}  # parent_path -> [file entries]

        # 보충 파일을 parent별로 그룹핑
        for path, fd in raw_data["files"].items():
            if fd.get("note") == "empty_or_unreadable":
                parent = "/".join(fd["path"][:-1])
                pending.setdefault(parent, []).append((path, fd))

        # 원본 순서 유지하면서, 각 DF의 마지막 자식 뒤에 보충 파일 삽입
        last_parent = None
        buffer = []
        for path, fd in raw_data["files"].items():
            if fd.get("note") == "empty_or_unreadable":
                continue  # 보충 파일은 나중에 삽입
            current_parent = "/".join(fd.get("path", [])[:-1])

            # parent가 바뀌면, 이전 parent의 보충 파일을 FID순으로 삽입
            if last_parent is not None and current_parent != last_parent and last_parent in pending:
                for p, f in sorted(pending[last_parent],
                                   key=lambda x: x[1]["fcp"].get("file_identifier", "ffff")):
                    new_files[p] = f
                del pending[last_parent]

            new_files[path] = fd
            last_parent = current_parent

        # 남은 보충 파일 처리
        for parent, items in pending.items():
            for p, f in sorted(items, key=lambda x: x[1]["fcp"].get("file_identifier", "ffff")):
                new_files[p] = f

        raw_data["files"] = dict(new_files)
        logger.info("tree에서 %d개 빠진 파일 보충", added)


def dump_sim(reader_num: int = 0) -> tuple[dict, Path]:
    """SIM 카드를 decoded 덤프 (raw 포함) 후 저장."""
    # 1) decoded 덤프 (raw 데이터도 함께 포함)
    logger.info("SIM 덤프 시작 (reader=%d)", reader_num)
    try:
        data, stdout, stderr = _run_fsdump(reader_num, as_json=True)
        logger.info("덤프: %d개 파일", len(data.get("files", {})))
    except Exception as e:
        logger.warning("decoded 덤프 실패, raw로 재시도: %s", e)
        data, stdout, stderr = _run_fsdump(reader_num, as_json=False)
        logger.info("raw 덤프: %d개 파일", len(data.get("files", {})))

    # 2) raw/body 분리
    for path, fd in data.get("files", {}).items():
        raw = fd.pop("raw", None)
        body = fd.get("body")

        if raw is not None:
            # decoded 모드에서 raw가 함께 온 경우
            fd["bytes"] = raw
        elif body is not None:
            # BER-TLV EF: {tag: value} → 전체 raw hex로 재조합
            if isinstance(body, dict) and all(k.isdigit() for k in body.keys()):
                raw_hex = ""
                for tag_str, val_hex in body.items():
                    tag = int(tag_str)
                    val_bytes = bytes.fromhex(val_hex)
                    if tag <= 0xFF:
                        raw_hex += f"{tag:02x}"
                    else:
                        raw_hex += f"{tag:04x}"
                    length = len(val_bytes)
                    if length <= 0x7F:
                        raw_hex += f"{length:02x}"
                    elif length <= 0xFF:
                        raw_hex += f"81{length:02x}"
                    else:
                        raw_hex += f"82{length:04x}"
                    raw_hex += val_hex
                fd["bytes"] = raw_hex
            else:
                fd["bytes"] = body

    card_dir = _get_card_dir(data)

    # JSON 저장
    json_path = card_dir / "dump.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    # 로그 저장
    log_path = card_dir / "dump.log"
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=== STDOUT ===\n" + stdout + "\n")
        f.write("=== STDERR ===\n" + stderr + "\n")

    file_count = len(data.get("files", {}))
    logger.info("덤프 완료: %d개 파일 → %s", file_count, card_dir)
    return data, json_path


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(description="SIM 카드 파일시스템 덤프")
    parser.add_argument("-p", "--reader", type=int, default=0)
    args = parser.parse_args()
    dump_sim(reader_num=args.reader)
