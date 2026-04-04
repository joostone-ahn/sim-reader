#!/usr/bin/env python3
"""SIM 카드 덤프 → JSON 저장 → Excel 변환 통합 실행."""

import argparse
import logging
from pysim_wrapper import dump_sim
from export_to_excel import convert_to_excel

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def main():
    parser = argparse.ArgumentParser(description="SIM 카드 읽기 → Excel 변환")
    parser.add_argument("-p", "--reader", type=int, default=0, help="PC/SC 리더기 번호")
    parser.add_argument("--json-only", action="store_true", help="JSON 덤프만")
    parser.add_argument("--from-json", type=str, default=None, help="기존 JSON → Excel 변환만")
    args = parser.parse_args()

    if args.from_json:
        convert_to_excel(args.from_json)
    else:
        data, json_path = dump_sim(reader_num=args.reader)
        if not args.json_only:
            convert_to_excel(str(json_path))


if __name__ == "__main__":
    main()
