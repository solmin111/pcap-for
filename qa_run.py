# -*- coding: utf-8 -*-
"""QA 실행 헬퍼: 분석 1회로 콘솔/JSON/GUI 산출 (브라우저 자동 오픈 없음).

사용: python qa_run.py <pcap> <out_prefix> [ioc파일]
     -> <out_prefix>_cli.txt / .json / _gui.html
"""
import io
import sys
import time

from pcapfor.analyzer import analyze
from pcapfor import report
from pcapfor.gui import render_static
from pcapfor.report import to_json

pcap, prefix = sys.argv[1], sys.argv[2]
ioc = sys.argv[3] if len(sys.argv) > 3 else None

t0 = time.time()
result = analyze(pcap, ioc_path=ioc)
elapsed = time.time() - t0

text = report.console_summary(result, verbose=True)
text += f"\n[분석 소요 시간: {elapsed:.1f}초]\n"
with io.open(prefix + "_cli.txt", "w", encoding="utf-8") as f:
    f.write(text)
to_json(result, prefix + ".json")
render_static(result, prefix + "_gui.html")
print(f"done {elapsed:.1f}s findings={len(result.findings)} "
      f"packets={result.packet_count} max={result.max_severity}")
