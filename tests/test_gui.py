"""GUI 페이로드·렌더·라이브 서버 테스트 (브라우저 없이 검증)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapfor import craft, gui
from pcapfor.analyzer import analyze
from pcapfor.live import LiveEngine
from pcapfor.pcapio import LINKTYPE_RAW_IP, RawPacket, write_pcap

_spec = importlib.util.spec_from_file_location(
    "make_samples",
    os.path.join(os.path.dirname(__file__), "..", "tools", "make_samples.py"),
)
make_samples = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_samples)


def _mixed_result():
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    f.close()
    write_pcap(f.name, make_samples.make_mixed())
    try:
        return analyze(f.name)
    finally:
        os.unlink(f.name)


class TestPayload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = gui.payload_from_result(_mixed_result())

    def test_schema(self):
        p = self.payload
        self.assertEqual(p["mode"], "file")
        self.assertEqual(p["brand"], "pcap for")
        for key in ("meta", "stats", "timeline", "protocols", "findings",
                    "sessions", "graph"):
            self.assertIn(key, p)
        self.assertTrue(p["timeline"]["bins"])
        self.assertLessEqual(len(p["timeline"]["bins"]), gui.MAX_BINS)
        json.dumps(p)  # 직렬화 가능해야 한다

    def test_graph_classification(self):
        nodes = {n["id"]: n for n in self.payload["graph"]["nodes"]}
        self.assertIn("10.0.0.66", nodes)          # 스캐너
        self.assertTrue(nodes["10.0.0.66"]["sev"])  # 탐지 연루 표시
        self.assertTrue(nodes["10.0.0.66"]["internal"])
        self.assertIn("203.0.113.99", nodes)        # 비커닝 C2 (외부)
        self.assertFalse(nodes["203.0.113.99"]["internal"])
        self.assertTrue(self.payload["graph"]["edges"])

    def test_flagged_sessions_first(self):
        sess = self.payload["sessions"]
        self.assertTrue(sess[0]["flagged"])  # 탐지 연루 세션이 상단


class TestRender(unittest.TestCase):
    def test_static_html(self):
        result = _mixed_result()
        out = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        out.close()
        try:
            gui.render_static(result, out.name)
            with open(out.name, encoding="utf-8") as f:
                html = f.read()
        finally:
            os.unlink(out.name)
        self.assertIn('"mode": "file"', html)
        self.assertIn("pcap for", html)       # 브랜드
        self.assertNotIn("__PAYLOAD__", html)  # 주입 완료


class TestLiveServer(unittest.TestCase):
    def test_state_endpoint(self):
        eng = LiveEngine()
        # 가짜 raw-IP 패킷 몇 개 주입
        for i in range(5):
            ip = craft.ipv4("10.0.0.5", "1.2.3.4", 6,
                            craft.tcp(50000 + i, 443, 1, 0, craft.TCP_SYN))
            eng.ingest(RawPacket(1000.0 + i, ip, len(ip), LINKTYPE_RAW_IP, i + 1))
        server, url = gui.start_live_server(eng, "10.0.0.5")
        try:
            with urllib.request.urlopen(url + "api/state", timeout=5) as r:
                state = json.loads(r.read().decode("utf-8"))
            self.assertEqual(state["mode"], "live")
            self.assertEqual(state["meta"]["packets"], 5)
            with urllib.request.urlopen(url, timeout=5) as r:
                page = r.read().decode("utf-8")
            self.assertIn('"mode": "live"', page)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
