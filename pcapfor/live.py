import ctypes; import socket; import threading; import time; from collections import Counter

from . import detect; from .analyzer import AnalysisData, classify_streams, feed_dns; from .layers import decode
from .pcapio import LINKTYPE_RAW_IP, PcapWriter, RawPacket; from .report import SEV_KO; from .sessions import SessionTable

def is_elevated():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError): return False

def default_iface_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8", 53)); return s.getsockname()[0]
    finally: s.close()

def _print_finding(f):
    print(f"\n[{time.strftime('%H:%M:%S')}] [!] ({SEV_KO[f.severity]}/{f.category}) {f.title}"); print(f"           {f.description}")
    for ev in f.evidence[:3]: print(f"           증거: {ev}")

class PacketCapture:
    def __init__(self, iface_ip=None):
        self.iface_ip, self._sock = iface_ip or default_iface_ip(), None

    def __enter__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP); s.bind((self.iface_ip, 0)); s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON); s.settimeout(1.0); self._sock = s; return self

    def __exit__(self, *exc):
        if self._sock is not None:
            try: self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError: pass
            self._sock.close()

    def recv(self):
        try: return self._sock.recv(65535)
        except socket.timeout: return None

class LiveEngine:
    def __init__(self, ioc_path=None):
        self.data, self.table, self.ioc_path = AnalysisData(), SessionTable(), ioc_path; self.packet_count = self.byte_count = 0
        self.timeline, self.started_at = Counter(), time.time(); self.findings, self.lock, self._seen = [], threading.Lock(), set()

    def ingest(self, raw):
        pkt = decode(raw)
        if pkt is None or not pkt.src: return
        with self.lock: self.packet_count += 1; self.byte_count += raw.orig_len; self.timeline[int(raw.ts)] += 1; self.table.feed(pkt); feed_dns(self.data, pkt, raw.ts)

    def sweep(self):
        with self.lock: return self._sweep_locked()

    def _sweep_locked(self):
        self.data.sessions = self.table.sessions; self.data.http_transactions, self.data.ftp_streams = [], []
        self.data.smtp_streams, self.data.telnet_streams = [], []; classify_streams(self.table.sessions, self.data); fresh = []
        for f in detect.run_all(self.data, self.ioc_path):
            key = (f.category, f.title)
            if key not in self._seen: self._seen.add(key); fresh.append(f); self.findings.append(f)
        return fresh

def run_live(duration, sweep_sec, ioc_path, save_path, gui=False):
    print("pcap-for :: 실시간 탐지"); print("[주의] 본인 소유/관리 호스트의 트래픽 모니터링 용도로만 사용하세요.\n")
    if not is_elevated(): print("오류: 실시간 모드는 관리자 권한 세션이 필요합니다."); print("터미널을 '관리자 권한으로 실행'으로 연 뒤 다시 실행하세요."); return 1
    engine = LiveEngine(ioc_path); writer = PcapWriter(save_path, LINKTYPE_RAW_IP) if save_path else None; server = None
    with PacketCapture() as cap:
        print(f"{cap.iface_ip} 인터페이스 감시 시작 (탐지 스윕 {sweep_sec:.0f}초 주기, Ctrl+C 종료)")
        if gui: import webbrowser; from .gui import start_live_server; server, url = start_live_server(engine, cap.iface_ip); print(f"라이브 GUI: {url}"); webbrowser.open(url)
        start = last_sweep = time.time(); number = 0
        try:
            while True:
                now = time.time()
                if duration and now - start >= duration: break
                data = cap.recv()
                if data:
                    number += 1; ts = time.time(); engine.ingest(RawPacket(ts, data, len(data), LINKTYPE_RAW_IP, number))
                    if writer: writer.write(ts, data)
                if now - last_sweep >= sweep_sec:
                    last_sweep = now
                    for f in engine.sweep(): _print_finding(f)
                    print(f"  … 패킷 {engine.packet_count:,} / 세션 {len(engine.table.sessions)}", end="\r")
        except KeyboardInterrupt: print("\n중단됨 - 최종 스윕 실행")
        for f in engine.sweep(): _print_finding(f)
        if writer: writer.close(); print(f"\n증거 pcap 저장: {save_path} ({writer.count:,} packets) - 파일 모드로 재분석 가능")
    if server is not None: server.shutdown()
    n = len(engine._seen); print(f"\n종료 - 누적 탐지 {n}건"); return 2 if n else 0
