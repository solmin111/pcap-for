import hashlib; import os; from collections import Counter; from dataclasses import dataclass, field; from datetime import datetime, timezone

from . import detect, dnsparse, httpparse; from .layers import decode; from .pcapio import read_packets; from .sessions import SessionTable

@dataclass
class AnalysisData:
    sessions: list = field(default_factory=list); http_transactions: list = field(default_factory=list)
    ftp_streams: list = field(default_factory=list); smtp_streams: list = field(default_factory=list)
    telnet_streams: list = field(default_factory=list); dns_messages: list = field(default_factory=list); arp_records: list = field(default_factory=list)

@dataclass
class AnalysisResult:
    path: str; sha256: str; analyzed_at: str; packet_count: int = 0; byte_count: int = 0; first_ts: float = 0.0; last_ts: float = 0.0
    protocol_counts: Counter = field(default_factory=Counter); timeline: Counter = field(default_factory=Counter)
    top_talkers: list = field(default_factory=list); data: AnalysisData = field(default_factory=AnalysisData); findings: list = field(default_factory=list)

    @property
    def duration(self):
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def max_severity(self):
        return self.findings[0].severity if self.findings else "none"

    def severity_counts(self):
        return Counter(f.severity for f in self.findings)

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

def classify_streams(sessions, data):
    for s in sessions:
        if s.proto != "tcp": continue
        c2s, s2c = s.stream(c2s=True), s.stream(c2s=False)
        if not c2s and not s2c: continue
        banner = s2c[:200].upper()
        if s.sport == 23: data.telnet_streams.append((s, c2s, s2c))
        elif s.sport in (25, 587) or (s2c.startswith(b"220") and b"SMTP" in banner): data.smtp_streams.append((s, c2s, s2c))
        elif s.sport == 21 or (s2c.startswith(b"220 ") and b"FTP" in banner): data.ftp_streams.append((s, c2s, s2c))
        elif httpparse.looks_like_http(c2s):
            for tx in httpparse.parse_transactions(c2s, s2c): data.http_transactions.append((s, tx))

def feed_dns(data, pkt, ts):
    if pkt.proto == "udp" and 53 in (pkt.sport, pkt.dport) and pkt.payload:
        msg = dnsparse.parse(pkt.payload)
        if msg is not None and (msg.questions or msg.answers): data.dns_messages.append((pkt.dst if msg.is_response else pkt.src, msg, ts))

def analyze(path, ioc_path=None):
    result = AnalysisResult(path=os.path.abspath(path), sha256=_sha256(path), analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    data, table, talkers = result.data, SessionTable(), Counter()
    for raw in read_packets(path):
        pkt = decode(raw)
        if pkt is None: continue
        result.packet_count += 1; result.byte_count += raw.orig_len
        if result.first_ts == 0.0: result.first_ts = pkt.ts
        result.last_ts = max(result.last_ts, pkt.ts); result.timeline[int(pkt.ts)] += 1
        if pkt.arp: result.protocol_counts["arp"] += 1; data.arp_records.append((pkt.ts, pkt.arp)); continue
        if not pkt.src: result.protocol_counts["l2-other"] += 1; continue
        talkers[pkt.src] += 1; result.protocol_counts[pkt.proto or "other"] += 1; table.feed(pkt); feed_dns(data, pkt, pkt.ts)
    data.sessions = table.sessions; result.top_talkers = talkers.most_common(10); classify_streams(table.sessions, data); result.findings = detect.run_all(data, ioc_path); return result
