from dataclasses import dataclass, field; from typing import Optional

from .layers import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN

MAX_STREAM_BYTES = 4 * 1024 * 1024

@dataclass
class Session:
    sid: int; proto: str; client: str; cport: int; server: str; sport: int; first_ts: float; last_ts: float = 0.0; packets: int = 0; bytes_c2s: int = 0; bytes_s2c: int = 0
    syn_seen: bool = False; synack_seen: bool = False; fin_seen: bool = False; rst_seen: bool = False
    _segs_c2s: dict = field(default_factory=dict, repr=False); _segs_s2c: dict = field(default_factory=dict, repr=False); _isn_c: Optional[int] = None; _isn_s: Optional[int] = None

    @property
    def key_str(self):
        return f"{self.client}:{self.cport} -> {self.server}:{self.sport}/{self.proto}"

    @property
    def duration(self):
        return max(0.0, self.last_ts - self.first_ts)

    def stream(self, c2s):
        segs = self._segs_c2s if c2s else self._segs_s2c
        if not segs: return b""
        out, expected = bytearray(), None
        for seq in sorted(segs):
            chunk = segs[seq]
            if expected is None or seq > expected: expected = seq
            elif seq < expected:
                overlap = expected - seq
                if overlap >= len(chunk): continue
                chunk = chunk[overlap:]
            out += chunk; expected += len(chunk)
            if len(out) >= MAX_STREAM_BYTES: break
        return bytes(out)

class SessionTable:
    def __init__(self):
        self._map = {}; self.sessions = []

    @staticmethod
    def _key(p):
        a, b = (p.src, p.sport), (p.dst, p.dport); return (p.proto,) + (a + b if a <= b else b + a)

    def feed(self, p):
        if p.proto not in ("tcp", "udp") or not p.src: return None
        key = self._key(p); s = self._map.get(key)
        if s is None:
            client, cport, server, sport = p.src, p.sport, p.dst, p.dport; fresh_syn = p.proto == "tcp" and p.flag(TCP_SYN) and not p.flag(TCP_ACK)
            if not fresh_syn and p.sport < 1024 <= p.dport: client, cport, server, sport = p.dst, p.dport, p.src, p.sport
            s = Session(sid=len(self.sessions) + 1, proto=p.proto, client=client, cport=cport, server=server, sport=sport, first_ts=p.ts, last_ts=p.ts); self._map[key] = s; self.sessions.append(s)
        if (p.proto == "tcp" and p.flag(TCP_SYN) and p.flag(TCP_ACK) and (p.src, p.sport) == (s.client, s.cport) and not s.syn_seen): s.client, s.cport, s.server, s.sport = s.server, s.sport, s.client, s.cport
        c2s = (p.src, p.sport) == (s.client, s.cport); s.packets += 1; s.last_ts = max(s.last_ts, p.ts)
        if c2s: s.bytes_c2s += len(p.payload)
        else: s.bytes_s2c += len(p.payload)
        if p.proto == "tcp":
            if p.flag(TCP_SYN) and not p.flag(TCP_ACK):
                s.syn_seen = True
                if c2s: s._isn_c = p.seq
            if p.flag(TCP_SYN) and p.flag(TCP_ACK):
                s.synack_seen = True
                if not c2s: s._isn_s = p.seq
            if p.flag(TCP_FIN): s.fin_seen = True
            if p.flag(TCP_RST): s.rst_seen = True
            if p.payload:
                segs = s._segs_c2s if c2s else s._segs_s2c
                if len(segs) < 65536 and p.seq not in segs: segs[p.seq] = p.payload
        return s

    @property
    def count(self):
        return len(self.sessions)
