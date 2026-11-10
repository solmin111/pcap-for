import struct; from dataclasses import dataclass

LINKTYPE_ETHERNET = 1; LINKTYPE_RAW_IP = 101; LINKTYPE_LINUX_SLL = 113; PCAP_MAGIC_US = 0xA1B2C3D4; PCAP_MAGIC_NS = 0xA1B23C4D; PCAPNG_SHB = 0x0A0D0D0A; PCAPNG_BYTE_ORDER = 0x1A2B3C4D

@dataclass
class RawPacket:
    ts: float; data: bytes; orig_len: int; linktype: int; number: int

class PcapFormatError(ValueError):
    pass

def read_packets(path):
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4: raise PcapFormatError("파일이 너무 짧습니다")
        magic = struct.unpack("<I", head)[0]; f.seek(0)
        if magic == PCAPNG_SHB: yield from _read_pcapng(f)
        elif magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS) or struct.unpack(">I", head)[0] in (PCAP_MAGIC_US, PCAP_MAGIC_NS): yield from _read_pcap(f)
        else: raise PcapFormatError(f"pcap/pcapng 매직이 아님: 0x{magic:08X}")

def _read_pcap(f):
    header = f.read(24)
    if len(header) < 24: raise PcapFormatError("pcap 전역 헤더가 잘려 있습니다")
    magic, endian = struct.unpack("<I", header[:4])[0], "<"
    if magic not in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        magic, endian = struct.unpack(">I", header[:4])[0], ">"
        if magic not in (PCAP_MAGIC_US, PCAP_MAGIC_NS): raise PcapFormatError("알 수 없는 pcap 매직")
    ts_div = 1e9 if magic == PCAP_MAGIC_NS else 1e6; linktype = struct.unpack(endian + "HHiIII", header[4:24])[5]; number = 0
    while True:
        rec = f.read(16)
        if len(rec) < 16: return
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
        if incl_len > 0x7FFFFFFF: return
        data = f.read(incl_len)
        if len(data) < incl_len: return
        number += 1; yield RawPacket(ts_sec + ts_frac / ts_div, data, orig_len, linktype, number)

def _read_pcapng(f):
    endian, interfaces, number = "<", [], 0
    while True:
        bh = f.read(8)
        if len(bh) < 8: return
        btype = struct.unpack(endian + "I", bh[:4])[0]
        if btype == PCAPNG_SHB or struct.unpack(">I", bh[:4])[0] == PCAPNG_SHB:
            peek = f.read(4)
            if len(peek) < 4: return
            endian = "<" if struct.unpack("<I", peek)[0] == PCAPNG_BYTE_ORDER else ">"; f.read(struct.unpack(endian + "I", bh[4:8])[0] - 12); interfaces = []; continue
        blen = struct.unpack(endian + "I", bh[4:8])[0]
        if blen < 12 or blen % 4: return
        body = f.read(blen - 12)
        if len(body) < blen - 12: return
        f.read(4)
        if btype == 1 and len(body) >= 8:
            linktype, tsresol = struct.unpack(endian + "H", body[0:2])[0], 1e-6
            for code, val in _iter_options(body[8:], endian):
                if code == 9 and len(val) == 1: tsresol = 2.0 ** -(val[0] & 0x7F) if val[0] & 0x80 else 10.0 ** -val[0]
            interfaces.append((linktype, tsresol))
        elif btype == 6 and len(body) >= 20:
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            linktype, tsresol = interfaces[if_id] if if_id < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6); number += 1
            yield RawPacket(((ts_hi << 32) | ts_lo) * tsresol, body[20:20 + cap_len], orig_len, linktype, number)

def _iter_options(buf, endian):
    off = 0
    while off + 4 <= len(buf):
        code, length = struct.unpack(endian + "HH", buf[off:off + 4]); off += 4
        if code == 0: return
        yield code, buf[off:off + length]; off += (length + 3) & ~3

class PcapWriter:
    def __init__(self, path, linktype=LINKTYPE_ETHERNET):
        self._f = open(path, "wb"); self._f.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 65535, linktype)); self.count = 0

    def write(self, ts, data):
        sec = int(ts); self._f.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(data), len(data)) + data); self.count += 1

    def close(self):
        self._f.close()

def write_pcap(path, packets, linktype=LINKTYPE_ETHERNET):
    w = PcapWriter(path, linktype)
    try:
        for ts, data in packets: w.write(ts, data)
    finally: w.close()
