import struct; from dataclasses import dataclass, field; from ipaddress import ip_address

QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

@dataclass
class DnsMessage:
    txid: int; is_response: bool; rcode: int; questions: list = field(default_factory=list); answers: list = field(default_factory=list)

def parse_name(msg, off, depth=0):
    labels, jumps, next_off = [], 0, -1
    while True:
        if off >= len(msg) or jumps > 20 or len(labels) > 127: break
        length = msg[off]
        if length == 0: off += 1; break
        if length & 0xC0 == 0xC0:
            if off + 2 > len(msg): break
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if next_off < 0: next_off = off + 2
            if ptr >= off: break
            off, jumps = ptr, jumps + 1; continue
        if length & 0xC0: break
        labels.append(msg[off + 1:off + 1 + length].decode("ascii", "replace")); off += 1 + length
    return ".".join(labels), (next_off if next_off >= 0 else off)

def parse(payload):
    if len(payload) < 12: return None
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12]); msg = DnsMessage(txid=txid, is_response=bool(flags & 0x8000), rcode=flags & 0x0F); off = 12
    try:
        for _ in range(min(qd, 32)):
            name, off = parse_name(payload, off)
            if off + 4 > len(payload): return msg
            qtype = struct.unpack("!H", payload[off:off + 2])[0]; off += 4; msg.questions.append((name, QTYPE.get(qtype, str(qtype))))
        for _ in range(min(an, 64)):
            name, off = parse_name(payload, off)
            if off + 10 > len(payload): return msg
            rtype, _, _, rdlen = struct.unpack("!HHIH", payload[off:off + 10]); off += 10; rdata = payload[off:off + rdlen]; off += rdlen
            msg.answers.append((name, QTYPE.get(rtype, str(rtype)), _rdata_str(rtype, rdata, payload, off - rdlen)))
    except (struct.error, IndexError): pass
    return msg

def _rdata_str(rtype, rdata, msg, rd_off):
    try:
        if (rtype == 1 and len(rdata) == 4) or (rtype == 28 and len(rdata) == 16): return str(ip_address(rdata))
        if rtype in (2, 5, 12): return parse_name(msg, rd_off)[0]
        if rtype == 15 and len(rdata) >= 2: return parse_name(msg, rd_off + 2)[0]
        if rtype == 16:
            parts, off = [], 0
            while off < len(rdata): ln = rdata[off]; parts.append(rdata[off + 1:off + 1 + ln].decode("ascii", "replace")); off += 1 + ln
            return "".join(parts)
    except (ValueError, IndexError): pass
    return rdata.hex()
