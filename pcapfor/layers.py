import struct; from dataclasses import dataclass; from ipaddress import ip_address; from typing import Optional

from .pcapio import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW_IP

ETH_IPV4, ETH_ARP, ETH_VLAN, ETH_QINQ, ETH_IPV6 = 0x0800, 0x0806, 0x8100, 0x88A8, 0x86DD; TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

@dataclass
class Arp:
    op: int; sender_mac: str; sender_ip: str; target_mac: str; target_ip: str

@dataclass
class Packet:
    number: int; ts: float; eth_src: str = ""; eth_dst: str = ""; vlan: Optional[int] = None; arp: Optional[Arp] = None
    src: str = ""; dst: str = ""; proto: str = ""; ttl: int = 0; sport: int = 0; dport: int = 0; tcp_flags: int = 0; seq: int = 0; ack: int = 0; payload: bytes = b""; icmp_type: int = -1

    def flag(self, f):
        return bool(self.tcp_flags & f)

def _mac(b):
    return ":".join(f"{x:02x}" for x in b)

def decode(raw):
    pkt, data = Packet(number=raw.number, ts=raw.ts), raw.data
    if raw.linktype == LINKTYPE_ETHERNET:
        if len(data) < 14: return None
        pkt.eth_dst, pkt.eth_src = _mac(data[0:6]), _mac(data[6:12]); etype, off = struct.unpack("!H", data[12:14])[0], 14
        while etype in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4: pkt.vlan = struct.unpack("!H", data[off:off + 2])[0] & 0x0FFF; etype = struct.unpack("!H", data[off + 2:off + 4])[0]; off += 4
        return _dispatch_ethertype(pkt, etype, data[off:])
    if raw.linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16: return None
        return _dispatch_ethertype(pkt, struct.unpack("!H", data[14:16])[0], data[16:])
    if raw.linktype == LINKTYPE_RAW_IP:
        if data and (data[0] >> 4) == 6: return _decode_ipv6(pkt, data)
        return _decode_ipv4(pkt, data)
    return None

def _dispatch_ethertype(pkt, etype, body):
    if etype == ETH_ARP: return _decode_arp(pkt, body)
    if etype == ETH_IPV4: return _decode_ipv4(pkt, body)
    if etype == ETH_IPV6: return _decode_ipv6(pkt, body)
    return pkt

def _decode_arp(pkt, b):
    if len(b) < 28: return pkt
    pkt.arp = Arp(struct.unpack("!H", b[6:8])[0], _mac(b[8:14]), str(ip_address(b[14:18])), _mac(b[18:24]), str(ip_address(b[24:28]))); return pkt

def _decode_ipv4(pkt, b):
    if len(b) < 20 or (b[0] >> 4) != 4: return pkt
    ihl, total_len = (b[0] & 0x0F) * 4, struct.unpack("!H", b[2:4])[0]; pkt.ttl, pkt.src, pkt.dst = b[8], str(ip_address(b[12:16])), str(ip_address(b[16:20]))
    end = min(len(b), total_len) if 20 <= total_len else len(b); return _decode_l4(pkt, b[9], b[ihl:end])

def _decode_ipv6(pkt, b):
    if len(b) < 40 or (b[0] >> 4) != 6: return pkt
    payload_len, nxt, pkt.ttl = struct.unpack("!H", b[4:6])[0], b[6], b[7]; pkt.src, pkt.dst = str(ip_address(b[8:24])), str(ip_address(b[24:40])); body, hops = b[40:40 + payload_len], 0
    while nxt in (0, 43, 44, 60) and len(body) >= 8 and hops < 8: hdr_len = 8 if nxt == 44 else (body[1] + 1) * 8; nxt, body, hops = body[0], body[hdr_len:], hops + 1
    return _decode_l4(pkt, {6: 6, 17: 17, 58: 1}.get(nxt, nxt), body)

def _decode_l4(pkt, proto, b):
    if proto == 6 and len(b) >= 20: pkt.proto = "tcp"; pkt.sport, pkt.dport, pkt.seq, pkt.ack = struct.unpack("!HHII", b[0:12]); pkt.tcp_flags, pkt.payload = b[13], b[(b[12] >> 4) * 4:]
    elif proto == 17 and len(b) >= 8: pkt.proto = "udp"; pkt.sport, pkt.dport, ulen = struct.unpack("!HHH", b[0:6]); pkt.payload = b[8:max(8, min(len(b), ulen))]
    elif proto == 1 and len(b) >= 4: pkt.proto, pkt.icmp_type, pkt.payload = "icmp", b[0], b[4:]
    else: pkt.proto, pkt.payload = "other", b
    return pkt
