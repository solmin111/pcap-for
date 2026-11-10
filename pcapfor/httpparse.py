import gzip; import zlib; from dataclasses import dataclass, field; from typing import Optional

METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH "); MAX_BODY = 1024 * 1024

@dataclass
class HttpRequest:
    method: str; uri: str; version: str; headers: dict = field(default_factory=dict); body: bytes = b""

    @property
    def host(self):
        return self.headers.get("host", "")

@dataclass
class HttpResponse:
    status: int; reason: str; headers: dict = field(default_factory=dict); body: bytes = b""

@dataclass
class HttpTransaction:
    request: Optional[HttpRequest]; response: Optional[HttpResponse]

def looks_like_http(c2s):
    return c2s.startswith(METHODS)

def parse_transactions(c2s, s2c):
    requests = _parse_messages(c2s, is_request=True); responses = [r for r in _parse_messages(s2c, is_request=False) if not (isinstance(r, HttpResponse) and r.status == 100)]
    return [HttpTransaction(requests[i] if i < len(requests) else None, responses[i] if i < len(responses) else None) for i in range(max(len(requests), len(responses)))]

def _parse_messages(stream, is_request):
    msgs, off = [], 0
    while off < len(stream) and len(msgs) < 500:
        head_end = stream.find(b"\r\n\r\n", off)
        if head_end < 0: break
        lines = stream[off:head_end].decode("latin-1", "replace").split("\r\n"); start, headers = lines[0], {}
        for line in lines[1:]:
            if ":" in line: k, v = line.split(":", 1); headers[k.strip().lower()] = v.strip()
        body_off = head_end + 4
        if is_request:
            parts = start.split(" ", 2)
            if len(parts) < 3 or not start.startswith(tuple(m.decode() for m in METHODS)): break
            msg = HttpRequest(parts[0], parts[1], parts[2], headers); has_body = "content-length" in headers or headers.get("transfer-encoding", "").lower() == "chunked"
        else:
            if not start.startswith("HTTP/"): break
            parts = start.split(" ", 2)
            try: status = int(parts[1])
            except (IndexError, ValueError): break
            msg = HttpResponse(status, parts[2] if len(parts) > 2 else "", headers); has_body = status >= 200 and status not in (204, 304)
        body = b""
        if has_body:
            if "chunked" in headers.get("transfer-encoding", "").lower(): body, off = _read_chunked(stream, body_off)
            elif "content-length" in headers:
                try: clen = int(headers["content-length"])
                except ValueError: clen = 0
                body, off = stream[body_off:body_off + clen], body_off + clen
            elif not is_request: body, off = stream[body_off:], len(stream)
            else: off = body_off
        else: off = body_off
        if not is_request: body = _decompress(body, headers.get("content-encoding", "").lower())
        msg.body = body[:MAX_BODY]; msgs.append(msg)
        if off <= head_end: break
    return msgs

def _read_chunked(stream, off):
    body = bytearray()
    while off < len(stream):
        line_end = stream.find(b"\r\n", off)
        if line_end < 0: break
        try: size = int(stream[off:line_end].split(b";")[0].strip(), 16)
        except ValueError: break
        off = line_end + 2
        if size == 0: trailer_end = stream.find(b"\r\n", off); off = (trailer_end + 2) if trailer_end >= 0 else len(stream); break
        body += stream[off:off + size]; off += size + 2
        if len(body) > MAX_BODY: break
    return bytes(body), off

def _decompress(body, encoding):
    try:
        if "gzip" in encoding and body[:2] == b"\x1f\x8b": return gzip.decompress(body)
        if "deflate" in encoding:
            try: return zlib.decompress(body)
            except zlib.error: return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError): pass
    return body
