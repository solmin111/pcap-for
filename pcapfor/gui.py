import json; import math; import re; import threading; from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer; from ipaddress import ip_address, ip_network

from .detect import SEVERITY_ORDER; from .gui_template import TEMPLATE

MAX_SESSIONS, MAX_BINS, MAX_STREAM_SESSIONS, MAX_STREAM_CHARS = 800, 120, 12, 4000; _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_INTERNAL_NETS = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]

def _fmt_ts(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S") if ts else "-"

def _flagged_ips(findings):
    out = {}
    for f in findings:
        text = " ".join([f.title, f.description] + list(f.evidence))
        for ip in _IP_RE.findall(text):
            try: ip_address(ip)
            except ValueError: continue
            if ip not in out or SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(out[ip], 0): out[ip] = f.severity
    return out

def _rebin(timeline):
    if not timeline: return {"t0": 0, "dt": 1, "bins": []}
    t0, t1 = min(timeline), max(timeline); dt = max(1, math.ceil((t1 - t0 + 1) / MAX_BINS)); bins = [0] * math.ceil((t1 - t0 + 1) / dt)
    for sec, n in timeline.items(): bins[(sec - t0) // dt] += n
    return {"t0": t0, "dt": dt, "bins": bins}

def _is_internal(ip):
    try: a = ip_address(ip); return any(a in n for n in _INTERNAL_NETS)
    except ValueError: return False

def _sessions_payload(sessions, flagged, flagged_sids):
    rows = [{"sid": s.sid, "proto": s.proto, "client": s.client, "cport": s.cport, "server": s.server, "sport": s.sport, "first": _fmt_ts(s.first_ts), "pkts": s.packets, "bytes": s.bytes_c2s + s.bytes_s2c, "state": "RST" if s.rst_seen else ("FIN" if s.fin_seen else ("개방" if s.synack_seen else "미완성")), "flagged": s.sid in flagged_sids or s.client in flagged or s.server in flagged} for s in sessions]
    rows.sort(key=lambda r: (not r["flagged"], -r["bytes"])); return rows[:MAX_SESSIONS]

def _edge_proto(s):
    if s.proto == "tcp" and s.sport in (80, 8080): return "http"
    if s.proto == "tcp" and s.sport == 443: return "tls"
    if s.proto == "udp" and s.sport == 53: return "dns"
    return "ftp" if s.sport == 21 else s.proto

def _graph_payload(sessions, flagged, flagged_sids):
    nodes, edges = {}, {}
    for s in sessions:
        pair = tuple(sorted((s.client, s.server))); e = edges.setdefault(pair, {"a": pair[0], "b": pair[1], "bytes": 0, "pkts": 0, "protos": set(), "flagged": False})
        e["bytes"] += s.bytes_c2s + s.bytes_s2c; e["pkts"] += s.packets; e["protos"].add(_edge_proto(s))
        if s.sid in flagged_sids: e["flagged"] = True
        for ip in (s.client, s.server): n = nodes.setdefault(ip, {"id": ip, "internal": _is_internal(ip), "pkts": 0, "bytes": 0, "sev": ""}); n["pkts"] += s.packets; n["bytes"] += s.bytes_c2s + s.bytes_s2c
    for ip, sev in flagged.items():
        if ip in nodes:
            cur = nodes[ip]["sev"]
            if not cur or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(cur, 0): nodes[ip]["sev"] = sev
        else: nodes[ip] = {"id": ip, "internal": _is_internal(ip), "pkts": 0, "bytes": 0, "sev": sev}
    for e in edges.values():
        if flagged.get(e["a"]) or flagged.get(e["b"]): e["flagged"] = True
        e["protos"] = sorted(e["protos"])
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}

def _findings_payload(findings):
    return [{"sev": f.severity, "cat": f.category, "title": f.title, "desc": f.description, "evidence": list(f.evidence), "mitre": f.mitre, "reco": f.recommendation, "sids": list(f.session_ids), "ts": f.ts if math.isfinite(f.ts) and f.ts > 0 else 0} for f in findings]

def _printable(data):
    return "".join(ch if (32 <= ord(ch) < 127) or ch in "\r\n\t" else "." for ch in data.decode("latin-1", "replace"))

def _streams_payload(sessions, flagged_sids):
    out = []
    for s in sessions:
        if s.sid not in flagged_sids or s.proto != "tcp": continue
        c2s, s2c = s.stream(c2s=True), s.stream(c2s=False)
        if not c2s and not s2c: continue
        out.append({"sid": s.sid, "client": f"{s.client}:{s.cport}", "server": f"{s.server}:{s.sport}", "bytes": s.bytes_c2s + s.bytes_s2c, "first": _fmt_ts(s.first_ts), "c2s": _printable(c2s[:MAX_STREAM_CHARS]), "s2c": _printable(s2c[:MAX_STREAM_CHARS]), "c2s_more": len(c2s) > MAX_STREAM_CHARS, "s2c_more": len(s2c) > MAX_STREAM_CHARS})
        if len(out) >= MAX_STREAM_SESSIONS: break
    return out

def _common_payload(mode, meta, timeline, protocol_counts, sessions, findings):
    flagged = _flagged_ips(findings); flagged_sids = {sid for f in findings for sid in f.session_ids}; sev_counts, talkers = {}, {}
    for f in findings: sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    for s in sessions:
        for ip in (s.client, s.server): talkers[ip] = talkers.get(ip, 0) + s.packets
    return {"mode": mode, "brand": "pcap for", "meta": meta, "stats": {"sessions": len(sessions), "findings": len(findings), "by_severity": sev_counts}, "timeline": _rebin(dict(timeline)), "protocols": sorted(protocol_counts.items(), key=lambda kv: -kv[1]), "talkers": sorted(talkers.items(), key=lambda kv: -kv[1])[:8], "findings": _findings_payload(findings), "sessions": _sessions_payload(sessions, flagged, flagged_sids), "graph": _graph_payload(sessions, flagged, flagged_sids), "streams": _streams_payload(sessions, flagged_sids)}

def payload_from_result(result):
    meta = {"source": result.path, "sha256": result.sha256, "analyzed_at": result.analyzed_at, "duration": round(result.duration, 1), "packets": result.packet_count, "bytes": result.byte_count}
    return _common_payload("file", meta, result.timeline, result.protocol_counts, result.data.sessions, result.findings)

def payload_from_live(engine, iface_ip):
    import time; protos = {}
    for s in engine.table.sessions: protos[s.proto] = protos.get(s.proto, 0) + s.packets
    meta = {"source": f"{iface_ip} (raw socket)", "sha256": None, "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "duration": round(time.time() - engine.started_at, 1), "packets": engine.packet_count, "bytes": engine.byte_count}
    return _common_payload("live", meta, engine.timeline, protos, engine.table.sessions, engine.findings)

def render_html(payload):
    return TEMPLATE.replace("__PAYLOAD__", json.dumps(payload, ensure_ascii=False))

def render_static(result, out_path):
    with open(out_path, "w", encoding="utf-8") as f: f.write(render_html(payload_from_result(result)))

class _LiveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?")[0] in ("/", "/index.html"): body, ctype = render_html(self.server.state_fn()).encode("utf-8"), "text/html; charset=utf-8"
        elif self.path.startswith("/api/state"): body, ctype = json.dumps(self.server.state_fn(), ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"
        else: self.send_error(404); return
        self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

    def log_message(self, *args):
        pass

def start_live_server(engine, iface_ip):
    def state_fn():
        with engine.lock: return payload_from_live(engine, iface_ip)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LiveHandler); server.state_fn = state_fn
    threading.Thread(target=server.serve_forever, daemon=True).start(); return server, f"http://127.0.0.1:{server.server_address[1]}/"
