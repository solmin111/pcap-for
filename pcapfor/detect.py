import base64; import math; import re; import statistics; from collections import Counter, defaultdict; from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network; from urllib.parse import unquote_plus

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
THRESHOLDS = {"portscan_min_ports": 15, "hostscan_min_hosts": 10, "brute_min_attempts": 8, "dns_min_queries": 20, "dns_label_len": 30, "dns_entropy": 3.5, "dns_len_extreme": 60, "dns_null_min": 20, "beacon_min_events": 8, "beacon_max_cv": 0.15, "beacon_min_interval": 2.0}
INF = float("inf")

@dataclass
class Finding:
    severity: str; category: str; title: str; description: str; evidence: list = field(default_factory=list)
    mitre: str = ""; recommendation: str = ""; session_ids: list = field(default_factory=list); ts: float = 0.0

    @property
    def rank(self):
        return SEVERITY_ORDER.get(self.severity, 0)

META = { "portscan": ("high", "recon", "T1046 (Network Service Discovery)", "해당 출발지 IP 차단 여부 검토, 스캔 이후 성공한 연결이 있는지 추적", "포트 스캔 의심: {src} -> {dst}", "{src} 가 {dst} 의 서로 다른 포트 {total}개에 SYN을 보냈고, 그중 {probes}개는 응답이 없는 미완성 연결입니다."), "hostscan": ("medium", "recon", "T1018 (Remote System Discovery)", "출발지 호스트의 감염 여부 점검", "호스트 스윕 의심: {src} (포트 {port})", "{src} 가 포트 {port} 로 호스트 {hosts}대를 차례로 접촉했습니다. 내부망 수평 이동 전 정찰 패턴입니다."), "brute_ftp": ("high", "bruteforce", "T1110 (Brute Force)", "해당 계정 잠금/비밀번호 변경, 출발지 차단", "FTP 브루트포스 의심: {src} -> {dst}", "로그인 실패(530) 응답이 {n}회 관찰되었습니다."), "brute_http": ("high", "bruteforce", "T1110.001 (Password Guessing)", "계정 잠금 정책·레이트 리밋 적용 검토", "HTTP 인증 브루트포스 의심: {src} -> {dst}{uri}", "동일 경로에 인증 실패 응답이 {n}회 반복되었습니다."), "brute_quick": ("medium", "bruteforce", "T1110 (Brute Force)", "인증 로그와 대조하여 실패 로그인 확인", "{svc} 반복 접속 의심: {src} -> {dst}", "{svc}({port}) 로 짧은 연결이 {n}회 반복되었습니다. 암호화 구간이라 내용 대신 연결 패턴으로 판단했습니다."), "cred_ftp": ("high", "credential", "T1040 (Network Sniffing)", "FTPS/SFTP 전환, 노출된 비밀번호 즉시 변경", "FTP 평문 자격증명 노출: {key}", "FTP 로그인 정보가 암호화 없이 전송되었습니다."), "cred_smtp": ("high", "credential", "T1048.003 (Exfiltration Over Unencrypted Protocol), T1040", "해당 계정 비밀번호 즉시 변경, 수신자 주소 차단, 발신 호스트 격리·점검", "SMTP 평문 자격증명·메일 전송: {key}", "SMTP 인증 정보가 암호화 없이 전송되었습니다(base64는 암호화가 아님). 정보 탈취 멀웨어가 수집 데이터를 메일로 내보내는 경로로도 쓰입니다."), "cred_telnet": ("high", "credential", "T1040 (Network Sniffing), T1021 (Remote Services)", "Telnet 비활성화 후 SSH 로 전환, 노출된 계정 비밀번호 즉시 변경", "Telnet 평문 자격증명 노출: {key}", "Telnet 은 로그인 정보와 입력 명령을 암호화 없이 전송합니다. 같은 구간을 캡처한 누구나 계정과 작업 내용을 그대로 볼 수 있습니다."), "cred_basic": ("high", "credential", "T1040 (Network Sniffing)", "HTTPS 적용, 해당 계정 비밀번호 변경", "HTTP Basic 인증 평문 노출: {key}", "Authorization: Basic 헤더는 base64일 뿐 암호화가 아닙니다."), "cred_form": ("medium", "credential", "T1040 (Network Sniffing)", "HTTPS 적용", "HTTP 폼 비밀번호 평문 전송: {key}", "POST {uri} 본문에 비밀번호 필드가 평문으로 포함되어 있습니다."), "web": (None, "webattack", None, "WAF 룰 점검, 해당 엔드포인트 입력 검증 확인, 응답 코드로 성공 여부 판단", "{name} 시도: {src} -> {dst}", "{method} {uri} 에서 공격 패턴이 발견되었습니다."), "dns_tunnel": ("critical", "c2", "T1071.004 (DNS), T1048 (Exfiltration)", "해당 도메인 차단 및 질의 호스트 격리, DNS 로그로 유출량 추정", "DNS 터널링 의심: {dom}", "{dom} 으로 질의 {n}건. 서브도메인 평균 길이 {avg_len:.0f}자, 평균 엔트로피 {avg_entropy:.2f}, 고유 비율 {uniq_ratio:.0%}: 데이터를 서브도메인에 인코딩해 내보내는 패턴입니다."), "dga": ("high", "c2", "T1568.002 (Domain Generation Algorithms)", "질의 호스트의 프로세스/작업 스케줄러 점검", "DGA 의심 (NXDOMAIN 다발): {host}", "{host} 가 서로 다른 도메인 {n}개를 질의했지만 모두 존재하지 않았습니다(NXDOMAIN). 도메인 생성 알고리즘(DGA)으로 C2 서버를 찾는 멀웨어 패턴입니다."), "beacon": ("high", "c2", "T1071 (Application Layer Protocol), T1573 (Encrypted Channel)", "{dst} 평판 조회, 출발 호스트 메모리/자동실행 항목 점검", "C2 비커닝 의심: {src} -> {dst}:{port}", "평균 {mean:.1f}초 간격으로 {n}회 연결 (간격 변동계수 {cv:.3f}). 사람의 통신은 이렇게 규칙적이지 않습니다."), "post_c2": ("high", "c2", "T1071.001 (Web Protocols), T1132 (Data Encoding)", "{target} 차단, 요청을 보낸 호스트 격리 후 랜섬웨어 감염 여부 점검", "HTTP POST C2 의심: {clients} -> {target}{path}", "같은 스크립트로 암호화된 16진수 페이로드를 담은 POST 가 {n}회 반복되었습니다. 감염 PC 가 C2 서버에 체크인하는 랜섬웨어 계열의 전형적인 패턴입니다."), "rat": ("high", "c2", "T1113 (Screen Capture), T1041 (Exfiltration Over C2 Channel), T1219", "{server}:{port} 통신 차단, {client} 즉시 격리 후 원격 제어 악성코드 점검", "원격 화면 캡처 유출 의심(RAT): {client} -> {server}:{port}", "비표준 포트 {port} 로 이미지 파일을 {n}회 업로드하고 서버는 짧은 명령만 보냈습니다. 원격 제어 악성코드가 화면을 찍어 공격자에게 보내는 행위로 보입니다."), "arp_ip": ("critical", "spoofing", "T1557.002 (ARP Cache Poisoning)", "정적 ARP/DAI(Dynamic ARP Inspection) 적용, 해당 구간 트래픽 전수 조사", "ARP 스푸핑 의심: {ip} 를 MAC {n}개가 주장", "같은 IP에 대해 서로 다른 MAC 주소가 ARP 응답을 보냈습니다. 중간자(MITM) 공격의 전형적인 흔적입니다."), "arp_mac": ("high", "spoofing", "T1557.002 (ARP Cache Poisoning)", "스위치 MAC 테이블·DHCP 기록으로 정상 소유자 확인, 정적 ARP/DAI 적용, 해당 MAC 장비 격리", "ARP 스푸핑 의심: MAC {mac} 가 IP {n}개를 주장", "한 장비(MAC)가 서로 다른 IP 여러 개의 주인이라고 ARP 로 알렸습니다. 다른 호스트(특히 게이트웨이)의 IP를 사칭해 트래픽을 가로채는 캐시 포이즈닝 패턴입니다."), "ioc_ip": ("critical", "ioc", "-", "해당 IP와 통신한 모든 호스트 격리·점검", "IOC 일치 (IP): {peer}", "침해지표 목록의 IP가 트래픽에 등장했습니다. 예: {key}"), "ioc_dom": ("critical", "ioc", "-", "질의 호스트 격리, DNS 싱크홀 적용", "IOC 일치 (도메인): {qname}", "침해지표 도메인 '{dom}' 에 대한 DNS 질의가 관찰되었습니다."), }

def F(rule, kw, ev=(), sids=(), ts=0.0, sev=None, mitre=None):
    s, c, m, r, title, desc = META[rule]; reco = r.format(**kw) if r and "{" in r else r; return Finding(sev or s, c, title.format(**kw), desc.format(**kw), list(ev), mitre or m, reco, list(sids), ts)

def _b64(raw):
    return base64.b64decode(raw + b"=" * (-len(raw) % 4))

def _strip_telnet(raw):
    b = re.sub(rb"\xff\xfa.*?\xff\xf0", b"", raw, flags=re.S); b = re.sub(rb"\xff[\xfb-\xfe].", b"", b, flags=re.S)
    b = re.sub(rb"\xff[\xf0-\xfa]", b"", b).replace(b"\xff\xff", b"\xff").replace(b"\x00", b""); out = bytearray()
    for ch in b:
        if ch in (0x08, 0x7F):
            if out and out[-1] not in (0x0A, 0x0D): out.pop()
        else: out.append(ch)
    return bytes(out)

def shannon_entropy(s):
    if not s: return 0.0
    n = len(s); return -sum(c / n * math.log2(c / n) for c in Counter(s).values())

def _registered_domain(name):
    parts = name.rstrip(".").split("."); return ".".join(parts[-2:]) if len(parts) >= 2 else name

def _printable(b, n=70):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:n])

def run_all(data, ioc_path=None):
    findings = []
    for det in (detect_port_scan, detect_host_scan, detect_bruteforce, detect_cleartext_credentials, detect_web_attacks, detect_dns_tunneling, detect_beaconing, detect_arp_spoofing, detect_http_post_c2, detect_rat_screen_exfil):
        findings.extend(det(data))
    if ioc_path: findings.extend(detect_ioc(data, ioc_path))
    findings.sort(key=lambda f: -f.rank); return findings

def detect_port_scan(data):
    out, probes, opened, first = [], defaultdict(lambda: defaultdict(set)), defaultdict(lambda: defaultdict(set)), defaultdict(lambda: INF)
    for s in data.sessions:
        if s.proto != "tcp" or not s.syn_seen: continue
        if not s.synack_seen and s.bytes_s2c == 0: probes[s.client][s.server].add(s.sport); first[(s.client, s.server)] = min(first[(s.client, s.server)], s.first_ts)
        elif s.synack_seen and s.bytes_c2s == 0: opened[s.client][s.server].add(s.sport)
    for src, by_dst in probes.items():
        for dst, ports in by_dst.items():
            if len(ports) < THRESHOLDS["portscan_min_ports"]: continue
            ev, found = [f"대상 포트 예시: {', '.join(map(str, sorted(ports)[:12]))} ..."], sorted(opened[src][dst])
            if found: ev.append(f"응답한 열린 포트(공격자가 발견한 서비스): {', '.join(map(str, found[:15]))}")
            out.append(F("portscan", dict(src=src, dst=dst, total=len(ports) + len(found), probes=len(ports)), ev, ts=first[(src, dst)]))
    return out

def detect_host_scan(data):
    out, sweep, first = [], defaultdict(lambda: defaultdict(set)), defaultdict(lambda: INF)
    for s in data.sessions:
        if s.proto == "tcp" and s.syn_seen and not s.synack_seen: sweep[s.client][s.sport].add(s.server); first[(s.client, s.sport)] = min(first[(s.client, s.sport)], s.first_ts)
    for src, by_port in sweep.items():
        for port, hosts in by_port.items():
            if len(hosts) >= THRESHOLDS["hostscan_min_hosts"]: out.append(F("hostscan", dict(src=src, port=port, hosts=len(hosts)), [f"대상 호스트 예시: {', '.join(sorted(hosts)[:8])} ..."], ts=first[(src, port)]))
    return out

def detect_bruteforce(data):
    out, n_min = [], THRESHOLDS["brute_min_attempts"]; fails, first = defaultdict(int), defaultdict(lambda: INF)
    for sess, c2s, s2c in data.ftp_streams:
        n = s2c.count(b"530")
        if n: k = (sess.client, sess.server); fails[k] += n; first[k] = min(first[k], sess.first_ts)
    for (src, dst), n in fails.items():
        if n >= n_min: out.append(F("brute_ftp", dict(src=src, dst=dst, n=n), [f"실패 횟수: {n}"], ts=first[(src, dst)]))
    auth, afirst = defaultdict(int), defaultdict(lambda: INF)
    for sess, tx in data.http_transactions:
        if tx.response and tx.response.status in (401, 403) and tx.request: k = (sess.client, sess.server, tx.request.uri); auth[k] += 1; afirst[k] = min(afirst[k], sess.first_ts)
    for (src, dst, uri), n in auth.items():
        if n >= n_min: out.append(F("brute_http", dict(src=src, dst=dst, uri=uri, n=n), [f"경로: {uri}", f"실패 횟수: {n}"], ts=afirst[(src, dst, uri)]))
    quick, qfirst = defaultdict(int), defaultdict(lambda: INF)
    for s in data.sessions:
        if s.proto == "tcp" and s.sport in (22, 23, 3389) and s.synack_seen and s.duration < 10 and (s.fin_seen or s.rst_seen): k = (s.client, s.server, s.sport); quick[k] += 1; qfirst[k] = min(qfirst[k], s.first_ts)
    for (src, dst, port), n in quick.items():
        if n >= n_min: out.append(F("brute_quick", dict(svc={22: "SSH", 23: "Telnet", 3389: "RDP"}[port], src=src, dst=dst, port=port, n=n), [f"짧은 연결 수: {n}"], ts=qfirst[(src, dst, port)]))
    return out

def _smtp_auth(c2s):
    lines = c2s.split(b"\r\n")
    for i, line in enumerate(lines):
        up = line.strip().upper()
        if up.startswith(b"AUTH LOGIN"):
            parts = line.strip().split()
            try:
                if len(parts) >= 3: return _b64(parts[2]).decode("latin-1"), (_b64(lines[i + 1].strip()).decode("latin-1") if i + 1 < len(lines) else None)
                if i + 2 < len(lines): return _b64(lines[i + 1].strip()).decode("latin-1"), _b64(lines[i + 2].strip()).decode("latin-1")
                return None, None
            except Exception: return "(base64 디코딩 실패)", None
        if up.startswith(b"AUTH PLAIN"):
            parts = line.strip().split()
            try:
                if len(parts) >= 3:
                    fields = _b64(parts[2]).split(b"\x00")
                    if len(fields) >= 3: return fields[1].decode("latin-1"), fields[2].decode("latin-1")
                return None, None
            except Exception: return "(base64 디코딩 실패)", None
    return None, None

def detect_cleartext_credentials(data):
    out = []
    for sess, c2s, s2c in data.ftp_streams:
        user, pw = re.search(rb"USER (\S+)", c2s), re.search(rb"PASS (\S+)", c2s)
        if user and pw and b"230" in s2c: out.append(F("cred_ftp", dict(key=sess.key_str), [f"USER: {user.group(1).decode('latin-1')}", f"PASS: {'*' * len(pw.group(1))} (캡처에 평문 존재)"], [sess.sid], sess.first_ts))
    for sess, c2s, s2c in data.smtp_streams:
        user, pw = _smtp_auth(c2s)
        if user is None: continue
        ev = [f"AUTH 사용자: {user}"]
        if pw: ev.append(f"비밀번호: {'*' * min(len(pw), 12)} (캡처에 base64 평문 존재)")
        rcpt = re.search(rb"RCPT TO:<([^>\r\n]+)>", c2s, re.I); subj = re.search(rb"Subject: ([^\r\n]{1,60})", c2s, re.I)
        if rcpt: ev.append(f"수신자: {rcpt.group(1).decode('latin-1')}")
        if subj: ev.append(f"메일 제목: {subj.group(1).decode('latin-1', 'replace')}")
        out.append(F("cred_smtp", dict(key=sess.key_str), ev, [sess.sid], sess.first_ts))
    for sess, c2s, s2c in getattr(data, "telnet_streams", []):
        srv = _strip_telnet(s2c).lower()
        if not (b"login:" in srv or b"username:" in srv) or b"password" not in srv: continue
        lines = [ln.strip() for ln in re.split(rb"\r\n|\r|\n", _strip_telnet(c2s)) if ln.strip()]
        if not lines: continue
        pw = lines[1] if len(lines) > 1 else b""; cmds = [ln.decode("latin-1", "replace")[:40] for ln in lines[2:7]]; ev = [f"사용자명: {lines[0].decode('latin-1', 'replace')[:40]}"]
        if pw: ev.append(f"비밀번호: {'*' * min(len(pw), 12)} (캡처에 평문 존재)")
        ev.append("로그인 결과: " + ("실패 응답 관찰" if (b"incorrect" in srv or b"failed" in srv) else "성공으로 보임 (실패 응답 없음)"))
        if cmds: ev.append("로그인 후 실행 명령: " + ", ".join(cmds))
        out.append(F("cred_telnet", dict(key=sess.key_str), ev, [sess.sid], sess.first_ts))
    seen_form = set()
    for sess, tx in data.http_transactions:
        if not tx.request: continue
        auth = tx.request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try: user = base64.b64decode(auth[6:]).decode("latin-1").split(":", 1)[0]
            except Exception: user = "(디코딩 실패)"
            out.append(F("cred_basic", dict(key=sess.key_str), [f"URI: {tx.request.uri}", f"사용자명: {user}"], [sess.sid], sess.first_ts))
        if tx.request.method == "POST" and tx.request.body:
            body = unquote_plus(tx.request.body.decode("latin-1", "replace")); m = re.search(r"(?:^|&)(passw(?:or)?d|pwd|pass)=([^&\s]+)", body, re.I)
            if not m: continue
            dedup = (sess.client, sess.server, tx.request.uri)
            if dedup in seen_form: continue
            seen_form.add(dedup); ev = [f"필드명: {m.group(1)}"]; um = re.search(r"(?:^|&)(user(?:name)?|login|id|email|uid)=([^&\s]+)", body, re.I)
            if um: ev.insert(0, f"사용자명: {um.group(2)[:40]}")
            ev.append(f"비밀번호: {'*' * min(len(m.group(2)), 12)} (본문에 평문 존재)"); out.append(F("cred_form", dict(key=sess.key_str, uri=tx.request.uri), ev, [sess.sid], sess.first_ts))
    return out

WEB_ATTACK_RULES = [ ("SQL 인젝션", "high", "T1190", re.compile(r"(union(\s|\+|/\*.*?\*/)+select|'\s*or\s+'?(?P<t>\w+)'?\s*=\s*'?(?P=t)|sleep\(\d+\)|benchmark\(|information_schema)", re.I)), ("XSS(크로스사이트 스크립팅)", "medium", "T1189", re.compile(r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|document\.cookie)", re.I)), ("경로 조작/LFI", "high", "T1190", re.compile(r"(\.\./){2,}|/etc/passwd|\\windows\\system32|php://(filter|input)", re.I)), ("Log4Shell(JNDI 조회)", "critical", "T1190", re.compile(r"\$\{jndi:(ldap|rmi|dns)s?://", re.I)), ("Shellshock", "critical", "T1190", re.compile(r"\(\)\s*\{\s*:?\s*;\s*\}\s*;", re.I)), ("명령 주입", "high", "T1190", re.compile(r"(;|\||%3b|%7c)\s*(cat|whoami|wget|curl|nc|bash|powershell)(\s|%20|\+)", re.I)), ]

def detect_web_attacks(data):
    out, seen = [], set()
    for sess, tx in data.http_transactions:
        if not tx.request: continue
        haystacks = [unquote_plus(tx.request.uri)]
        if tx.request.body: haystacks.append(unquote_plus(tx.request.body.decode("latin-1", "replace")))
        if tx.request.headers: haystacks.append(" ".join(tx.request.headers.values()))
        for name, sev, mitre, rx in WEB_ATTACK_RULES:
            for text in haystacks:
                m = rx.search(text)
                if not m: continue
                dedup = (name, sess.client, sess.server, tx.request.uri[:80])
                if dedup not in seen:
                    seen.add(dedup)
                    out.append(F("web", dict(name=name, src=sess.client, dst=sess.server, method=tx.request.method, uri=tx.request.uri[:120]), [f"일치 문자열: {m.group(0)[:100]}", f"응답 상태: {tx.response.status if tx.response else '(없음)'}"], [sess.sid], sess.first_ts, sev=sev, mitre=f"{mitre} (Exploit Public-Facing Application)"))
                break
    return out

def detect_dns_tunneling(data):
    out, by_domain, txt_count, null_count = [], defaultdict(list), Counter(), Counter(); nx_by_host, dom_first, nx_first = defaultdict(set), defaultdict(lambda: INF), defaultdict(lambda: INF)
    for src, msg, mts in data.dns_messages:
        for qname, qtype in msg.questions:
            if not qname or "." not in qname or qname.rstrip(".").endswith((".in-addr.arpa", ".ip6.arpa")): continue
            parts = qname.rstrip(".").split("."); zones = [".".join(parts[-2:])] if len(parts) >= 3 else []
            if len(parts) >= 4: zones.append(".".join(parts[-3:]))
            if not msg.is_response:
                for dom in zones:
                    by_domain[dom].append((src, qname)); dom_first[dom] = min(dom_first[dom], mts)
                    if qtype == "TXT": txt_count[dom] += 1
                    elif qtype == "NULL": null_count[dom] += 1
            elif msg.rcode == 3: nx_by_host[src].add(_registered_domain(qname)); nx_first[src] = min(nx_first[src], mts)
    suspicious = {}
    for dom, queries in by_domain.items():
        if len(queries) < THRESHOLDS["dns_min_queries"]: continue
        subs = [q[:-(len(dom) + 1)] for _, q in queries if q.rstrip(".").endswith("." + dom) and q[:-(len(dom) + 1)]]
        if not subs: continue
        uniq_ratio, avg_len = len(set(subs)) / len(subs), sum(len(s) for s in subs) / len(subs); avg_entropy = sum(shannon_entropy(s) for s in subs) / len(subs)
        if ((avg_len >= THRESHOLDS["dns_label_len"] and avg_entropy >= THRESHOLDS["dns_entropy"] and uniq_ratio > 0.8) or avg_len >= THRESHOLDS["dns_len_extreme"] or null_count[dom] >= THRESHOLDS["dns_null_min"]):
            suspicious[dom] = (queries, subs, uniq_ratio, avg_len, avg_entropy)
    for dom, (queries, subs, uniq_ratio, avg_len, avg_entropy) in suspicious.items():
        if any(child != dom and child.endswith("." + dom) for child in suspicious): continue
        out.append(F("dns_tunnel", dict(dom=dom, n=len(queries), avg_len=avg_len, avg_entropy=avg_entropy, uniq_ratio=uniq_ratio), [f"질의 호스트: {', '.join(sorted({s for s, _ in queries})[:5])}", f"서브도메인 예시: {subs[0][:60]}...", f"TXT 질의: {txt_count[dom]}건 · NULL 질의: {null_count[dom]}건 / 총 {len(queries)}건"], ts=dom_first[dom]))
    for host, failed in nx_by_host.items():
        if len(failed) < THRESHOLDS["dns_min_queries"]: continue
        avg_ent = sum(shannon_entropy(d.split(".")[0]) for d in failed) / len(failed)
        if avg_ent >= 3.0: out.append(F("dga", dict(host=host, n=len(failed)), [f"실패 도메인 예시: {', '.join(sorted(failed)[:5])}", f"평균 엔트로피: {avg_ent:.2f}"], ts=nx_first[host]))
    return out

def detect_beaconing(data):
    out, conn_times = [], defaultdict(list)
    for s in data.sessions:
        if s.proto == "tcp": conn_times[(s.client, s.server, s.sport)].append(s.first_ts)
    for (src, dst, port), times in conn_times.items():
        if len(times) < THRESHOLDS["beacon_min_events"]: continue
        times.sort(); gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < THRESHOLDS["beacon_min_events"] - 1: continue
        mean = statistics.fmean(gaps)
        if mean < THRESHOLDS["beacon_min_interval"]: continue
        cv = statistics.pstdev(gaps) / mean if mean else 99
        if cv <= THRESHOLDS["beacon_max_cv"]: out.append(F("beacon", dict(src=src, dst=dst, port=port, mean=mean, n=len(times), cv=cv), [f"연결 횟수: {len(times)}", f"평균 간격: {mean:.2f}s", f"CV: {cv:.3f}"], ts=times[0]))
    return out

_HEX_POST = re.compile(rb"[A-Za-z]{1,3}=[0-9a-fA-F]{64,}")

def detect_http_post_c2(data):
    out, groups = [], defaultdict(list)
    for sess, tx in data.http_transactions:
        q = tx.request
        if q and q.method == "POST" and q.body and _HEX_POST.fullmatch(q.body.strip()): groups[(sess.server, q.host, q.uri.split("?")[0])].append((sess, tx))
    for (server, host, path), items in groups.items():
        if len(items) < 2: continue
        clients, first = sorted({s.client for s, _ in items}), items[0][1].request; statuses = [str(t.response.status) if t.response else "-" for _, t in items]
        out.append(F("post_c2", dict(clients=", ".join(clients), target=host or server, path=path, n=len(items)), [f"서버: {server} (Host: {host or '-'})", f"요청 예시: POST {first.uri[:70]}", f"본문 예시: {first.body[:44].decode('latin-1')}… ({len(first.body)}바이트)", f"응답 코드: {', '.join(statuses)}"], [s.sid for s, _ in items], min(s.first_ts for s, _ in items)))
    return out

_IMG_MAGIC = (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n"); _STD_TCP_PORTS = {20, 21, 25, 80, 110, 143, 443, 587, 993, 995, 8000, 8080, 8443}

def detect_rat_screen_exfil(data):
    out, uploads = [], defaultdict(list)
    for s in data.sessions:
        if s.proto != "tcp" or s.sport in _STD_TCP_PORTS or s.bytes_c2s < 1024: continue
        head = s.stream(c2s=True)[:4096]; positions = [p for p in (head.find(m) for m in _IMG_MAGIC) if p >= 0]
        if positions and min(positions) <= 512 and s.bytes_s2c < 200: uploads[(s.client, s.server, s.sport)].append((s, head[:min(positions)]))
    for (client, server, port), items in uploads.items():
        if len(items) < 3: continue
        ev = [f"이미지 업로드 세션 {len(items)}개, 총 {sum(s.bytes_c2s for s, _ in items):,}바이트 (서버 응답은 세션당 200바이트 미만)"]; header = items[0][1].strip()
        if header: ev.append(f"업로드 헤더: {_printable(header)}")
        ctrl = max((x for x in data.sessions if (x.client, x.server, x.sport) == (client, server, port)), key=lambda x: x.duration)
        if ctrl.duration > 10:
            ev.append(f"명령 채널: 세션 #{ctrl.sid} {ctrl.duration:.0f}초 지속"); ev.append(f"  감염 PC → 서버: {_printable(ctrl.stream(c2s=True))}")
            ev.append(f"  서버 → 감염 PC: {_printable(ctrl.stream(c2s=False))}")
        out.append(F("rat", dict(client=client, server=server, port=port, n=len(items)), ev, [s.sid for s, _ in items], min(s.first_ts for s, _ in items)))
    return out

def detect_arp_spoofing(data):
    out, claims, reply_count, ip_first = [], defaultdict(set), Counter(), defaultdict(lambda: INF)
    for ats, a in data.arp_records:
        if a.op == 2: claims[a.sender_ip].add(a.sender_mac); reply_count[(a.sender_ip, a.sender_mac)] += 1; ip_first[a.sender_ip] = min(ip_first[a.sender_ip], ats)
    for ip, macs in claims.items():
        if len(macs) > 1: detail = ", ".join(f"{m}({reply_count[(ip, m)]}회)" for m in sorted(macs)); out.append(F("arp_ip", dict(ip=ip, n=len(macs)), [f"{ip} <- {detail}"], ts=ip_first[ip]))
    mac_ips, mac_ops, mac_first = defaultdict(set), Counter(), defaultdict(lambda: INF)
    for ats, a in data.arp_records:
        if a.sender_ip == "0.0.0.0" or a.sender_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"): continue
        mac_ips[a.sender_mac].add(a.sender_ip); mac_ops[(a.sender_mac, a.sender_ip, a.op)] += 1; mac_first[a.sender_mac] = min(mac_first[a.sender_mac], ats)
    for mac, ips in mac_ips.items():
        if len(ips) < 2: continue
        detail = [f"{ip} (요청 {mac_ops[(mac, ip, 1)]}회 · 응답 {mac_ops[(mac, ip, 2)]}회)" for ip in sorted(ips)]
        out.append(F("arp_mac", dict(mac=mac, n=len(ips)), [f"{mac} 가 주장한 IP: " + ", ".join(detail)], ts=mac_first[mac]))
    return out

def detect_ioc(data, path):
    ips, nets, domains = set(), [], set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                try: nets.append(ip_network(line, strict=False)) if "/" in line else ips.add(str(ip_address(line)))
                except ValueError: domains.add(line.lower().rstrip("."))
    except OSError as e: return [Finding("info", "ioc", "IOC 파일을 읽지 못함", str(e))]
    out, hit_ips = [], set()
    for s in data.sessions:
        for peer in (s.client, s.server):
            if peer in hit_ips: continue
            matched = peer in ips
            if not matched and nets:
                try: addr = ip_address(peer); matched = any(addr in n for n in nets)
                except ValueError: pass
            if matched: hit_ips.add(peer); out.append(F("ioc_ip", dict(peer=peer, key=s.key_str), [f"세션 수 집계 필요: '{peer}' 로 필터링"], [s.sid], s.first_ts))
    hit_doms = set()
    for _, msg, mts in data.dns_messages:
        for qname, _ in msg.questions:
            q = qname.lower().rstrip(".")
            for d in domains:
                if (q == d or q.endswith("." + d)) and d not in hit_doms: hit_doms.add(d); out.append(F("ioc_dom", dict(qname=qname, dom=d), ts=mts))
    return out
