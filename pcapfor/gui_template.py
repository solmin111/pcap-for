"""GUI 프론트엔드 템플릿 (D01 다크 SOC 대시보드 + D08 토폴로지 맵).

__PAYLOAD__ 자리에 JSON 페이로드가 주입된다. 외부 리소스 없이 완전 self-contained.
mode=="live" 면 /api/state 를 2초 폴링해 화면을 갱신한다.
"""

TEMPLATE = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcap for</title>
<style>
:root{--bg:#11151c;--panel:#1a2029;--panel2:#202835;--border:#2a3240;--text:#e6ebf2;
 --muted:#8b97a8;--accent:#4b9fff;--crit:#ef5350;--high:#ff8a4c;--med:#ffd54f;--low:#9ccc65;--info:#90a4ae}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Malgun Gothic','Segoe UI',sans-serif;font-size:14px}
#app{display:grid;grid-template-columns:200px 1fr 320px;min-height:100vh}
.hidden{display:none!important}
.muted{color:var(--muted)}
/* ---------- 사이드바 ---------- */
#side{background:#0d1117;border-right:1px solid var(--border);padding:18px 14px;display:flex;flex-direction:column;gap:4px}
.brand{display:flex;align-items:center;gap:9px}
.brand .bt{font-family:Consolas,monospace;font-weight:700;font-size:19px;line-height:1.1}
.brand .bt span{color:var(--accent)}
.brand-sub{color:var(--muted);font-size:11px;margin:4px 0 16px 2px}
nav a{display:block;padding:9px 12px;border-radius:7px;color:var(--muted);text-decoration:none;margin-bottom:2px;cursor:pointer}
nav a.on{background:var(--panel2);color:var(--text)}
nav a:hover{color:var(--text)}
#live-side{margin-top:14px;color:var(--crit);font-size:12px;font-weight:700}
#side-foot{margin-top:auto;color:#55617a;font-size:10.5px;line-height:1.6;word-break:break-all}
/* ---------- 메인 ---------- */
#main{padding:20px 24px;min-width:0}
#hdr{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;gap:12px}
#hdr h1{font-size:19px;margin:0 0 3px}
#hdr-sub{font-size:12px}
#live-strip{background:#2a1215;border:1px solid #5c2a2e;color:#ff9a9a;border-radius:8px;
 padding:7px 14px;font-size:12.5px;white-space:nowrap}
#live-strip .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--crit);
 margin-right:6px;animation:blink 1.2s infinite}
@keyframes blink{50%{opacity:.25}}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:13px 16px}
.card .k{color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.card .v{font-size:25px;font-weight:700;margin-top:3px}
.card .s{color:var(--muted);font-size:11.5px;margin-top:2px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:14px}
.ptitle{font-size:13px;font-weight:700;margin-bottom:10px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
#chart{width:100%;height:200px;display:block}
.axis{display:flex;justify-content:space-between;color:var(--muted);font-size:10.5px;margin-top:4px}
.bar-row{display:grid;grid-template-columns:86px 1fr 46px;align-items:center;gap:8px;margin:6px 0;font-size:12px}
.bar-track{background:#232c3a;border-radius:4px;height:10px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;background:var(--accent)}
.bar-fill.g{background:#26a69a}
/* ---------- 탐지 피드 ---------- */
#feed{background:#151a22;border-left:1px solid var(--border);padding:18px 16px;overflow-y:auto;max-height:100vh;position:sticky;top:0}
.fitem{border:1px solid var(--border);border-left:3px solid var(--muted);background:var(--panel);
 border-radius:8px;padding:10px 12px;margin-bottom:10px;cursor:pointer}
.fitem .t{font-weight:700;font-size:12.5px;margin:6px 0 3px}
.fitem .d{color:var(--muted);font-size:11.5px;line-height:1.5}
.fitem .ev{display:none;margin-top:7px;border-top:1px dashed var(--border);padding-top:7px;font-size:11px;color:#a8b6c8}
.fitem.open .ev{display:block}
.fitem .ev div{margin:2px 0}
.badge{display:inline-block;font-size:10px;font-weight:700;padding:1px 8px;border-radius:9px;letter-spacing:.05em}
.b-critical{background:#3b1518;color:#ff8a86;border:1px solid #713035}.fitem.sev-critical{border-left-color:var(--crit)}
.b-high{background:#3a2313;color:#ffb27d;border:1px solid #7a4a28}.fitem.sev-high{border-left-color:var(--high)}
.b-medium{background:#3a3213;color:#ffe082;border:1px solid #7a6a28}.fitem.sev-medium{border-left-color:var(--med)}
.b-low{background:#1d3315;color:#b5e48c;border:1px solid #42682f}.fitem.sev-low{border-left-color:var(--low)}
.b-info{background:#1d2733;color:#a8c0d8;border:1px solid #3a4f66}.fitem.sev-info{border-left-color:var(--info)}
.cat{color:var(--muted);font-size:10.5px;margin-left:6px}
/* ---------- 토폴로지 ---------- */
.topo-wrap{display:grid;grid-template-columns:1fr 290px;gap:14px}
#topo{width:100%;height:600px;background:var(--panel);border:1px solid var(--border);border-radius:10px}
#topo line{stroke:#3a4556}
#topo text{fill:var(--muted);font-size:10px;font-family:Consolas,monospace}
#topo circle{cursor:pointer}
.legend{display:flex;gap:16px;color:var(--muted);font-size:11.5px;margin-top:8px;flex-wrap:wrap}
.legend i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
#topo-panel{align-self:start;min-height:200px}
#topo-panel .ip{font-family:Consolas,monospace;font-size:15px;font-weight:700}
#topo-panel table{width:100%;font-size:11.5px;border-collapse:collapse;margin-top:8px}
#topo-panel td{padding:3px 0;border-bottom:1px solid #222b38}
#topo-panel td:last-child{text-align:right;color:var(--muted)}
/* ---------- 테이블 ---------- */
table.list{width:100%;border-collapse:collapse;font-size:12px}
table.list th{color:var(--muted);text-align:left;font-weight:600;padding:7px 10px;border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap}
table.list td{padding:6px 10px;border-bottom:1px solid #202836;font-family:Consolas,monospace;font-size:11.5px}
table.list tr.fl td{background:#241a1a}
.pill{font-family:'Malgun Gothic';display:inline-block;background:#232c3a;border-radius:4px;padding:0 7px;font-size:10.5px}
.det-full{margin-bottom:12px}
.det-full .d{margin:6px 0;color:#c3cedb;font-size:12.5px;line-height:1.55}
.det-full .m{color:#b39ddb;font-size:11.5px;margin-top:4px}
.det-full .r{color:#90caf9;font-size:11.5px;margin-top:2px}
.det-full .e{color:#a8b6c8;font-size:11.5px;font-family:Consolas,monospace}
/* ---------- 타임라인 ---------- */
#tl-svg{width:100%;height:340px;display:block}
#tl-svg text{fill:var(--muted);font-size:10.5px}
#tl-svg line.grid{stroke:#232c3a}
#tl-svg circle{cursor:pointer;stroke:rgba(0,0,0,.4);stroke-width:1}
/* ---------- 증거 뷰어 ---------- */
.ev-wrap{display:grid;grid-template-columns:270px 1fr;gap:14px;align-items:start}
.ev-item{border:1px solid var(--border);border-left:3px solid var(--high);background:var(--panel2);
 border-radius:7px;padding:8px 10px;margin-bottom:8px;cursor:pointer;font-family:Consolas,monospace;font-size:11px}
.ev-item.sel{border-color:var(--accent);border-left-color:var(--accent)}
.ev-item .m{color:var(--muted);font-family:'Malgun Gothic';font-size:10.5px;margin-top:2px}
.stream{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:8px 11px;
 font-family:Consolas,monospace;font-size:11px;line-height:1.55;white-space:pre-wrap;word-break:break-all;
 max-height:300px;overflow-y:auto;margin:4px 0 10px}
.stream.c2s{border-left:3px solid var(--accent)}
.stream.s2c{border-left:3px solid #26a69a}
.stream mark{background:#5c2a2e;color:#ffb3af;border-radius:2px;padding:0 2px}
.dirlab{font-size:11px;color:var(--muted);margin-top:6px}
/* ---------- 칸반 보드 ---------- */
.board{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;align-items:start}
.bcol{background:#151a22;border:1px solid var(--border);border-radius:10px;padding:10px;min-width:0}
.bcol .bh{font-size:12px;font-weight:700;margin-bottom:8px;display:flex;justify-content:space-between}
.bcol .bh .n{color:var(--muted);font-weight:400}
.bcard{background:var(--panel);border:1px solid var(--border);border-radius:7px;padding:9px 11px;
 margin-bottom:8px;cursor:pointer;border-top:3px solid var(--muted)}
.bcard.sev-critical{border-top-color:var(--crit)} .bcard.sev-high{border-top-color:var(--high)}
.bcard.sev-medium{border-top-color:var(--med)} .bcard.sev-low{border-top-color:var(--low)}
.bcard.sev-info{border-top-color:var(--info)}
.bcard .t{font-weight:700;font-size:12px;margin-bottom:3px;word-break:break-all}
.bcard .d{color:var(--muted);font-size:11px;line-height:1.5;word-break:break-all}
.bcard .ev{display:none;margin-top:6px;border-top:1px dashed var(--border);padding-top:6px;font-size:10.5px;color:#a8b6c8}
.bcard.open .ev{display:block}
@media(max-width:1100px){#app{grid-template-columns:170px 1fr}#feed{display:none}}
</style>
</head>
<body>
<script type="application/json" id="payload">__PAYLOAD__</script>
<div id="app">
<aside id="side">
  <div class="brand">
    <svg width="46" height="30" viewBox="0 0 90 100">
      <rect x="20" y="36" width="12" height="56" rx="6" fill="#e6ebf2"/>
      <circle cx="48" cy="56" r="15" fill="none" stroke="#e6ebf2" stroke-width="12"/>
      <g transform="rotate(-8 44 28)">
        <path d="M 26 32 A 21 21 0 0 1 66 32 L 26 32 Z" fill="#4b9fff"/>
        <rect x="60" y="28" width="24" height="8" rx="4" fill="#1565c0"/>
        <circle cx="46" cy="13" r="3.5" fill="#1565c0"/>
      </g>
    </svg>
    <div class="bt">pcap<br><span>for</span></div>
  </div>
  <div class="brand-sub" id="side-mode">network forensics</div>
  <nav id="nav">
    <a data-tab="overview" class="on">Overview</a>
    <a data-tab="timeline">Timeline</a>
    <a data-tab="topology">Topology</a>
    <a data-tab="evidence">Evidence</a>
    <a data-tab="board">Board</a>
    <a data-tab="sessions">Sessions</a>
    <a data-tab="detections">Detections</a>
  </nav>
  <div id="live-side" class="hidden">● LIVE CAPTURE</div>
  <footer id="side-foot"></footer>
</aside>

<main id="main">
  <header id="hdr">
    <div><h1 id="hdr-title"></h1><div id="hdr-sub" class="muted"></div></div>
    <div id="live-strip" class="hidden"><span class="dot"></span>LIVE ·
      <b id="pps">0</b> pkt/s · <span id="elapsed">00:00</span></div>
  </header>

  <section id="tab-overview" class="tab">
    <div class="cards" id="cards"></div>
    <div class="panel"><div class="ptitle">Traffic over time (pkts/s)</div>
      <svg id="chart" viewBox="0 0 800 200" preserveAspectRatio="none"></svg>
      <div class="axis" id="chart-x"></div></div>
    <div class="cols">
      <div class="panel"><div class="ptitle">Protocol distribution</div><div id="protos"></div></div>
      <div class="panel"><div class="ptitle">Top talkers (packets)</div><div id="talkers"></div></div>
    </div>
  </section>

  <section id="tab-topology" class="tab hidden">
    <div class="topo-wrap">
      <div>
        <svg id="topo"></svg>
        <div class="legend">
          <span><i style="background:var(--crit)"></i>심각 연루</span>
          <span><i style="background:var(--high)"></i>탐지 연루</span>
          <span><i style="background:var(--accent)"></i>내부 호스트</span>
          <span><i style="background:#26a69a"></i>외부 호스트</span>
          <span style="margin-left:auto">엣지 굵기 = 전송량 · 노드 클릭 = 상세</span>
        </div>
      </div>
      <div id="topo-panel" class="panel"><div class="muted">노드를 클릭하면 호스트 상세가 표시됩니다.</div></div>
    </div>
  </section>

  <section id="tab-timeline" class="tab hidden">
    <div class="panel"><div class="ptitle">Attack chronology — 탐지기 레인별 발생 시각 (점 클릭 = 상세)</div>
      <svg id="tl-svg"></svg>
      <div class="axis" id="tl-x"></div></div>
    <div id="tl-detail"></div>
  </section>

  <section id="tab-evidence" class="tab hidden">
    <div class="ev-wrap">
      <div class="panel" id="ev-list-panel"><div class="ptitle">탐지 연루 세션</div><div id="ev-list"></div></div>
      <div class="panel" id="ev-view"><div class="muted">왼쪽에서 세션을 선택하면 재조립된 TCP 스트림이 표시됩니다.</div></div>
    </div>
  </section>

  <section id="tab-board" class="tab hidden">
    <div class="board" id="board-cols"></div>
  </section>

  <section id="tab-sessions" class="tab hidden">
    <div class="panel"><div class="ptitle" id="sess-title">Sessions</div>
      <table class="list" id="sess-table"><thead><tr>
        <th data-k="sid">#</th><th data-k="proto">Proto</th><th data-k="client">Client</th>
        <th data-k="server">Server</th><th data-k="first">First</th>
        <th data-k="pkts">Pkts</th><th data-k="bytes">Bytes</th><th data-k="state">State</th>
      </tr></thead><tbody></tbody></table></div>
  </section>

  <section id="tab-detections" class="tab hidden"><div id="det-list"></div></section>
</main>

<aside id="feed">
  <div class="ptitle">Detections <span class="muted" id="feed-count"></span></div>
  <div id="feed-list"></div>
</aside>
</div>

<script>
"use strict";
let S = JSON.parse(document.getElementById('payload').textContent);
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SEVK = {critical:'심각', high:'높음', medium:'중간', low:'낮음', info:'정보'};
const fmtB = b => b>1048576 ? (b/1048576).toFixed(1)+' MB' : b>1024 ? (b/1024).toFixed(1)+' KB' : b+' B';
const fmtN = n => n.toLocaleString();

/* ---------- 탭 ---------- */
function showTab(name){
  document.querySelectorAll('.tab').forEach(t => t.classList.add('hidden'));
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.dataset.tab===name));
  const el = $('tab-'+name); if (el) el.classList.remove('hidden');
  if (name==='topology') renderTopo();
  if (name==='timeline') renderTimelineTab();
  history.replaceState(null,'','#'+name);
}
document.querySelectorAll('#nav a').forEach(a => a.onclick = () => showTab(a.dataset.tab));

/* ---------- 오버뷰 ---------- */
function renderHeader(){
  const m = S.meta;
  if (S.mode==='live'){
    $('hdr-title').textContent = 'Live Capture';
    $('hdr-sub').textContent = m.source + ' · 시작 후 ' + m.duration.toFixed(0) + '초 · 관리자 세션';
    $('live-strip').classList.remove('hidden');
    $('live-side').classList.remove('hidden');
    $('side-mode').textContent = 'live packet capture';
    $('side-foot').textContent = '본인 소유/관리 호스트 전용 · ARP는 라이브에서 비가시';
  } else {
    const file = m.source.split(/[\\/]/).pop();
    $('hdr-title').textContent = 'Capture Overview';
    $('hdr-sub').textContent = file + ' · ' + m.analyzed_at + ' · SHA-256 ' + (m.sha256||'').slice(0,16) + '…';
    $('side-foot').textContent = 'offline analysis · ' + file;
  }
}
function renderCards(){
  const sev = S.stats.by_severity, m = S.meta;
  const sevTxt = ['critical','high','medium'].filter(k=>sev[k]).map(k=>SEVK[k]+' '+sev[k]).join(' · ') || '없음';
  $('cards').innerHTML = [
    ['PACKETS', fmtN(m.packets), fmtB(m.bytes)],
    ['SESSIONS', fmtN(S.stats.sessions), 'TCP/UDP 플로우'],
    ['FINDINGS', S.stats.findings, sevTxt],
    [S.mode==='live'?'ELAPSED':'DURATION', m.duration.toFixed(0)+'s', S.mode==='live'?'캡처 진행 중':'캡처 구간'],
  ].map(c=>'<div class="card"><div class="k">'+c[0]+'</div><div class="v">'+c[1]+'</div><div class="s">'+esc(c[2])+'</div></div>').join('');
}
function renderChart(){
  const tl = S.timeline, svg = $('chart');
  if (!tl.bins.length){ svg.innerHTML=''; $('chart-x').innerHTML=''; return; }
  const W=800, H=200, P=8, n=tl.bins.length, mx=Math.max(...tl.bins,1);
  const x = i => P + i*(W-2*P)/Math.max(n-1,1);
  const y = v => H-P - v*(H-2*P)/mx;
  let pts=[]; for(let i=0;i<n;i++) pts.push(x(i)+','+y(tl.bins[i]));
  svg.innerHTML =
    '<polygon points="'+x(0)+','+(H-P)+' '+pts.join(' ')+' '+x(n-1)+','+(H-P)+'" fill="rgba(75,159,255,.14)"/>'+
    '<polyline points="'+pts.join(' ')+'" fill="none" stroke="var(--accent)" stroke-width="2"/>';
  const t = s => new Date(s*1000).toISOString().substr(11,8);
  $('chart-x').innerHTML = '<span>'+t(tl.t0)+'</span><span>'+t(tl.t0+Math.floor(n/2)*tl.dt)+'</span><span>'+t(tl.t0+(n-1)*tl.dt)+'</span>';
}
function bars(el, rows, green){
  const mx = Math.max(...rows.map(r=>r[1]),1);
  el.innerHTML = rows.map(r =>
    '<div class="bar-row"><span style="font-family:Consolas,monospace">'+esc(r[0])+'</span>'+
    '<div class="bar-track"><div class="bar-fill'+(green?' g':'')+'" style="width:'+(r[1]/mx*100).toFixed(1)+'%"></div></div>'+
    '<span class="muted">'+fmtN(r[1])+'</span></div>').join('');
}
/* ---------- 탐지 피드 / 탭 ---------- */
function fBadge(f){ return '<span class="badge b-'+f.sev+'">'+SEVK[f.sev].toUpperCase()+'</span><span class="cat">'+esc(f.cat)+'</span>'; }
function renderFeed(){
  $('feed-count').textContent = S.findings.length + ' findings';
  $('feed-list').innerHTML = S.findings.map((f,i) =>
    '<div class="fitem sev-'+f.sev+'" data-i="'+i+'">'+fBadge(f)+
    '<div class="t">'+esc(f.title)+'</div><div class="d">'+esc(f.desc)+'</div>'+
    '<div class="ev">'+f.evidence.map(e=>'<div>· '+esc(e)+'</div>').join('')+
    (f.mitre && f.mitre!=='-' ? '<div style="color:#b39ddb">MITRE: '+esc(f.mitre)+'</div>':'')+
    (f.reco ? '<div style="color:#90caf9">대응: '+esc(f.reco)+'</div>':'')+'</div></div>'
  ).join('') || '<div class="muted">탐지 없음 — 이상 징후가 발견되지 않았습니다.</div>';
  document.querySelectorAll('.fitem').forEach(el => el.onclick = () => el.classList.toggle('open'));
}
function renderDetTab(){
  $('det-list').innerHTML = S.findings.map(f =>
    '<div class="panel det-full">'+fBadge(f)+
    '<div class="t" style="font-weight:700;margin-top:6px">'+esc(f.title)+'</div>'+
    '<div class="d">'+esc(f.desc)+'</div>'+
    f.evidence.map(e=>'<div class="e">· '+esc(e)+'</div>').join('')+
    (f.mitre && f.mitre!=='-' ? '<div class="m">MITRE ATT&CK: '+esc(f.mitre)+'</div>':'')+
    (f.reco ? '<div class="r">대응: '+esc(f.reco)+'</div>':'')+'</div>'
  ).join('') || '<div class="panel muted">탐지 없음</div>';
}
/* ---------- 세션 테이블 ---------- */
let sortK='flagged', sortAsc=false;
function renderSessions(){
  $('sess-title').textContent = 'Sessions ('+S.sessions.length+(S.sessions.length>=800?'+':'')+')';
  const rows = [...S.sessions].sort((a,b)=>{
    let va=a[sortK], vb=b[sortK];
    if (sortK==='flagged'){ va=a.flagged?1:0; vb=b.flagged?1:0; }
    if (va<vb) return sortAsc?-1:1; if (va>vb) return sortAsc?1:-1; return b.bytes-a.bytes;
  });
  $('sess-table').querySelector('tbody').innerHTML = rows.map(s =>
    '<tr'+(s.flagged?' class="fl"':'')+'><td>'+s.sid+'</td><td><span class="pill">'+s.proto+'</span></td>'+
    '<td>'+esc(s.client)+':'+s.cport+'</td><td>'+esc(s.server)+':'+s.sport+'</td>'+
    '<td>'+s.first+'</td><td>'+fmtN(s.pkts)+'</td><td>'+fmtB(s.bytes)+'</td><td>'+esc(s.state)+'</td></tr>').join('');
}
document.querySelectorAll('#sess-table th').forEach(th => th.onclick = () => {
  const k = th.dataset.k; sortAsc = (sortK===k) ? !sortAsc : false; sortK = k; renderSessions();
});
/* ---------- 토폴로지 (간단 force 레이아웃, 위치는 갱신 간 유지) ---------- */
const pos = {};
let selectedIp = null, topoDone = false;
function nodeColor(n){
  if (n.sev==='critical') return 'var(--crit)';
  if (n.sev) return 'var(--high)';
  return n.internal ? 'var(--accent)' : '#26a69a';
}
function layout(nodes, edges, W, H){
  nodes.forEach((n,i)=>{ if(!pos[n.id]){
    const a = i/Math.max(nodes.length,1)*6.2832;
    pos[n.id] = {x: W/2+Math.cos(a)*H*0.32, y: H/2+Math.sin(a)*H*0.32}; }});
  const ids = nodes.map(n=>n.id);
  const rep = 2200 * Math.max(1, 28/Math.max(ids.length,1)); // 노드 많으면 반발 축소
  for (let it=0; it<300; it++){
    for (let i=0;i<ids.length;i++) for (let j=i+1;j<ids.length;j++){
      const p=pos[ids[i]], q=pos[ids[j]];
      let dx=p.x-q.x, dy=p.y-q.y, d2=dx*dx+dy*dy+0.01;
      const f=Math.min(rep/d2, 6);
      dx*=f; dy*=f; p.x+=dx; p.y+=dy; q.x-=dx; q.y-=dy;
    }
    edges.forEach(e=>{
      const p=pos[e.a], q=pos[e.b];
      const dx=q.x-p.x, dy=q.y-p.y, d=Math.sqrt(dx*dx+dy*dy)+0.01, f=(d-115)*0.016/d;
      p.x+=dx*f; p.y+=dy*f; q.x-=dx*f; q.y-=dy*f;
    });
    ids.forEach(id=>{ const p=pos[id];
      p.x += (W/2-p.x)*0.028; p.y += (H/2-p.y)*0.028;
      p.x = Math.max(40,Math.min(W-40,p.x)); p.y = Math.max(32,Math.min(H-36,p.y)); });
  }
}
function renderTopo(){
  const svg = $('topo'), W = svg.clientWidth||760, H = 600;
  svg.setAttribute('viewBox','0 0 '+W+' '+H);
  const g = S.graph;
  layout(g.nodes, g.edges, W, H);
  let out = '';
  g.edges.forEach(e=>{
    const p=pos[e.a], q=pos[e.b];
    const w = Math.min(7, 1+Math.log10(e.bytes+1)*0.9);
    const col = e.flagged ? 'rgba(255,138,76,.55)' : '#3a4556';
    out += '<line x1="'+p.x+'" y1="'+p.y+'" x2="'+q.x+'" y2="'+q.y+'" stroke="'+col+'" stroke-width="'+w.toFixed(1)+'"/>';
  });
  g.nodes.forEach(n=>{
    const p=pos[n.id], r = Math.min(17, 7+Math.log10(n.bytes+10));
    out += '<circle data-ip="'+esc(n.id)+'" cx="'+p.x+'" cy="'+p.y+'" r="'+r.toFixed(1)+'" fill="'+nodeColor(n)+'"'+
           (selectedIp===n.id?' stroke="#fff" stroke-width="2.5" stroke-dasharray="4 3"':'')+'/>' +
           '<text x="'+p.x+'" y="'+(p.y+r+13)+'" text-anchor="middle">'+esc(n.id)+'</text>';
  });
  svg.innerHTML = out;
  svg.querySelectorAll('circle').forEach(c => c.onclick = () => { selectedIp=c.dataset.ip; renderTopo(); renderTopoPanel(); });
}
function renderTopoPanel(){
  const n = S.graph.nodes.find(x=>x.id===selectedIp);
  if (!n){ return; }
  const findings = S.findings.filter(f => (f.title+' '+f.desc+' '+f.evidence.join(' ')).includes(n.id));
  const sess = S.sessions.filter(s=>s.client===n.id||s.server===n.id).slice(0,8);
  $('topo-panel').innerHTML =
    '<div class="ip" style="color:'+nodeColor(n)+'">'+esc(n.id)+'</div>'+
    '<div class="muted" style="font-size:11.5px">'+(n.internal?'내부(사설) 호스트':'외부 호스트')+
    (n.sev?' · 탐지 연루('+SEVK[n.sev]+')':'')+'</div>'+
    '<table><tr><td>패킷</td><td>'+fmtN(n.pkts)+'</td></tr>'+
    '<tr><td>바이트</td><td>'+fmtB(n.bytes)+'</td></tr>'+
    '<tr><td>세션</td><td>'+sess.length+(sess.length>=8?'+':'')+'</td></tr></table>'+
    (findings.length?'<div class="ptitle" style="margin-top:12px">관련 탐지 ('+findings.length+')</div>'+
      findings.map(f=>'<div class="fitem sev-'+f.sev+'" style="cursor:default">'+fBadge(f)+
        '<div class="t">'+esc(f.title)+'</div></div>').join(''):'')+
    (sess.length?'<div class="ptitle" style="margin-top:10px">세션</div><table>'+
      sess.map(s=>'<tr><td>'+esc(s.client)+' → '+esc(s.server)+':'+s.sport+'</td><td>'+s.proto+' · '+fmtB(s.bytes)+'</td></tr>').join('')+'</table>':'');
}
/* ---------- 탐지 타임라인 (D04) ---------- */
const CATS = [['recon','정찰'],['bruteforce','계정 공격'],['credential','자격증명'],
              ['webattack','웹 공격'],['c2','C2/유출'],['spoofing','스푸핑'],['ioc','IOC']];
const SEVC = {critical:'var(--crit)', high:'var(--high)', medium:'var(--med)',
              low:'var(--low)', info:'var(--info)'};
function renderTimelineTab(){
  const svg = $('tl-svg'), W = svg.clientWidth||900, H = 340, L = 92, R = 20;
  svg.setAttribute('viewBox','0 0 '+W+' '+H);
  const tl = S.timeline;
  const t0 = tl.t0, t1 = tl.t0 + Math.max(tl.bins.length,1)*tl.dt;
  const lanes = CATS.filter(c => S.findings.some(f=>f.cat===c[0]));
  if (!lanes.length){ svg.innerHTML='<text x="20" y="30">탐지가 없어 타임라인이 비어 있습니다.</text>'; $('tl-x').innerHTML=''; return; }
  const laneH = Math.min(44, (H-30)/lanes.length);
  const x = ts => L + Math.max(0,Math.min(1,(ts-t0)/Math.max(t1-t0,1)))*(W-L-R);
  let out = '';
  lanes.forEach((c,i)=>{
    const y = 18 + i*laneH + laneH/2;
    out += '<text x="4" y="'+(y+4)+'">'+c[1]+'</text>';
    out += '<line class="grid" x1="'+L+'" y1="'+y+'" x2="'+(W-R)+'" y2="'+y+'"/>';
  });
  S.findings.forEach((f,idx)=>{
    const li = lanes.findIndex(c=>c[0]===f.cat);
    if (li<0) return;
    const y = 18 + li*laneH + laneH/2;
    const px = f.ts ? x(f.ts) : L+6;  // 시각 미상은 구간 시작에
    out += '<circle data-i="'+idx+'" cx="'+px+'" cy="'+y+'" r="7" fill="'+SEVC[f.sev]+'"/>';
  });
  svg.innerHTML = out;
  const t = s => new Date(s*1000).toISOString().substr(11,8);
  $('tl-x').innerHTML = '<span style="margin-left:'+(L/ (W/100))+'%">'+t(t0)+'</span><span>'+t((t0+t1)/2)+'</span><span>'+t(t1)+'</span>';
  svg.querySelectorAll('circle').forEach(c => c.onclick = () => {
    const f = S.findings[+c.dataset.i];
    $('tl-detail').innerHTML =
      '<div class="panel det-full">'+fBadge(f)+
      '<span class="cat">'+(f.ts?new Date(f.ts*1000).toISOString().substr(11,8)+' UTC':'시각 미상')+'</span>'+
      '<div style="font-weight:700;margin-top:6px">'+esc(f.title)+'</div>'+
      '<div class="d">'+esc(f.desc)+'</div>'+
      f.evidence.map(e=>'<div class="e">· '+esc(e)+'</div>').join('')+
      (f.mitre && f.mitre!=='-' ? '<div class="m">MITRE ATT&CK: '+esc(f.mitre)+'</div>':'')+
      (f.reco ? '<div class="r">대응: '+esc(f.reco)+'</div>':'')+'</div>';
  });
}
/* ---------- 증거 스트림 뷰어 (D10) ---------- */
let evSel = null;
const HILITE = /(PASS [^\r\n]*|USER [^\r\n]*|Authorization:[^\r\n]*|password=[^&\s]*|530 [^\r\n]*|230 [^\r\n]*|\$\{jndi:[^}]*\}?|<script[^>]*>|\(\)\s*\{\s*:;\s*\};|UNION[+ ]SELECT[^\r\n]*)/gi;
function hilite(text){
  return esc(text).replace(HILITE, m => '<mark>'+m+'</mark>');
}
function renderEvidence(){
  const list = $('ev-list');
  if (!S.streams.length){
    list.innerHTML = '<div class="muted" style="font-size:12px">탐지에 연루된 세션 스트림이 없습니다.</div>';
    $('ev-view').innerHTML = '<div class="muted">표시할 증거 스트림이 없습니다.</div>';
    return;
  }
  list.innerHTML = S.streams.map(st =>
    '<div class="ev-item'+(evSel===st.sid?' sel':'')+'" data-sid="'+st.sid+'">'+
    esc(st.client)+' → '+esc(st.server)+
    '<div class="m">세션 #'+st.sid+' · '+fmtB(st.bytes)+' · '+st.first+'</div></div>').join('');
  list.querySelectorAll('.ev-item').forEach(el => el.onclick = () => {
    evSel = +el.dataset.sid; renderEvidence();
  });
  const st = S.streams.find(s=>s.sid===evSel) || S.streams[0];
  if (!st) return;
  const rel = S.findings.filter(f=>f.sids.includes(st.sid));
  $('ev-view').innerHTML =
    '<div class="ptitle">세션 #'+st.sid+' — '+esc(st.client)+' ⇄ '+esc(st.server)+'</div>'+
    rel.map(f=>'<span class="badge b-'+f.sev+'">'+SEVK[f.sev].toUpperCase()+'</span> <b style="font-size:12px">'+esc(f.title)+'</b><br>').join('')+
    '<div class="dirlab">클라이언트 → 서버'+(st.c2s_more?' (앞 4KB)':'')+'</div>'+
    '<div class="stream c2s">'+(st.c2s?hilite(st.c2s):'(데이터 없음)')+'</div>'+
    '<div class="dirlab">서버 → 클라이언트'+(st.s2c_more?' (앞 4KB)':'')+'</div>'+
    '<div class="stream s2c">'+(st.s2c?hilite(st.s2c):'(데이터 없음)')+'</div>';
}
/* ---------- 칸반 보드 (D06) ---------- */
function renderBoard(){
  const cols = [['critical','심각'],['high','높음'],['medium','중간'],['low','낮음·정보']];
  $('board-cols').innerHTML = cols.map(c => {
    const items = S.findings.filter(f => c[0]==='low' ? (f.sev==='low'||f.sev==='info') : f.sev===c[0]);
    return '<div class="bcol"><div class="bh"><span>'+c[1]+'</span><span class="n">'+items.length+'</span></div>'+
      items.map(f=>{
        const idx = S.findings.indexOf(f);
        return '<div class="bcard sev-'+f.sev+'" data-i="'+idx+'">'+
          '<div class="t">'+esc(f.title)+'</div><div class="d">'+esc(f.desc)+'</div>'+
          '<div class="ev">'+f.evidence.map(e=>'<div>· '+esc(e)+'</div>').join('')+
          (f.mitre&&f.mitre!=='-'?'<div style="color:#b39ddb">MITRE: '+esc(f.mitre)+'</div>':'')+
          (f.reco?'<div style="color:#90caf9">대응: '+esc(f.reco)+'</div>':'')+'</div></div>';
      }).join('')+'</div>';
  }).join('');
  document.querySelectorAll('.bcard').forEach(el => el.onclick = () => el.classList.toggle('open'));
}
/* ---------- 전체 렌더 + 라이브 폴링 ---------- */
function renderAll(){
  renderHeader(); renderCards(); renderChart();
  bars($('protos'), S.protocols); bars($('talkers'), S.talkers, true);
  renderFeed(); renderDetTab(); renderSessions(); renderEvidence(); renderBoard();
  if (!$('tab-topology').classList.contains('hidden')) { renderTopo(); if(selectedIp) renderTopoPanel(); }
  if (!$('tab-timeline').classList.contains('hidden')) renderTimelineTab();
}
renderAll();
const TABS = {overview:1,timeline:1,topology:1,evidence:1,board:1,sessions:1,detections:1};
showTab((location.hash||'#overview').slice(1) in TABS
        ? (location.hash||'#overview').slice(1) : 'overview');

if (S.mode === 'live'){
  let prevPkts = S.meta.packets, prevT = Date.now();
  setInterval(async () => {
    try{
      const r = await fetch('/api/state'); if (!r.ok) return;
      const openSet = new Set([...document.querySelectorAll('.fitem.open')].map(e=>e.dataset.i));
      S = await r.json();
      const now = Date.now();
      $('pps').textContent = Math.max(0,(S.meta.packets-prevPkts)/((now-prevT)/1000)).toFixed(0);
      prevPkts = S.meta.packets; prevT = now;
      const el = Math.floor(S.meta.duration);
      $('elapsed').textContent = String(Math.floor(el/60)).padStart(2,'0')+':'+String(el%60).padStart(2,'0');
      renderAll();
      openSet.forEach(i => { const e=document.querySelector('.fitem[data-i="'+i+'"]'); if(e) e.classList.add('open'); });
    }catch(e){ /* 서버 종료 시 조용히 무시 */ }
  }, 2000);
}
</script>
</body>
</html>
"""
