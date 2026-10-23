#pragma once

/* Single-page dashboard served at /. Kept as a raw string so it can be
 * edited like normal HTML without escaping. */
static const char PWN_WEB_PAGE[] =
R"PWNWEB(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PWNI</title>
<style>
:root{--bg:#050806;--panel:#0c120d;--line:#1c2a1e;--fg:#d6f5d6;--dim:#6f8a72;
--acc:#8cf58c;--acc2:#5cffb0;--warn:#ffcc66;--bad:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
a{color:var(--acc2)}
header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:12px;
padding:12px 16px;background:rgba(5,8,6,.94);border-bottom:1px solid var(--line);
backdrop-filter:blur(6px)}
.logo{font-size:22px;font-weight:700;letter-spacing:3px;color:var(--acc);
text-shadow:0 0 14px rgba(140,245,140,.45)}
.dot{width:9px;height:9px;border-radius:50%;background:#444;box-shadow:0 0 8px #000}
.dot.on{background:var(--acc);box-shadow:0 0 10px var(--acc)}
.dot.warn{background:var(--warn);box-shadow:0 0 10px var(--warn)}
.spacer{flex:1}
.ip{color:var(--dim);font-size:12px}
nav{display:flex;gap:4px;overflow:auto;padding:8px 12px;border-bottom:1px solid var(--line);
position:sticky;top:57px;background:rgba(5,8,6,.94);z-index:4}
nav button{background:transparent;border:1px solid transparent;color:var(--dim);
padding:8px 12px;border-radius:8px;font:inherit;cursor:pointer;white-space:nowrap}
nav button:hover{color:var(--fg);border-color:var(--line)}
nav button.active{color:#051006;background:var(--acc);font-weight:700}
main{padding:16px;max-width:1100px;margin:0 auto}
section{display:none}section.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
.card h3{margin:0 0 6px;font-size:11px;letter-spacing:1.5px;color:var(--dim);font-weight:600;
text-transform:uppercase}
.big{font-size:26px;color:var(--acc);font-weight:700;line-height:1.1}
.sub{color:var(--dim);font-size:12px;margin-top:2px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;margin-top:14px}
h2{font-size:13px;letter-spacing:1.5px;color:var(--dim);margin:0 0 10px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--dim);font-size:11px;letter-spacing:1px;text-transform:uppercase;font-weight:600}
tr:hover td{background:#101810}
.mono{font-variant-numeric:tabular-nums}
.rssi{display:inline-block;width:38px;height:8px;background:#162016;border-radius:3px;
overflow:hidden;vertical-align:middle}
.rssi i{display:block;height:100%;background:var(--acc)}
.rssi-wrap{display:inline-block;white-space:nowrap}
button.act,a.act{display:inline-block;background:#142016;color:var(--acc);border:1px solid #2a3d2c;
padding:6px 10px;border-radius:7px;font:inherit;font-size:12px;cursor:pointer;text-decoration:none}
button.act:hover,a.act:hover{border-color:var(--acc)}
button.act.danger{color:var(--bad);border-color:#3d2020;background:#180d0d}
button.act.danger:hover{border-color:var(--bad)}
button.act:disabled{opacity:.35;cursor:not-allowed}
input,select{background:#0a0f0b;border:1px solid var(--line);color:var(--fg);border-radius:8px;
padding:9px 10px;font:inherit;width:100%}
label{display:block;font-size:11px;color:var(--dim);margin:10px 0 4px;letter-spacing:1px;
text-transform:uppercase}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.row>*{flex:1;min-width:120px}
.row .fit{flex:0 0 auto;min-width:0}
.sw{position:relative;display:inline-block;width:46px;height:24px;flex:0 0 auto}
.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;inset:0;background:#1a241b;border:1px solid var(--line);
border-radius:20px;cursor:pointer;transition:.2s}
.sl:before{content:"";position:absolute;width:16px;height:16px;left:3px;top:3px;
background:var(--dim);border-radius:50%;transition:.2s}
.sw input:checked+.sl{background:#173a24;border-color:var(--acc)}
.sw input:checked+.sl:before{transform:translateX(22px);background:var(--acc)}
.toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%) translateY(20px);
background:#102015;border:1px solid var(--acc);color:var(--fg);padding:10px 16px;border-radius:10px;
opacity:0;pointer-events:none;transition:.25s;z-index:50;max-width:90vw}
.toast.on{opacity:1;transform:translateX(-50%) translateY(0)}
.tag{display:inline-block;padding:2px 7px;border-radius:999px;font-size:11px;background:#142016;
border:1px solid #263a29;color:var(--dim)}
.tag.good{color:#051006;background:var(--acc);border-color:var(--acc);font-weight:700}
.tag.warn{color:var(--warn);border-color:#3d3320;background:#1e1a0d}
.tag.bad{color:var(--bad);border-color:#3d2020;background:#1e0d0d}
.bar{height:6px;background:#162016;border-radius:4px;overflow:hidden;margin-top:6px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--acc),var(--acc2))}
.event{color:var(--dim);font-size:12px;margin-top:6px;min-height:18px}
.hint{color:var(--dim);font-size:12px;margin-top:8px}
pre{white-space:pre-wrap;word-break:break-all;color:var(--dim);font-size:12px;margin:0}
footer{color:#39503c;font-size:11px;text-align:center;padding:26px 10px}
@media(max-width:600px){.big{font-size:22px}td,th{padding:7px 4px}main{padding:12px}}
</style>
</head>
<body>
<header>
  <span class="logo">PWNI</span>
  <span id="dot" class="dot"></span>
  <span id="hstate" class="ip">booting</span>
  <span class="spacer"></span>
  <span class="ip" id="hip">--</span>
</header>
<nav>
  <button data-tab="dash" class="active">Dashboard</button>
  <button data-tab="nets">Networks</button>
  <button data-tab="clients">Clients</button>
  <button data-tab="caps">Captures</button>
  <button data-tab="attack">Attacks</button>
  <button data-tab="set">Settings</button>
</nav>
<main>

<section id="dash" class="active">
  <div class="grid">
    <div class="card"><h3>Mood</h3><div class="big" id="mood">--</div>
      <div class="sub" id="pstatus">--</div></div>
    <div class="card"><h3>Level</h3><div class="big" id="level">1</div>
      <div class="sub"><span id="xp">0</span> XP &middot; bond <span id="bond">50</span>%</div></div>
    <div class="card"><h3>Access points</h3><div class="big" id="aps">0</div>
      <div class="sub"><span id="clientStat">0</span> clients seen</div></div>
    <div class="card"><h3>Handshakes</h3><div class="big" id="hs">0</div>
      <div class="sub"><span id="pmkid">0</span> PMKID &middot; <span id="saved">0</span> saved slots</div></div>
    <div class="card"><h3>Channel</h3><div class="big" id="chan">-</div>
      <div class="sub" id="band">--</div></div>
    <div class="card"><h3>Strategy</h3><div class="big" id="action" style="font-size:19px">--</div>
      <div class="sub" id="locked">--</div></div>
  </div>
  <div class="panel">
    <h2>Live</h2>
    <div class="row" style="align-items:stretch">
      <div><div class="sub">frames</div><div class="big" id="frames" style="font-size:20px">0</div></div>
      <div><div class="sub">EAPOL</div><div class="big" id="eapol" style="font-size:20px">0</div></div>
      <div><div class="sub">deauth</div><div class="big" id="deauth" style="font-size:20px">0</div></div>
      <div><div class="sub">dropped</div><div class="big" id="drop" style="font-size:20px">0</div></div>
      <div><div class="sub">uptime</div><div class="big" id="up" style="font-size:20px">0s</div></div>
    </div>
    <div class="event" id="event">listening...</div>
  </div>
  <div class="panel">
    <h2>Now</h2>
    <div class="row">
      <button class="act" id="bPause">Pause</button>
      <button class="act" id="bScan">Rescan WiFi</button>
      <button class="act" id="bAuthState">Attack status</button>
    </div>
    <div class="hint">Web UI is read/write over your LAN. Active attacks need the
    authorization phrase (Attacks tab).</div>
  </div>
</section>

<section id="nets">
  <div class="panel">
    <div class="row"><h2 style="margin:0">Nearby networks</h2>
      <span style="flex:0 0 auto"><button class="act" id="bScan2">Rescan</button></span></div>
    <table><thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th>
      <th>Security</th><th>Flags</th><th></th></tr></thead>
      <tbody id="netRows"><tr><td colspan="7" class="sub">scanning...</td></tr></tbody></table>
  </div>
</section>

<section id="clients">
  <div class="panel">
    <h2>Observed clients</h2>
    <table><thead><tr><th>Station</th><th>BSSID</th><th>RSSI</th><th>Frames</th><th></th></tr></thead>
      <tbody id="cliRows"><tr><td colspan="5" class="sub">waiting...</td></tr></tbody></table>
  </div>
</section>

<section id="caps">
  <div class="panel">
    <h2>Captured handshakes</h2>
    <table><thead><tr><th>SSID</th><th>BSSID / station</th><th>Type</th>
      <th>Frames</th><th>File</th><th></th></tr></thead>
      <tbody id="capRows"><tr><td colspan="6" class="sub">none yet</td></tr></tbody></table>
  </div>
  <div class="panel" style="margin-top:14px">
    <h2>Saved PCAPs</h2>
    <table><thead><tr><th>File</th><th>Size</th><th></th></tr></thead>
      <tbody id="fileRows"><tr><td colspan="3" class="sub">none yet</td></tr></tbody></table>
  </div>
</section>

<section id="attack">
  <div class="panel">
    <h2>Authorization</h2>
    <div id="authBox" class="sub">Locked. Active attacks are disabled.</div>
    <div class="row" style="margin-top:10px">
      <input id="phrase" type="password" placeholder="authorization phrase" autocomplete="off">
      <button class="act fit" id="bAuth">Unlock</button>
      <button class="act danger fit" id="bRevoke">Lock</button>
    </div>
    <div class="hint">Only use active features on networks you own or have written
    permission to test. The phrase is checked on the device.</div>
  </div>
  <div class="panel">
    <h2>Deauthentication</h2>
    <label>Target AP</label>
    <select id="targetAp"><option value="">-- select an AP --</option></select>
    <div class="row" style="margin-top:8px">
      <div><label>Burst</label><select id="deauthDur">
        <option value="5000">5 seconds</option>
        <option value="8000" selected>8 seconds</option>
        <option value="15000">15 seconds</option>
        <option value="30000">30 seconds</option>
      </select></div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="act danger" id="bDeauthAll">Deauth all clients</button>
      <button class="act danger" id="bDeauthBcast">Broadcast</button>
      <button class="act" id="bDeauthStop">Stop</button>
      <button class="act" id="bHop">Park on AP channel</button>
    </div>
    <div id="deauthState" class="sub">idle</div>
    <div class="hint">Deauth runs for the selected burst duration so clients
    cannot immediately reassociate. Only observed clients are targeted; the
    device itself is skipped. Broadcast uses ff:ff:ff:ff:ff:ff (clients that
    are asleep or use PMF may ignore it).</div>
  </div>
  <div class="panel">
    <h2>Capture hunt</h2>
    <div class="hint">Uses the <b>Target AP</b> selected above. Sends a limited
    deauth burst, watches the capture table, and stops as soon as a complete
    4-way handshake or PMKID is saved (20 s maximum). PMF targets may ignore
    the deauth and time out.</div>
    <label style="margin-top:12px">Client (optional)</label>
    <select id="huntSta"><option value="">any observed client</option></select>
    <div class="row" style="margin-top:12px">
      <button class="act danger" id="bHunt">Capture hunt</button>
      <button class="act" id="bHuntStop">Stop hunt</button>
    </div>
    <div id="huntState" class="sub">idle</div>
  </div>
  <div class="panel">
    <h2>Hunting</h2>
    <div class="row">
      <div><label>Strategy</label><select id="strategy">
        <option value="-1">auto (learning)</option>
        <option value="0">linger 2.4 GHz</option>
        <option value="1">hop 2.4 GHz</option>
        <option value="2">5 GHz low</option>
        <option value="3">5 GHz high</option>
        <option value="4">hunt (wide)</option>
        <option value="5">rest</option>
      </select></div>
      <div><label>Channel</label><input id="hopCh" type="number" min="1" max="165" placeholder="e.g. 6"></div>
      <button class="act fit" id="bSetStrategy" style="align-self:end">Apply</button>
    </div>
    <label style="margin-top:12px">Automatic deauth during hunting epochs</label>
    <label class="sw"><input type="checkbox" id="autoDeauth"><span class="sl"></span></label>
    <span class="hint" style="margin-left:10px">off by default</span>
  </div>
</section>

<section id="set">
  <div class="panel">
    <h2>WiFi connection</h2>
    <div id="wifiState" class="sub">not connected</div>
    <div class="row" style="margin-top:10px">
      <div><label>Network name</label><input id="ssid" maxlength="32" placeholder="SSID"></div>
      <div><label>Password</label><input id="pass" type="password" maxlength="63" placeholder="leave empty if open"></div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="act" id="bConnect">Connect &amp; save</button>
      <button class="act" id="bConnectOnce">Connect once</button>
      <button class="act danger" id="bDisc">Disconnect</button>
    </div>
    <label style="margin-top:12px">Reconnect automatically at boot</label>
    <label class="sw"><input type="checkbox" id="autoConn"><span class="sl"></span></label>
    <div class="hint">Hopping pauses while associated to an AP. Disconnect to
    resume the full channel plan.</div>
  </div>
  <div class="panel">
    <h2>Display</h2>
    <label>Backlight: <span id="brightVal">100</span>%</label>
    <input id="bright" type="range" min="10" max="100" value="100">
  </div>
  <div class="panel">
    <h2>Maintenance</h2>
    <div class="row">
      <button class="act" id="bResetBrain">Reset brain</button>
      <button class="act danger" id="bReboot">Reboot device</button>
      <button class="act danger" id="bForget">Forget WiFi</button>
      <button class="act" id="bSdRemount">Remount SD</button>
      <button class="act" id="bSdPrune">Prune SD</button>
    </div>
    <div class="row" style="margin-top:12px">
      <input id="otaFile" type="file" accept=".bin">
      <button class="act danger" id="bOta">Upload firmware &amp; reboot</button>
      <button class="act" id="bOtaGh">Update from GitHub</button>
    </div>
    <div class="hint">Firmware update is manual and gated by the authorization
    phrase. <b>Update from GitHub</b> makes the device download the latest
    <code>dist/esp32touch.bin</code> from the public repo and reboot. Nothing is
    checked automatically.</div>
  </div>
  <div class="panel">
    <h2>System</h2>
    <pre id="sys">--</pre>
  </div>
</section>

<footer>PWNI &middot; ESP32-C5 &middot; passive-first WiFi research tool</footer>
</main>
<div id="toast" class="toast"></div>
<script>
const $ = s => document.querySelector(s);
const esc = s => (s==null?'':String(s)).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let S = {};
let toastT;
function toast(m,bad){const t=$('#toast');t.textContent=m;t.style.borderColor=bad?'#ff6b6b':'#8cf58c';
t.classList.add('on');clearTimeout(toastT);toastT=setTimeout(()=>t.classList.remove('on'),2600)}
function goUnlock(){document.querySelector('nav button[data-tab="attack"]').click();
setTimeout(()=>$('#phrase').focus(),80)}
async function api(p,opt){try{const r=await fetch(p,opt);const j=await r.json();
if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}catch(e){toast(e.message,true);throw e}}
function post(p,body){return api(p,{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify(body||{})})}
const fmtUp = s => {s=Math.floor(s);const d=Math.floor(s/86400);s%=86400;const h=Math.floor(s/3600);
s%=3600;const m=Math.floor(s/60);s%=60;return (d?d+'d ':'')+(h?h+'h ':'')+m+'m '+s+'s'}
const fmtB = b => b>1048576?(b/1048576).toFixed(1)+' MB':b>1024?(b/1024).toFixed(0)+' KB':b+' B'
function rssiBar(r){const pct=Math.max(0,Math.min(100,(r+100)*100/60));return '<span class="rssi-wrap"><span class="rssi"><i style="width:'+pct+'%"></i></span> '+r+'</span>'}

document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('section').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');$('#'+b.dataset.tab).classList.add('active');
  if(b.dataset.tab==='nets')loadNets();
  if(b.dataset.tab==='clients')loadClients();
  if(b.dataset.tab==='caps')loadCaps();
  if(b.dataset.tab==='attack'){loadNets(true).then(loadHuntClients);$('#strategy').value=String(S.action_override??-1);}
});
function renderStatus(){
  $('#dot').className='dot '+(S.connected?'on':(S.connecting?'warn':''));
  $('#hstate').textContent=S.connected?('online '+(S.ssid||'')):(S.connecting?'connecting...':'no wifi');
  $('#hip').textContent=S.connected?('http://'+S.ip):'offline';
  $('#mood').textContent=S.mood||'--';$('#pstatus').textContent=S.status||'';
  $('#level').textContent=S.level;$('#xp').textContent=S.xp;$('#bond').textContent=S.bond;
  $('#aps').textContent=S.ap_count;$('#clientStat').textContent=S.client_count;
  $('#hs').textContent=S.hs_count;$('#pmkid').textContent=S.pmkid_count;$('#saved').textContent=S.saved_count;
  $('#chan').textContent=S.channel||'-';$('#band').textContent=(S.connected?'pinned ':'')+(S.band==5?'5 GHz':'2.4 GHz');
  $('#action').textContent=S.action;$('#locked').textContent=S.locked?'channel locked (STA)':(S.paused?'paused':'hopping');
  $('#frames').textContent=S.frames;$('#eapol').textContent=S.eapol;$('#deauth').textContent=S.deauths;
  $('#drop').textContent=S.dropped;$('#up').textContent=fmtUp(S.uptime);
  $('#event').textContent=S.last_event||'listening...';
  $('#bPause').textContent=S.paused?'Resume':'Pause';
  $('#bAuthState').textContent=S.authorized?'Attacks UNLOCKED':'Attacks locked';
  $('#authBox').innerHTML=S.authorized
    ?'<span class="tag good">UNLOCKED</span> active features are available for this session.'
    :'<span class="tag bad">LOCKED</span> enter the authorization phrase to enable active attacks.';
  if($('#deauthState'))$('#deauthState').textContent=S.deauth_active?'burst active':'idle';
  if($('#huntState')){
    if(S.hunt_active){
      $('#huntState').textContent='hunt active: '+Math.round((S.hunt_elapsed_ms||0)/1000)+'s / '+
        Math.round((S.hunt_duration_ms||0)/1000)+'s'+(S.hunt_bssid?' · '+S.hunt_bssid:'');
    }else{
      const r=S.hunt_result||'idle';
      $('#huntState').textContent='idle'+(r!=='idle'?(' · last: '+r+
        (S.hunt_bssid?' · '+S.hunt_bssid:'')+(S.hunt_file?' · '+S.hunt_file:'')+
        (S.hunt_message?' · '+S.hunt_message:'')):'');
    }
    if($('#bHunt'))$('#bHunt').textContent=S.hunt_active?'Hunt running...':'Capture hunt';
  }
  $('#autoDeauth').checked=!!S.auto_deauth;
  if(S.auto_deauth!==undefined && S.auto_deauth && !S.authorized){$('#autoDeauth').checked=false}
  $('#wifiState').innerHTML = S.connected
    ?('<span class="tag good">connected</span> '+esc(S.ssid)+' &middot; '+esc(S.ip)+' &middot; ch '+S.sta_channel+' &middot; '+S.rssi+' dBm')
    :(S.connecting?'<span class="tag warn">connecting</span> '+esc(S.ssid||''):
      (S.have_creds?'<span class="tag">disconnected</span> saved: '+esc(S.ssid):'<span class="sub">no saved network</span>'));
  $('#autoConn').checked=!!S.autoconnect;
  if(S.build){$('#sys').textContent=
    'firmware   PWNI '+S.build.version+'\n'+
    'chip       ESP32-C5 @ '+S.build.cpu_mhz+' MHz\n'+
    'flash      '+S.build.flash+'\n'+
    'psram      '+S.build.psram+' ('+fmtB(S.psram_free)+' free)\n'+
    'heap       '+fmtB(S.heap_free)+' free\n'+
    'deauth     '+(S.build.deauth?'compiled in (runtime gated)':'not compiled')+'\n'+
    'sd card    '+(S.sd?'ready':'not mounted')+'  '+
      (S.sd_free?fmtB(S.sd_free)+' free / '+fmtB(S.sd_total):'')+'\n'+
    'uptime     '+fmtUp(S.uptime);}
}
async function poll(){try{S=await api('/api/status');renderStatus();fillApSelect()}catch(e){}}
function fillApSelect(){
  const cur=$('#targetAp').value;let h='<option value="">-- select an AP --</option>';
  (window.LAST_APS||[]).forEach(a=>{h+='<option value="'+a.bssid+'">'+esc(a.ssid||'<hidden>')+' &middot; '+a.bssid+' &middot; ch '+a.ch+' &middot; '+(a.clients||0)+' cli'+(a.pmf?' &middot; PMF':'')+'</option>'});
  $('#targetAp').innerHTML=h;$('#targetAp').value=cur;
}
async function loadNets(selectOnly){
  const j=await api('/api/aps');window.LAST_APS=j.aps||[];fillApSelect();
  if(selectOnly)return;
  let h='';if(!j.aps.length)h='<tr><td colspan="7" class="sub">no access points yet</td></tr>';
  j.aps.forEach(a=>{
    h+='<tr><td>'+esc(a.ssid||'<hidden>')+'</td><td class="mono">'+a.bssid+'</td><td>'+a.ch+
    '</td><td>'+rssiBar(a.rssi)+'</td><td>'+esc(a.sec)+'</td><td>'+
    (a.wps?'<span class="tag warn">WPS</span> ':'')+(a.hs?'<span class="tag good">HS</span>':'')+
    (a.pmf?'<span class="tag warn">PMF</span> ':'')+
    (a.clients?'<span class="tag">'+a.clients+' cli</span>':'')+
    '</td><td class="row" style="justify-content:flex-end"><button class="act" onclick="connectAp('+
    JSON.stringify(a.ssid).replace(/"/g,'&quot;')+')">Connect</button>'+
    '<button class="act danger" onclick="deauthAp(\''+a.bssid+'\',true)">Deauth</button></td></tr>'});
  $('#netRows').innerHTML=h;
}
async function loadClients(){
  const j=await api('/api/clients');let h='';
  if(!j.clients.length)h='<tr><td colspan="5" class="sub">no clients seen</td></tr>';
  j.clients.forEach(c=>{h+='<tr><td class="mono">'+c.mac+(c.self?' <span class="tag">this device</span>':'')+'</td><td class="mono">'+c.bssid+
    '</td><td>'+rssiBar(c.rssi)+'</td><td>'+c.frames+'</td><td class="row" style="justify-content:flex-end">'+
    (c.self?'<span class="sub">protected</span>':
      (c.has_ap?'<button class="act danger" onclick="deauthClient(\''+c.bssid+'\',\''+c.mac+'\')">Deauth</button>':
       '<span class="sub">AP unknown</span>'))+'</td></tr>'});
  $('#cliRows').innerHTML=h;
}
async function loadHuntClients(){
  const b=$('#targetAp').value;
  const cur=$('#huntSta').value;
  let h='<option value="">any observed client</option>';
  if(b){
    try{
      const j=await api('/api/clients');
      (j.clients||[]).filter(c=>c.bssid===b&&!c.self).forEach(c=>{
        h+='<option value="'+c.mac+'">'+c.mac+' &middot; '+c.rssi+' dBm</option>';
      });
    }catch(e){}
  }
  $('#huntSta').innerHTML=h;
  if([...$('#huntSta').options].some(o=>o.value===cur))$('#huntSta').value=cur;
}
async function deletePcap(name){if(!confirm('Delete '+name+'?'))return;try{await post('/api/pcap_delete',{name:name});toast('deleted');loadCaps();}catch(e){}}
async function loadCaps(){
  const j=await api('/api/hs');let h='';
  if(!j.hs.length)h='<tr><td colspan="6" class="sub">no handshakes captured yet</td></tr>';
  j.hs.forEach(x=>{
    const msgs=[];for(let i=0;i<4;i++)if(x.mask&(1<<i))msgs.push('M'+(i+1));
    const type=(x.pmkid?'<span class="tag good">PMKID</span> ':'')+
      (x.complete?'<span class="tag good">4-way</span>':
        (msgs.length?'<span class="tag">'+msgs.join('+')+'</span>':''));
    h+='<tr><td>'+esc(x.ssid||'<hidden>')+'</td><td class="mono">'+x.bssid+'<br>'+
    x.sta+'</td><td>'+type+'</td><td>'+x.frames+'</td><td class="mono">'+esc(x.file||'-')+'</td><td>'+
    (x.file?'<a class="act" href="/api/pcap?name='+encodeURIComponent(x.file)+'">Download</a>':'')+
    '</td></tr>'});
  $('#capRows').innerHTML=h;
  let f='';
  if(!j.files||!j.files.length)f='<tr><td colspan="3" class="sub">no saved PCAPs on SD</td></tr>';
  (j.files||[]).forEach(x=>{f+='<tr><td class="mono">'+esc(x.name)+'</td><td>'+fmtB(x.size)+
    '</td><td><a class="act" href="/api/pcap?name='+encodeURIComponent(x.name)+'">Download</a> <button class="act danger" onclick="deletePcap(\''+x.name.replace(/'/g,"\\'")+'\')">Delete</button></td></tr>'});
  $('#fileRows').innerHTML=f;
}
async function connectAp(ssid){
  const pass=prompt('Password for "'+(ssid||'hidden')+'" (leave empty if open):');
  if(pass===null)return;
  try{const j=await post('/api/connect',{ssid:ssid,password:pass,save:true});
  toast(j.connected?'connected':'connecting...');setTimeout(poll,800)}catch(e){}
}
async function deauthAp(bssid,all){
  if(!S.authorized){toast('unlock attacks first',true);goUnlock();return}
  const dur=+($('#deauthDur')?.value||8000);
  const msg=all
    ?('Send deauth frames to all observed clients for '+(dur/1000)+' seconds?\nOnly do this on networks you own.')
    :('Send broadcast deauth frames for '+(dur/1000)+' seconds?\nBroadcasts may be ignored and can disconnect this device if it is your current AP.\nOnly do this on networks you own.');
  if(!confirm(msg))return;
  try{const j=await post('/api/deauth',{bssid:bssid,all:!!all,duration_ms:dur});
    if(j.started){
      let m='deauth '+(j.duration_ms/1000)+'s'+(j.targets?(' to '+j.targets+' client'+(j.targets===1?'':'s')):' (broadcast)');
      if(j.warning)m+=' — '+j.warning;
      toast(m);
    }else toast(j.tx_error||'no targets',true);
  }catch(e){if(String(e.message).includes('unlock'))goUnlock()}
}
async function deauthClient(bssid,mac){
  if(!S.authorized){toast('unlock attacks first',true);goUnlock();return}
  const dur=+($('#deauthDur')?.value||8000);
  if(!confirm('Deauth '+mac+' for '+(dur/1000)+' seconds?'))return;
  try{const j=await post('/api/deauth',{bssid:bssid,sta:mac,duration_ms:dur});
    if(j.started)toast('deauth '+(j.duration_ms/1000)+'s: '+mac);
    else toast(j.tx_error||'no targets',true);
  }catch(e){if(String(e.message).includes('unlock'))goUnlock()}
}
$('#bPause').onclick=async()=>{await post('/api/pause',{paused:!S.paused});poll()};
$('#bScan').onclick=$('#bScan2').onclick=async()=>{toast('scanning...');
  try{const j=await post('/api/scan',{});toast('found '+j.found+' APs');loadNets()}catch(e){}};
$('#bAuthState').onclick=async()=>{goUnlock()};
$('#bAuth').onclick=async()=>{
  const p=$('#phrase').value.trim();if(!p)return toast('enter the phrase',true);
  try{
    const r=await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({phrase:p})});
    const j=await r.json();
    toast(j.authorized?'attacks unlocked':'wrong phrase',!j.authorized);
    if(j.authorized)$('#phrase').value='';
    poll();
  }catch(e){toast('device unreachable',true)}
};
$('#phrase').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();$('#bAuth').click()}});
$('#ssid').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();doConnect(true)}});
$('#pass').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();doConnect(true)}});
$('#bRevoke').onclick=async()=>{await post('/api/auth',{off:true});toast('attacks locked');poll()};
$('#bDeauthAll').onclick=()=>{const b=$('#targetAp').value;if(!b)return toast('pick an AP',true);deauthAp(b,true)};
$('#bDeauthBcast').onclick=()=>{const b=$('#targetAp').value;if(!b)return toast('pick an AP',true);deauthAp(b,false)};
$('#bDeauthStop').onclick=async()=>{await post('/api/deauth',{stop:true});toast('deauth stopped');poll()};
$('#targetAp').onchange=loadHuntClients;
$('#bHunt').onclick=async()=>{
  if(!S.authorized){toast('unlock attacks first',true);goUnlock();return}
  const b=$('#targetAp').value;if(!b)return toast('pick an AP',true);
  const sta=$('#huntSta').value||null;
  if(!confirm('Start a capture hunt against '+b+(sta?(' / '+sta):'')+'?\n'+
    'This sends a limited deauth burst for up to 20 seconds and stops when a complete\n'+
    '4-way handshake or PMKID is saved. Only do this on networks you own.'))return;
  const body={bssid:b,duration_ms:20000};if(sta)body.sta=sta;
  try{const j=await post('/api/hunt',body);
    if(j.started){
      toast('hunt '+(j.duration_ms/1000)+'s: '+b+(sta?(' / '+sta):''),false);
      if(j.warning)setTimeout(()=>toast(j.warning,true),2700);
      poll();
    }else toast(j.error||'hunt not started',true);
  }catch(e){}
};
$('#bHuntStop').onclick=async()=>{await post('/api/hunt',{stop:true});toast('hunt stopped');poll()};
$('#bHop').onclick=()=>{const b=$('#targetAp').value;if(!b)return toast('pick an AP',true);
  post('/api/hop_ap',{bssid:b}).then(j=>toast('channel '+j.channel)).catch(()=>{})};
$('#bSetStrategy').onclick=async()=>{await post('/api/strategy',{action:+$('#strategy').value});toast('strategy set');poll()};
$('#hopCh').onchange=async()=>{const ch=+$('#hopCh').value;if(!ch)return;
  try{const j=await post('/api/hop',{channel:ch});toast('channel '+j.channel)}catch(e){}};
$('#autoDeauth').onchange=async e=>{try{await post('/api/attacks',{auto:e.target.checked});toast('auto-deauth '+(e.target.checked?'on':'off'))}catch(x){e.target.checked=!e.target.checked}};
$('#bConnect').onclick=()=>doConnect(true);
$('#bConnectOnce').onclick=()=>doConnect(false);
async function doConnect(save){const ssid=$('#ssid').value.trim(),password=$('#pass').value;
  if(!ssid)return toast('enter an SSID',true);
  try{const j=await post('/api/connect',{ssid:ssid,password:password,save:save});
  toast(j.connected?'connected':'connecting...');$('#pass').value='';setTimeout(poll,900)}catch(e){}}
$('#bDisc').onclick=async()=>{await post('/api/disconnect',{forget:false});toast('disconnected');poll()};
$('#bForget').onclick=async()=>{if(!confirm('Forget saved WiFi credentials?'))return;
  await post('/api/disconnect',{forget:true});toast('credentials erased');poll()};
$('#autoConn').onchange=async e=>{await post('/api/autoconnect',{on:e.target.checked});poll()};
$('#bright').oninput=e=>{$('#brightVal').textContent=e.target.value};
$('#bright').onchange=async e=>{await post('/api/brightness',{percent:+e.target.value});toast('brightness '+e.target.value+'%')};
$('#bResetBrain').onclick=async()=>{if(!confirm('Reset the learned strategy?'))return;
  await post('/api/reset_brain',{});toast('brain reset');poll()};
$('#bReboot').onclick=async()=>{if(!confirm('Reboot the device?'))return;
  toast('rebooting...');try{await post('/api/reboot',{})}catch(e){}};
$('#bOtaGh').onclick=async()=>{
  if(!confirm('Download the latest firmware from GitHub and reboot?'))return;
  toast('contacting GitHub...');
  try{const j=await post('/api/ota_github',{});toast('OTA started; device will reboot');}
  catch(e){}};
$('#bOta').onclick=async()=>{const f=$('#otaFile').files[0];
  if(!f)return toast('choose a firmware .bin',true);
  if(!confirm('Flash '+f.name+' and reboot?'))return;
  toast('uploading firmware...');
  try{const r=await fetch('/api/ota',{method:'POST',body:f});
    const j=await r.json();
    if(!r.ok)throw new Error(j.error||('HTTP '+r.status));
    toast('firmware written; rebooting...');
  }catch(e){toast(e.message,true)}};
$('#bSdPrune').onclick=async()=>{
  const n=prompt('Keep how many newest PCAPs?','50');if(n===null)return;
  const k=parseInt(n,10);if(!(k>=0))return toast('invalid count',true);
  toast('pruning...');try{const j=await post('/api/sd',{prune:k});toast('pruned '+j.pruned+' file(s)');poll();}catch(e){}};
$('#bSdRemount').onclick=async()=>{toast('remounting SD...');
  try{const j=await post('/api/sd',{remount:true});
    toast(j.sd?('SD ready, '+fmtB(j.free)+' free'):'SD remount failed',!j.sd);poll();
  }catch(e){}};
setInterval(poll,2000);poll();
setInterval(()=>{if(document.getElementById('nets').classList.contains('active'))loadNets()},7000);
setInterval(()=>{if(document.getElementById('caps').classList.contains('active'))loadCaps()},5000);
setInterval(()=>{if(document.getElementById('clients').classList.contains('active'))loadClients()},5000);
</script>
</body>
</html>
)PWNWEB";
