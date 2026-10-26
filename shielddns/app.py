import os, time, base64, asyncio
from collections import defaultdict, deque
from pathlib import Path

import dns.message
import dns.rcode
import dns.rdatatype
import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import Response, HTMLResponse, JSONResponse

APP_NAME = "ShieldDNS"
UPSTREAM_DOH = os.getenv("UPSTREAM_DOH", "https://cloudflare-dns.com/dns-query")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
BLOCKLIST_FILE = Path(os.getenv("BLOCKLIST_FILE", "blocklist.txt"))
MAX_BODY = 4096
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
WINDOW = 60

app = FastAPI(title=APP_NAME, docs_url=None, redoc_url=None)
blocked_domains = set()
allow_domains = set()
ip_windows = defaultdict(deque)
stats = {"total": 0, "blocked": 0, "errors": 0, "started_at": time.time()}
stats_lock = asyncio.Lock()
client = httpx.AsyncClient(timeout=5.0, follow_redirects=False,
                            headers={"accept": "application/dns-message"})

def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or value.startswith("#") or "/" in value or " " in value:
        return ""
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(value) > 253:
        return ""
    labels = value.split(".")
    if any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-") for x in labels):
        return ""
    return value

def load_blocklist():
    blocked_domains.clear()
    if BLOCKLIST_FILE.exists():
        for line in BLOCKLIST_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            # Accept one domain per line; comments and common hosts-file lines are supported.
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            parts = raw.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                raw = parts[1]
            else:
                raw = parts[0]
            domain = normalize_domain(raw)
            if domain:
                blocked_domains.add(domain)

def is_blocked(name: str) -> bool:
    domain = normalize_domain(name)
    if not domain:
        return False
    if any(domain == a or domain.endswith("." + a) for a in allow_domains):
        return False
    return any(domain == b or domain.endswith("." + b) for b in blocked_domains)

def check_rate_limit(ip: str):
    now = time.monotonic()
    q = ip_windows[ip]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    q.append(now)

def admin_required(token: str | None):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Admin API disabled: set ADMIN_TOKEN")
    if not token or token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")

def blocked_response(query):
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return response.to_wire()

@app.on_event("startup")
async def startup():
    load_blocklist()

@app.on_event("shutdown")
async def shutdown():
    await client.aclose()

async def process_wire(wire: bytes, ip: str) -> bytes:
    if len(wire) > MAX_BODY:
        raise HTTPException(status_code=413, detail="DNS message too large")
    try:
        query = dns.message.from_wire(wire, ignore_trailing=False)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid DNS message")
    if not query.question:
        raise HTTPException(status_code=400, detail="DNS question missing")
    qname = query.question[0].name.to_text()
    async with stats_lock:
        stats["total"] += 1
    if is_blocked(qname):
        async with stats_lock:
            stats["blocked"] += 1
        return blocked_response(query)
    try:
        upstream = await client.post(
            UPSTREAM_DOH,
            content=wire,
            headers={"content-type": "application/dns-message",
                     "accept": "application/dns-message"}
        )
        if upstream.status_code != 200 or upstream.headers.get("content-type", "").split(";")[0].strip() != "application/dns-message":
            raise RuntimeError("Upstream returned unexpected response")
        dns.message.from_wire(upstream.content)  # Validate response before returning it.
        return upstream.content
    except Exception:
        async with stats_lock:
            stats["errors"] += 1
        # Return SERVFAIL, not a fabricated successful answer.
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()

@app.get("/health")
async def health():
    return {"status": "ok", "service": APP_NAME}

@app.post("/dns-query")
async def doh_post(request: Request):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/dns-message":
        raise HTTPException(status_code=415, detail="Use application/dns-message")
    wire = await request.body()
    result = await process_wire(wire, ip)
    return Response(result, media_type="application/dns-message",
                    headers={"Cache-Control": "no-store"})

@app.get("/dns-query")
async def doh_get(request: Request):
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)
    encoded = request.query_params.get("dns", "")
    try:
        wire = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid dns parameter")
    result = await process_wire(wire, ip)
    return Response(result, media_type="application/dns-message",
                    headers={"Cache-Control": "no-store"})

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShieldDNS</title><style>
body{font:16px system-ui;max-width:900px;margin:40px auto;padding:0 18px;background:#0b1220;color:#e8eefc}
h1{margin-bottom:4px}.muted{color:#a9b7d0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:#151f33;border:1px solid #283650;border-radius:14px;padding:18px}.num{font-size:30px;font-weight:700}
input,button{font:inherit;padding:10px;border-radius:8px;border:1px solid #354563;background:#111b2e;color:#e8eefc}
button{cursor:pointer;background:#2d67d8;border:0}pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style></head><body>
<h1>🛡️ ShieldDNS</h1><p class="muted">Custom DNS filtering service · prototype dashboard</p>
<div class="cards"><div class="card"><div class="muted">Total queries</div><div class="num" id="total">—</div></div>
<div class="card"><div class="muted">Blocked queries</div><div class="num" id="blocked">—</div></div>
<div class="card"><div class="muted">Upstream errors</div><div class="num" id="errors">—</div></div>
<div class="card"><div class="muted">Blocklist domains</div><div class="num" id="domains">—</div></div></div>
<h2>Admin tools</h2><p class="muted">Enter the ADMIN_TOKEN configured on the server. Keep it secret.</p>
<p><input id="token" type="password" placeholder="Admin token" style="width:min(420px,90%)"> <button onclick="refresh()">Refresh stats</button></p>
<p><input id="domain" placeholder="example-ad-domain.com"> <button onclick="addDomain()">Block domain</button></p>
<pre id="message" class="muted"></pre>
<h2>Connect a client</h2><p>Once deployed behind HTTPS, configure your client to use <code>https://YOUR_DOMAIN/dns-query</code> where the client supports RFC 8484 DoH. Android Private DNS requires DNS-over-TLS, which this starter does not yet implement.</p>
<p class="muted">Prototype note: metrics are in-memory and reset on restart. Do not advertise this as a production privacy service until persistence, monitoring, robust rate limiting, and abuse controls are added.</p>
<script>
async function refresh(){let t=document.getElementById('token').value;try{let r=await fetch('/admin/stats',{headers:{'X-Admin-Token':t}});let d=await r.json();if(!r.ok)throw Error(d.detail||r.status);for(let k of ['total','blocked','errors'])document.getElementById(k).textContent=d[k];document.getElementById('domains').textContent=d.blocklist_domains;document.getElementById('message').textContent='Stats updated';}catch(e){document.getElementById('message').textContent='Error: '+e.message}}
async function addDomain(){let t=document.getElementById('token').value,domain=document.getElementById('domain').value;try{let r=await fetch('/admin/blocklist',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':t},body:JSON.stringify({domain})});let d=await r.json();if(!r.ok)throw Error(d.detail||r.status);document.getElementById('message').textContent=JSON.stringify(d);await refresh()}catch(e){document.getElementById('message').textContent='Error: '+e.message}}
</script></body></html>""")

@app.get("/admin/stats")
async def admin_stats(x_admin_token: str | None = Header(default=None)):
    admin_required(x_admin_token)
    async with stats_lock:
        return {**stats, "blocklist_domains": len(blocked_domains),
                "uptime_seconds": int(time.time() - stats["started_at"])}

@app.post("/admin/blocklist")
async def add_blocklist(payload: dict, x_admin_token: str | None = Header(default=None)):
    admin_required(x_admin_token)
    domain = normalize_domain(str(payload.get("domain", "")))
    if not domain:
        raise HTTPException(status_code=400, detail="Provide a valid domain")
    blocked_domains.add(domain)
    # Persist as one-domain-per-line, sorted for easy review.
    BLOCKLIST_FILE.write_text("# ShieldDNS custom blocklist\\n" + "\\n".join(sorted(blocked_domains)) + "\\n", encoding="utf-8")
    return {"ok": True, "domain": domain, "blocklist_domains": len(blocked_domains)}

@app.delete("/admin/blocklist/{domain}")
async def remove_blocklist(domain: str, x_admin_token: str | None = Header(default=None)):
    admin_required(x_admin_token)
    domain = normalize_domain(domain)
    if not domain or domain not in blocked_domains:
        raise HTTPException(status_code=404, detail="Domain not found")
    blocked_domains.remove(domain)
    BLOCKLIST_FILE.write_text("# ShieldDNS custom blocklist\\n" + "\\n".join(sorted(blocked_domains)) + "\\n", encoding="utf-8")
    return {"ok": True, "domain": domain}
