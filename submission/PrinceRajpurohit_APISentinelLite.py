"""API Sentinel Lite v0.2 - single-file backend (demo target + scanner + SQLite storage + reports + CLI).
For AUTHORIZED testing on localhost only. IBM SkillsBuild Cyber Security 2026 project by Prince Rajpurohit.
Usage:  python Prince_APISentinelLite.py selftest | demo | api | scan URL [--protected /p1 /p2]
"""
import sys, argparse, threading, time, json
# ===== DEMO TARGET (deliberately vulnerable: /api/*, hardened: /safe/*) =====
import traceback
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
demo_app = FastAPI(title="Vulnerable Demo API")
HARD = {"Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=63072000", "Referrer-Policy": "no-referrer"}

@demo_app.middleware("http")
async def mw(req: Request, call):
    r = await call(req)
    if req.url.path.startswith("/safe"):
        r.headers.update(HARD)
    elif o := req.headers.get("origin"):  # vulnerable: reflects any origin with credentials
        r.headers["Access-Control-Allow-Origin"] = o
        r.headers["Access-Control-Allow-Credentials"] = "true"
    return r

@demo_app.get("/api/public")
def pub(): return {"ok": True}
@demo_app.get("/api/admin/users")  # designated protected endpoint, but no auth check (vulnerable)
def users(): return [{"id": 1, "name": "demo"}]
@demo_app.get("/api/items/{i}")
def item(i: str):
    try: return {"id": int(i)}
    except Exception: return JSONResponse({"error": "failed", "trace": traceback.format_exc()}, 500)

@demo_app.get("/safe/public")
def spub(): return {"ok": True}
@demo_app.get("/safe/admin/users")
def susers(authorization: str | None = Header(None)):
    return JSONResponse({"error": "unauthorized"}, 401) if not authorization else [{"id": 1}]
@demo_app.get("/safe/items/{i}")
def sitem(i: str):
    return {"id": int(i)} if i.isdigit() else JSONResponse({"error": "bad request"}, 400)

import asyncio
from fastapi.responses import RedirectResponse, Response
@demo_app.get("/api/redirect")
def redir(): return RedirectResponse("http://example.com/login", 302)
@demo_app.get("/api/slow")
async def slow():
    await asyncio.sleep(2); return {"ok": True}
@demo_app.get("/api/big")
def big(): return Response("x" * 200000, media_type="text/plain")

# ===== SCANNER =====
import httpx, ipaddress, re, socket, time, logging
from types import SimpleNamespace
from urllib.parse import urlparse
log = logging.getLogger("sentinel")
LOCAL = {"localhost", "127.0.0.1", "::1"}
MAXB, TIMEOUT, TOTAL = 65536, 5.0, 20.0
CHECKS = {"missing-header": "Security headers", "permissive-cors": "CORS policy", "https-config": "HTTPS / HSTS",
          "verbose-error": "Error disclosure", "missing-auth": "Authentication on protected paths"}
HDR = [("Content-Security-Policy", "low", "Limits where scripts/resources load from, reducing XSS impact."),
       ("X-Content-Type-Options", "low", "Stops browsers MIME-sniffing responses into executable types."),
       ("X-Frame-Options", "low", "Prevents the response being framed (clickjacking)."),
       ("Referrer-Policy", "info", "Limits URL leakage to other sites.")]

class ScanError(Exception): pass

def validate(url):
    if not isinstance(url, str) or len(url) > 200 or re.search(r"[\s\\]", url.strip()): raise ValueError("Malformed URL")
    try: u = urlparse(url.strip()); port = u.port
    except ValueError: raise ValueError("Malformed URL or invalid port")
    if u.scheme not in ("http", "https") or not u.hostname: raise ValueError("URL must be http(s) with a host")
    if u.username or u.password: raise ValueError("Credentials in URL are not allowed")
    if u.hostname not in LOCAL: raise ValueError("MVP only permits localhost targets")
    if port is not None and not 1 <= port <= 65535: raise ValueError("Invalid port")
    if u.path not in ("", "/") or u.query or u.fragment or u.params: raise ValueError("Give the origin only (e.g. http://127.0.0.1:8001); set paths separately")
    return f"{u.scheme}://{u.netloc}"

def _path(p):
    if not isinstance(p, str) or len(p) > 200 or ".." in p or p.startswith("//") or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", p):
        raise ValueError(f"Invalid path: {str(p)[:40]!r}")
    return p

def _resolve(host, port):  # DNS-rebinding guard: every resolved address must be loopback
    try: ips = [i[4][0].split("%")[0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    except OSError: raise ValueError("Hostname could not be resolved")
    if not ips or not all(ipaddress.ip_address(i).is_loopback for i in ips): raise ValueError("Target resolves to a non-loopback address")
    return ips[0]

class Ctx:
    def __init__(s, target, client, deadline):
        u = urlparse(target); s.host, s.https, s.client, s.deadline = u.netloc, u.scheme == "https", client, deadline
        ip = _resolve(u.hostname, u.port or (443 if s.https else 80))
        s.base = target if s.https else f"http://{'[' + ip + ']' if ':' in ip else ip}:{u.port or 80}"  # http: connect to the validated IP

def fetch(ctx, path, extra=None):
    if time.monotonic() > ctx.deadline: raise ScanError("Scan time budget exceeded")
    h = {"Host": ctx.host, "User-Agent": "APISentinelLite/0.2"}; h.update(extra or {})
    with ctx.client.stream("GET", ctx.base + _path(path), headers=h) as r:
        body, trunc = b"", False
        for ch in r.iter_bytes():
            body += ch
            if len(body) > MAXB: trunc = True; break
        return r.status_code, r.headers, body[:MAXB].decode("utf-8", "replace"), trunc

def F(rule, title, sev, conf, ep, ev, impact, fix, kind="hardening gap"):
    return dict(rule=rule, title=title, severity=sev, confidence=conf, endpoint=ep, evidence=ev, impact=impact,
                remediation=fix, kind=kind, verification="needs_review")

def c_headers(ctx, p):
    st, h, _, _ = fetch(ctx, p.base); miss = [x for x in HDR if x[0].lower() not in h]
    fs = [F("missing-header", f"Missing {n}", s, "high", p.base, f"HTTP {st} response had no {n} header", w,
            f"Send {n} on responses. A missing header is a hardening gap, not a confirmed exploit.") for n, s, w in miss]
    return ("warning" if miss else "pass"), f"HTTP {st}; {len(miss)} of {len(HDR)} headers missing", fs

def c_cors(ctx, p):
    evil = "https://evil.example"; st, h, _, _ = fetch(ctx, p.base, {"Origin": evil})
    a, cred = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower() == "true"
    if a == evil:
        return "fail", f"Origin echoed (credentials={cred})", [F("permissive-cors", "CORS reflects arbitrary Origin", "high" if cred else "medium",
            "high", p.base, f"Origin {evil} echoed in Access-Control-Allow-Origin; allow-credentials={cred}",
            "Any website can read responses" + (" using the visitor's credentials" if cred else " that do not need credentials"),
            "Allow-list trusted origins; never reflect Origin, especially with credentials.", "potential vulnerability")]
    if a == "*":
        return "warning", "Wildcard CORS", [F("permissive-cors", "Wildcard CORS (Access-Control-Allow-Origin: *)", "info", "medium", p.base,
            "ACAO is *", "Fine for public data; risky if responses are private (credentials are not sent with *).", "Confirm this API serves only public data.")]
    return "pass", f"HTTP {st}; no permissive CORS observed", []

def c_https(ctx, p):
    if not ctx.https: return "not_tested", "Plain HTTP on localhost: TLS/HSTS not assessed (expected for local demos)", []
    st, h, _, _ = fetch(ctx, p.base)
    if "strict-transport-security" in h: return "pass", "HSTS present", []
    return "warning", "HSTS missing", [F("https-config", "Missing HSTS on HTTPS endpoint", "low", "high", p.base, "HTTPS response lacks Strict-Transport-Security",
            "Browsers may be downgraded to HTTP on first visit.", "Add Strict-Transport-Security.")]

def c_error(ctx, p):
    st, _, body, _ = fetch(ctx, p.error)
    if st < 400: return "not_tested", f"Probe returned HTTP {st}; no error triggered, disclosure could not be assessed", []
    marks = [m for m in ("Traceback (most recent call last)", 'File "', "at java.", "Exception in") if m in body]
    if marks: return "fail", "Stack trace markers in error response", [F("verbose-error", "Verbose error disclosure", "medium", "high", p.error,
        f"HTTP {st}; marker {marks[0]!r} found (body not stored)", "Reveals internals and file paths that help attackers.",
        "Return generic errors; log details server-side.", "potential vulnerability")]
    return "pass", f"HTTP {st}; no stack-trace markers", []

def c_auth(ctx, p):
    if not p.protected: return "not_tested", "No protected paths configured", []
    fs, notes, bad = [], [], False
    for path in p.protected:
        st, h, body, _ = fetch(ctx, path)
        if 200 <= st < 300:
            data = "json" in h.get("content-type", "") and len(body.strip()) > 2; bad = True
            fs.append(F("missing-auth", "Protected path answered without credentials", "high" if data else "medium", "medium" if data else "low", path,
                f"Unauthenticated GET returned HTTP {st}" + (" with JSON data" if data else ""),
                "Possible unauthorized access. Only a potential issue: the path may intentionally be public.",
                "Confirm the path should be protected, then enforce authentication/authorization.", "potential vulnerability"))
        elif st in (401, 403): notes.append(f"{path}: {st} (auth enforced)")
        elif 300 <= st < 400: notes.append(f"{path}: redirect {st} (not followed)"); bad = bad or None
        else: notes.append(f"{path}: HTTP {st} (inconclusive)"); bad = bad or None
    st = "fail" if bad is True else ("warning" if bad is None else "pass")
    return st, "; ".join(notes) or "Unauthenticated access observed", fs

CHECK_FUNCS = {"missing-header": c_headers, "permissive-cors": c_cors, "https-config": c_https, "verbose-error": c_error, "missing-auth": c_auth}

def run_scan(target, base_path="/api/public", protected=(), error_path="/api/items/abc", total=None):
    target = validate(target); p = SimpleNamespace(base=_path(base_path), error=_path(error_path), protected=[_path(x) for x in list(protected)[:20]])
    t0 = time.monotonic(); checks, findings = [], []
    with httpx.Client(timeout=httpx.Timeout(TIMEOUT), follow_redirects=False, limits=httpx.Limits(max_connections=1)) as c:
        ctx = Ctx(target, c, t0 + (TOTAL if total is None else total))
        for cid, fn in CHECK_FUNCS.items():
            try: st, detail, fs = fn(ctx, p)
            except ScanError as e: st, detail, fs = "not_tested", str(e), []
            except httpx.TimeoutException: st, detail, fs = "not_tested", "Request timed out", []
            except httpx.HTTPError as e: st, detail, fs = "not_tested", f"Connection problem ({type(e).__name__})", []
            except Exception: log.exception("check %s crashed", cid); st, detail, fs = "not_tested", "Unexpected error in this check", []
            for f in fs: f["check"] = cid; findings.append(f)
            checks.append(dict(id=cid, name=CHECKS[cid], status=st, detail=detail))
    return dict(checks=checks, findings=findings, duration=round(time.monotonic() - t0, 2))

def scan(target, base_path="/api/public", protected=(), error_path="/api/items/abc"):
    return run_scan(target, base_path, protected, error_path)["findings"]

# ===== STORAGE + REST API + REPORTS =====
import sqlite3, json, uuid, html, re, os, threading, logging, datetime as dt
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
log = logging.getLogger("sentinel")
VER, ID, LOCK = "0.2.0", re.compile(r"^[0-9a-f]{8}$"), threading.Lock()
NOTICE = "Automated results cover only the implemented checks and require human verification. This is not a penetration test."
def dbpath(): return os.environ.get("SENTINEL_DB", "sentinel.db")
@contextmanager
def conn():
    c = sqlite3.connect(dbpath(), timeout=10); c.row_factory = sqlite3.Row
    try:
        c.executescript("create table if not exists scans(id text primary key,target text,started text,status text,error text);"
                        "create table if not exists findings(id text primary key,scan_id text,data text);")
        have = {r[1] for r in c.execute("pragma table_info(scans)")}
        for col in ("checks", "duration"):
            if col not in have: c.execute(f"alter table scans add column {col} text")
        yield c; c.commit()
    except Exception: c.rollback(); raise
    finally: c.close()
class Req(BaseModel):
    target: str; authorized: bool = False; protected: list[str] = []
    error_path: str = "/api/items/abc"; base_path: str = "/api/public"
app = FastAPI(title="API Sentinel Lite", version=VER)
@app.exception_handler(Exception)
async def boom(_, e): log.exception("unhandled"); return JSONResponse({"detail": "Internal error; see server log"}, 500)

@app.post("/api/scans")
def create(r: Req):
    if not r.authorized: raise HTTPException(400, "You must confirm you are authorized to test this target")
    if not LOCK.acquire(blocking=False): raise HTTPException(429, "Another scan is running; try again shortly")
    try:
        try: res = run_scan(r.target, r.base_path, r.protected, r.error_path)
        except ValueError as e: raise HTTPException(400, str(e))
        ran = any(c["status"] != "not_tested" for c in res["checks"])
        st, err = ("completed", "") if ran else ("failed", "No check could run: target unreachable or timed out")
        sid = uuid.uuid4().hex[:8]
        with conn() as c:  # one transaction: scan + findings are saved together or not at all
            c.execute("insert into scans values(?,?,?,?,?,?,?)", (sid, validate(r.target), dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), st, err, json.dumps(res["checks"]), str(res["duration"])))
            for f in res["findings"]: c.execute("insert into findings values(?,?,?)", (uuid.uuid4().hex[:8], sid, json.dumps(f)))
        return {"id": sid, "status": st, "error": err, "findings": len(res["findings"])}
    except HTTPException: raise
    except Exception: log.exception("scan failed"); raise HTTPException(500, "Scan could not be saved; see server log")
    finally: LOCK.release()

def _get(sid):
    if not ID.fullmatch(sid): raise HTTPException(404, "Scan not found")
    with conn() as c:
        s = c.execute("select * from scans where id=?", (sid,)).fetchone()
        if not s: raise HTTPException(404, "Scan not found")
        fs = [dict(json.loads(r["data"]), id=r["id"]) for r in c.execute("select * from findings where scan_id=?", (sid,))]
    s = dict(s); s["checks"] = json.loads(s.get("checks") or "[]"); s["duration_s"] = s.pop("duration", None)
    return s, fs
@app.get("/api/scans")
def scans():
    with conn() as c:
        return [dict(s, findings=c.execute("select count(*) from findings where scan_id=?", (s["id"],)).fetchone()[0], checks=json.loads(s["checks"] or "[]"))
                for s in c.execute("select * from scans order by started desc")]
@app.get("/api/findings")
def findings():
    with conn() as c:
        return [dict(json.loads(r["data"]), id=r["id"], scan_id=r["scan_id"], target=r["target"]) for r in
                c.execute("select f.id,f.data,f.scan_id,s.target from findings f join scans s on s.id=f.scan_id order by s.started desc")]
@app.get("/api/scans/{sid}/report.json")
def rj(sid: str, download: int = 0):
    s, fs = _get(sid); body = {"generator": f"API Sentinel Lite {VER}", "notice": NOTICE, "scan": {k: s[k] for k in ("id", "target", "started", "status", "error", "duration_s")}, "checks": s["checks"], "findings": fs}
    return JSONResponse(body, headers={"Content-Disposition": f'attachment; filename="report-{sid}.json"'} if download else {})
@app.get("/api/scans/{sid}/report.html", response_class=HTMLResponse)
def rh(sid: str, download: int = 0):
    s, fs = _get(sid); e = lambda v: html.escape(str(v))
    ch = "".join(f"<tr><td>{e(c['name'])}</td><td>{e(c['status'])}</td><td>{e(c['detail'])}</td></tr>" for c in s["checks"])
    rows = "".join(f"<div class=f><h3><span class=s>{e(f['severity'].upper())}</span> {e(f['title'])}</h3><p><b>Type:</b> {e(f.get('kind', ''))} · <b>Endpoint:</b> <code>{e(f['endpoint'])}</code> · <b>Confidence:</b> {e(f['confidence'])} · <b>Status:</b> {e(f['verification'])}</p><p><b>Evidence:</b> <code>{e(f['evidence'])}</code></p><p><b>Why it matters:</b> {e(f['impact'])}</p><p><b>Fix:</b> {e(f['remediation'])}</p></div>" for f in fs) or "<p>No findings.</p>"
    page = (f"<!doctype html><meta charset=utf-8><title>Report {e(sid)}</title><style>body{{background:#08090D;color:#F2F4F8;font:15px system-ui;max-width:860px;margin:2rem auto;padding:0 1rem}}code{{font-family:monospace;color:#168BFF}}.f{{background:#11131B;border:1px solid #1E2433;border-radius:8px;padding:1rem;margin:1rem 0}}.s{{color:#FF2DAA}}td,th{{border-bottom:1px solid #1E2433;padding:6px;text-align:left}}</style>"
            f"<h1>API Sentinel Lite report</h1><p>Target <code>{e(s['target'])}</code> · {e(s['started'])} · {e(s['status'])} · {e(s['duration_s'])}s</p><p><i>{e(NOTICE)}</i></p><h2>Checks performed</h2><table><tr><th>Check<th>Status<th>Detail</tr>{ch}</table><h2>Findings</h2>{rows}")
    return HTMLResponse(page, headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'", **({"Content-Disposition": f'attachment; filename="report-{sid}.html"'} if download else {})})
@app.get("/api/settings")
def settings():
    return {"version": VER, "allowed_hosts": sorted(LOCAL), "timeout_s": TIMEOUT, "total_scan_budget_s": TOTAL, "max_response_bytes": MAXB,
            "checks": CHECKS, "storage": "SQLite: " + os.path.basename(dbpath()), "notice": NOTICE}

# ===== CLI + SELF-TEST =====
def selftest():
    import uvicorn
    s = uvicorn.Server(uvicorn.Config(demo_app, port=8765, log_level="error")); threading.Thread(target=s.run, daemon=True).start(); time.sleep(1.5)
    b = "http://127.0.0.1:8765"; st = lambda r: {c["id"]: c["status"] for c in r["checks"]}
    v = run_scan(b, "/api/public", ["/api/admin/users"], "/api/items/abc"); h = run_scan(b, "/safe/public", ["/safe/admin/users"], "/safe/items/abc")
    ok1 = [st(v)[k] for k in ("missing-header", "permissive-cors", "verbose-error", "missing-auth")] == ["warning", "fail", "fail", "fail"]
    ok2 = not h["findings"] and st(h)["missing-auth"] == "pass"
    ok3 = True
    for u in ["http://example.com", "http://u:p@localhost", "ftp://localhost", "http://localhost:99999"]:
        try: validate(u); ok3 = False
        except ValueError: pass
    print("vulnerable demo: expected checks fail      :", "PASS" if ok1 else "FAIL", st(v))
    print("hardened demo: zero findings (no false pos):", "PASS" if ok2 else "FAIL", st(h))
    print("malformed / non-local targets rejected     :", "PASS" if ok3 else "FAIL")
    s.should_exit = True; sys.exit(0 if ok1 and ok2 and ok3 else 1)

if __name__ == "__main__":
    import uvicorn
    p = argparse.ArgumentParser(); p.add_argument("cmd", choices=["selftest", "demo", "api", "scan"]); p.add_argument("url", nargs="?")
    p.add_argument("--protected", nargs="*", default=[]); a = p.parse_args()
    if a.cmd == "selftest": selftest()
    elif a.cmd == "demo": uvicorn.run(demo_app, port=8001)
    elif a.cmd == "api": uvicorn.run(app, port=8000)
    else:
        if not a.url: sys.exit("usage: scan URL [--protected /path ...]")
        try: print(json.dumps(run_scan(a.url, "/api/public", a.protected), indent=2))
        except ValueError as e: sys.exit(f"Error: {e}")
