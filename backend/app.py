import sqlite3, json, uuid, html, re, os, threading, logging, datetime as dt
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import scanner
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
        try: res = scanner.run_scan(r.target, r.base_path, r.protected, r.error_path)
        except ValueError as e: raise HTTPException(400, str(e))
        ran = any(c["status"] != "not_tested" for c in res["checks"])
        st, err = ("completed", "") if ran else ("failed", "No check could run: target unreachable or timed out")
        sid = uuid.uuid4().hex[:8]
        with conn() as c:  # one transaction: scan + findings are saved together or not at all
            c.execute("insert into scans values(?,?,?,?,?,?,?)", (sid, scanner.validate(r.target), dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), st, err, json.dumps(res["checks"]), str(res["duration"])))
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
    return {"version": VER, "allowed_hosts": sorted(scanner.LOCAL), "timeout_s": scanner.TIMEOUT, "total_scan_budget_s": scanner.TOTAL, "max_response_bytes": scanner.MAXB,
            "checks": scanner.CHECKS, "storage": "SQLite: " + os.path.basename(dbpath()), "notice": NOTICE}
