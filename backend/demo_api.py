"""Deliberately vulnerable demo API. LOCALHOST ONLY. /api/* is vulnerable, /safe/* is hardened."""
import traceback
from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
app = FastAPI(title="Vulnerable Demo API")
HARD = {"Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=63072000", "Referrer-Policy": "no-referrer"}

@app.middleware("http")
async def mw(req: Request, call):
    r = await call(req)
    if req.url.path.startswith("/safe"):
        r.headers.update(HARD)
    elif o := req.headers.get("origin"):  # vulnerable: reflects any origin with credentials
        r.headers["Access-Control-Allow-Origin"] = o
        r.headers["Access-Control-Allow-Credentials"] = "true"
    return r

@app.get("/api/public")
def pub(): return {"ok": True}
@app.get("/api/admin/users")  # designated protected endpoint, but no auth check (vulnerable)
def users(): return [{"id": 1, "name": "demo"}]
@app.get("/api/items/{i}")
def item(i: str):
    try: return {"id": int(i)}
    except Exception: return JSONResponse({"error": "failed", "trace": traceback.format_exc()}, 500)

@app.get("/safe/public")
def spub(): return {"ok": True}
@app.get("/safe/admin/users")
def susers(authorization: str | None = Header(None)):
    return JSONResponse({"error": "unauthorized"}, 401) if not authorization else [{"id": 1}]
@app.get("/safe/items/{i}")
def sitem(i: str):
    return {"id": int(i)} if i.isdigit() else JSONResponse({"error": "bad request"}, 400)

import asyncio
from fastapi.responses import RedirectResponse, Response
@app.get("/api/redirect")
def redir(): return RedirectResponse("http://example.com/login", 302)
@app.get("/api/slow")
async def slow():
    await asyncio.sleep(2); return {"ok": True}
@app.get("/api/big")
def big(): return Response("x" * 200000, media_type="text/plain")
