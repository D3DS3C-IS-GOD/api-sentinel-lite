"""Read-only, localhost-only scanner. Findings come only from observed evidence."""
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
