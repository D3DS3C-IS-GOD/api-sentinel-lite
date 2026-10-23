import os, threading, time, json, socket, tempfile, pytest, uvicorn, httpx
os.environ["SENTINEL_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import scanner, app as appmod
from demo_api import app as demo
from fastapi.testclient import TestClient
B = "http://127.0.0.1:8765"
@pytest.fixture(scope="module", autouse=True)
def server():
    s = uvicorn.Server(uvicorn.Config(demo, port=8765, log_level="error")); threading.Thread(target=s.run, daemon=True).start(); time.sleep(1.2); yield; s.should_exit = True
def st(res): return {c["id"]: c["status"] for c in res["checks"]}
def rules(fs): return {f["rule"] for f in fs}
V = dict(base_path="/api/public", protected=["/api/admin/users"], error_path="/api/items/abc")
H = dict(base_path="/safe/public", protected=["/safe/admin/users"], error_path="/safe/items/abc")

def test_vulnerable_all_rules_fire():
    r = scanner.run_scan(B, **V)
    assert {"missing-header", "permissive-cors", "verbose-error", "missing-auth"} <= rules(r["findings"])
    assert [st(r)[k] for k in ("missing-header", "permissive-cors", "verbose-error", "missing-auth")] == ["warning", "fail", "fail", "fail"]
def test_http_localhost_is_not_a_finding():
    r = scanner.run_scan(B, **V); assert st(r)["https-config"] == "not_tested" and "https-config" not in rules(r["findings"])
def test_hardened_no_false_positives():
    r = scanner.run_scan(B, **H); assert not r["findings"] and st(r)["missing-auth"] == "pass" and st(r)["verbose-error"] == "pass" and st(r)["permissive-cors"] == "pass"
def test_auth_not_tested_without_paths():
    assert st(scanner.run_scan(B, base_path="/api/public", protected=[]))["missing-auth"] == "not_tested"
def test_header_finding_is_hardening_gap_not_vuln():
    f = [x for x in scanner.run_scan(B, **V)["findings"] if x["rule"] == "missing-header"]; assert f and all(x["kind"] == "hardening gap" and x["severity"] in ("low", "info") for x in f)

@pytest.mark.parametrize("u", ["http://example.com", "http://u:p@localhost", "ftp://localhost", "http://localhost:99999", "http://[::1", "http://localhost/ x", "http://localhost?x=1", "http://localhost/a", "", "localhost", "http://10.0.0.1", "http://localhost.evil.com"])
def test_bad_targets_rejected(u):
    with pytest.raises(ValueError): scanner.validate(u)
@pytest.mark.parametrize("u", ["http://localhost:8001", "http://127.0.0.1", "http://[::1]:8000"])
def test_good_targets(u): assert scanner.validate(u).startswith("http")
@pytest.mark.parametrize("p", ["//evil.com", "/../etc", "api", "/a b", "/a?x=1", "/" + "a" * 300])
def test_bad_paths_rejected(p):
    with pytest.raises(ValueError): scanner._path(p)
def test_dns_rebinding_guard(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 80))])
    with pytest.raises(ValueError): scanner.run_scan("http://localhost:8765", **V)
def test_redirect_not_followed_and_not_a_finding():
    r = scanner.run_scan(B, base_path="/api/public", protected=["/api/redirect"])
    assert st(r)["missing-auth"] == "warning" and "missing-auth" not in rules(r["findings"]) and "not followed" in [c for c in r["checks"] if c["id"] == "missing-auth"][0]["detail"]
def test_timeout_is_not_tested_not_crash(monkeypatch):
    monkeypatch.setattr(scanner, "TIMEOUT", 0.3); r = scanner.run_scan(B, base_path="/api/public", protected=["/api/slow"])
    assert st(r)["missing-auth"] == "not_tested" and st(r)["missing-header"] == "warning"
def test_oversized_response_truncated():
    with httpx.Client() as c:
        ctx = scanner.Ctx(B, c, time.monotonic() + 5); code, _, body, trunc = scanner.fetch(ctx, "/api/big")
    assert trunc and len(body) == scanner.MAXB
def test_total_budget():
    assert {c["status"] for c in scanner.run_scan(B, total=0, **V)["checks"]} == {"not_tested"}
def test_one_failing_check_does_not_crash(monkeypatch):
    def bad(*a): raise RuntimeError("boom")
    monkeypatch.setitem(scanner.CHECK_FUNCS, "verbose-error", bad); r = scanner.run_scan(B, **V)
    assert st(r)["verbose-error"] == "not_tested" and st(r)["permissive-cors"] == "fail"

cl = TestClient(appmod.app, raise_server_exceptions=False)
def post(**k): return cl.post("/api/scans", json={"target": B, "authorized": True, **V, **k})
def test_requires_authorization(): assert cl.post("/api/scans", json={"target": B}).status_code == 400
def test_non_local_rejected_by_api(): assert post(target="http://example.com").status_code == 400
def test_unreachable_is_failed_not_crash():
    r = post(target="http://127.0.0.1:9").json(); assert r["status"] == "failed" and "Traceback" not in json.dumps(r)
def test_persistence_and_reports():
    sid = post().json()["id"]
    assert sid in [s["id"] for s in cl.get("/api/scans").json()] and any(f["scan_id"] == sid for f in cl.get("/api/findings").json())
    j = cl.get(f"/api/scans/{sid}/report.json").json(); assert j["checks"] and j["findings"] and j["scan"]["target"] == B and "human verification" in j["notice"]
    h = cl.get(f"/api/scans/{sid}/report.html"); assert h.status_code == 200 and "Checks performed" in h.text and "default-src 'none'" in h.headers["content-security-policy"]
    assert "attachment" in cl.get(f"/api/scans/{sid}/report.json?download=1").headers["content-disposition"]
def test_html_escaping():
    sid = post().json()["id"]
    with appmod.conn() as c: c.execute("insert into findings values(?,?,?)", ("zz", sid, json.dumps(dict(rule="x", title="<script>alert(1)</script>", severity="low", confidence="low", endpoint="/<img onerror=x>", evidence="<b>", impact="<i>", remediation="<u>", kind="k", verification="v"))))
    t = cl.get(f"/api/scans/{sid}/report.html").text; assert "<script>alert" not in t and "&lt;script&gt;" in t and "<img onerror" not in t
@pytest.mark.parametrize("i", ["../etc/passwd", "zzzzzzzz", "00000000", "a" * 50, "%00"])
def test_invalid_report_ids(i):
    for ext in ("json", "html"): assert cl.get(f"/api/scans/{i}/report.{ext}").status_code in (404, 422)
def test_concurrent_scan_rejected():
    appmod.LOCK.acquire()
    try: assert post().status_code == 429
    finally: appmod.LOCK.release()
def test_no_secrets_or_bodies_stored():
    sid = post().json()["id"]; raw = json.dumps(cl.get(f"/api/scans/{sid}/report.json").json())
    assert '"name": "demo"' not in raw  # body of /api/admin/users never stored
def test_settings(): assert cl.get("/api/settings").json()["version"] == appmod.VER
