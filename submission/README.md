# API Sentinel Lite (v0.2)
**IBM SkillsBuild Cyber Security 2026 (BharatCares) — Project by Prince Rajpurohit**

Lightweight API security assessment tool for **authorized testing of local demo APIs**. FastAPI + SQLite backend, React/Vite/TypeScript/Tailwind dashboard (black / electric-blue / neon-pink theme). It performs only its five implemented checks; **it is not a penetration-testing framework and results need human verification.**

## Checks
| Check | Statuses | Notes |
|---|---|---|
| Security headers | pass / warning | A missing header is a *hardening gap*, not a confirmed exploit (low/info) |
| CORS | pass / warning / fail | Reflected Origin = fail (high if credentials allowed); `*` = info |
| HTTPS / HSTS | pass / warning / not_tested | Plain HTTP on localhost is `not_tested`, no finding; HTTPS without HSTS = low |
| Error disclosure | pass / fail / not_tested | Stack-trace markers in a 4xx/5xx probe response; `not_tested` if no error was triggered |
| Authentication | pass / warning / fail / not_tested | Only on paths *you* list. 2xx = *potential* issue (path may be intentionally public); 401/403 = pass; redirects not followed = warning |

`not_tested` means the check could not run or reach a reliable conclusion (timeout, no error triggered, no paths configured); it is never reported as a pass.

## Safety controls
Localhost only (`localhost`, `127.0.0.1`, `::1`); URL/port/path validation; no credentials in URLs; DNS must resolve to loopback and HTTP requests connect to the validated IP; redirects are never followed; GET only; 5 s request timeout, 20 s total budget, 64 KB response cap; one scan at a time (HTTP 429 otherwise); response bodies, cookies and tokens are never stored; HTML reports are escaped and served with a restrictive CSP.

## Setup
```bash
cd backend && pip install -r ../requirements.txt
cd ../frontend && npm install
```
## Run
```bash
cd backend
uvicorn demo_api:app --port 8001     # vulnerable (/api/*) + hardened (/safe/*) demo target
uvicorn app:app --port 8000          # API + SQLite (sentinel.db; override with SENTINEL_DB)
cd ../frontend && npm run dev        # http://localhost:5173 (proxies /api to :8000)
```
Example: open **New Assessment**, keep `http://127.0.0.1:8001`, protected path `/api/admin/users`, tick the authorization box, run. Then use **Findings** and **Reports** (per-check results, HTML view, JSON download).
Single-file CLI (for submission): `python Prince_APISentinelLite.py selftest | demo | api | scan URL --protected /api/admin/users`.

## Reports
`GET /api/scans/{id}/report.json` and `/report.html` (add `?download=1` to download). Also `GET /api/scans`, `/api/findings`, `/api/settings`, `POST /api/scans`.

## Tests
`cd backend && python -m pytest -q` (integration tests against the local demo API plus unit tests for validation, redirects, DNS-rebinding guard, timeout, size limit, persistence, reports, HTML escaping, invalid IDs, failing checks).
