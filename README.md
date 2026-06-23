# ZKNET Audit Toolkit v1

Automated security audit and remediation for vibe-coded applications in production. Probes codebases for 17 vulnerability categories, then applies targeted fixes.

Built for the ZKNetwork ecosystem. Zero external dependencies — pure Python stdlib (optional `npm` for dependency audit checks).

---

## Quick Start

```
$ git clone https://github.com/ethrx-dev/zknet-audit-toolkit.git
$ cd zknet-audit-toolkit
$ ln -sf "$PWD/run-audit" ~/.local/bin/zknet-audit

# Scan anything
$ zknet-audit /path/to/project -o ./reports

# Preview fixes (dry-run — no files touched)
$ zknet-audit fix ./reports/audit-results.json /path/to/project --dry-run

# Apply fixes
$ zknet-audit fix ./reports/audit-results.json /path/to/project
```

---

## Scanner

`scanner.py` walks a target directory and yields source files for analysis:

| Setting | Value |
|---------|-------|
| Max file size | 1 MB (larger files are skipped) |
| Excluded dirs | `.git`, `node_modules`, `__pycache__`, `.next`, `build`, `dist`, `target`, `venv`, `.venv`, `.cache`, `.npm`, `.yarn`, `coverage`, `.nyc_output`, `env`, `.env`, `site-packages`, `.tox`, `.eggs`, `eggs`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.hypothesis`, `.svn` |
| Excluded extensions | `.pyc`, `.pyo`, `.so`, `.o`, `.a`, `.lib`, `.dll`, `.dylib`, `.exe`, `.bin`, `.dat`, `.db`, `.sqlite`, `.sqlite3`, images, audio, video, archives, PDFs, Office docs, fonts, source maps, `.lock`, `.log`, `.pid` |
| Source extensions scanned | `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.go`, `.rs`, `.java`, `.rb`, `.php`, `.c`, `.cpp`, `.h`, `.hpp`, `.swift`, `.kt`, `.scala`, `.html`, `.vue`, `.svelte`, `.css`, `.scss`, `.sass`, `.less`, `.yaml`, `.yml`, `.json`, `.toml`, `.ini`, `.cfg`, `.conf`, `.md`, `.mdx`, `.sh`, `.bash`, `.zsh`, `.fish`, `.dockerfile`, `.env`, `.env.example`, `.mjs`, `.cjs`, `.mts`, `.cts` |

---

## 17 Security Checks

Each check module lives in `checks/` and returns a dict with `id`, `name`, `status` (PASS/FAIL), `severity` (LOW/MEDIUM/HIGH/CRITICAL), `summary`, `details`, and `findings`.

| # | Check | Severity | What It Finds | Patterns Scanned |
|---|-------|----------|---------------|-----------------|
| 1 | Exposed Secrets | **CRITICAL** | .env in git, hard-coded keys, .env.example with real values | Stripe keys, AWS AKIA keys, SSH private keys, GitHub tokens, Slack tokens, DB connection strings, hardcoded passwords/secrets/API keys/tokens |
| 2 | Database Access Control | LOW | Supabase RLS, Firebase rules bypassed | Supabase config files missing RLS references, Firebase rules without `auth != null`, raw SQL patterns (`.raw()`, `.query()`, `execute()`, `.sql()`) |
| 3 | Auth Middleware | **CRITICAL** | Missing auth guards on API routes | Route definitions (FastAPI, Express, Flask, Next.js, Django), auth middleware keywords (`authenticate`, `login_required`, `jwt.verify`, `getSession`, etc.) |
| 4 | Access Control (IDOR) | LOW | Missing ownership checks on user data | ID parameter usage (`user_id`, `params.id`, `[id]`, `:id`, `/{id}`), ownership check patterns (`owner_id`, `user_id ==`, `current_user`, `creator_id`, `request.user`) |
| 5 | Frontend Secrets | LOW | `NEXT_PUBLIC_` / `VITE_` env vars with secrets | Public env prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_ENV_`, `GATSBY_`, `SANITY_STUDIO_`) with secret indicators |
| 6 | SSRF | **HIGH** | URL fetching without private-IP validation | HTTP client usage (requests, urllib, httpx, fetch, axios, got, jQuery), IP blocklist patterns (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, `::1`) |
| 7 | CSRF | **HIGH** | Missing SameSite or CSRF tokens on cookies | `SameSite=Lax/Strict/None`, CSRF token references, Bearer auth detection (which makes CSRF via cookies N/A) |
| 8 | Security Headers | MEDIUM | CSP, HSTS, XFO, XCTO, Referrer-Policy | Header presence, middleware detection (helmet, Secure, CSP middleware) |
| 9 | CORS | LOW | Wildcard ACAO, creds + wildcard | Wildcard origins (`origin: *`, `Access-Control-Allow-Origin: *`), dynamic origin reflection |
| 10 | Rate Limiting | **HIGH** | No limits on auth endpoints | Rate limit middleware keywords (`rate_limit`, `ratelimit`, `throttle`, `limiter`, `slowapi`, `express-rate-limit`), auth endpoint detection (login, register, password-reset) |
| 11 | SQL Injection | **HIGH** | f-string SQL, string concat in execute() | f-string SQL interpolation, `.format()` in SQL, template literals in SQL, parameterized query detection (`%s`, `?`, `:param`, `$1`) |
| 12 | XSS | **HIGH** | dangerouslySetInnerHTML, v-html, innerHTML | `dangerouslySetInnerHTML`, `v-html`, `innerHTML=`, `.html()`, `insertAdjacentHTML`, sanitizer detection (DOMPurify, sanitize-html, xss lib), triple braces in templates |
| 13 | Payment Webhooks | LOW | Missing Stripe sig verification | Stripe references, `construct_event` verification, idempotency handling (`idempotency_key`, `processed_events`), event lifecycle handlers (`payment_intent.succeeded`, `invoice.payment_failed`, `customer.subscription.deleted/past_due`) |
| 14 | File Uploads | MEDIUM | No magic-byte check, no UUID rename | Upload patterns (multer, FileField, FileUpload, form-data, multipart), security measures (magic byte detection, Content-Type validation, UUID renaming, external storage, size limits) |
| 15 | Error Handling | MEDIUM | Stack traces exposed, debug mode in prod | Debug mode flags (`debug=True`, `NODE_ENV=development`, `DEBUG=true`), error handler detection (try/except, catch, error middleware, ExceptionHandler, generic error responses) |
| 16 | Password Hashing | LOW | MD5/SHA1 for passwords | Strong hash detection (bcrypt, argon2, scrypt), weak hash detection (MD5, SHA-1, SHA-256 for passwords), third-party auth provider detection (Auth0, Supabase Auth, Firebase Auth, Clerk, NextAuth, Passport) |
| 17 | Dependencies | MEDIUM | Unpinned ^/~ versions, no lockfile, vulns | Package.json unpinned deps (`^`/`~`), lockfile presence, Python unpinned deps (`>=`), runs `npm audit --json` for vulnerability scanning |

---

## Automated Fix Modules

When a check fails, `zknet-audit fix` applies targeted remediation. Fixes live in `fixes/` and are orchestrated by `fixes/fixer.py`.

Before any modification, the fixer **backs up every file** with a `.bak` suffix.

| Module | What It Does |
|--------|-------------|
| secrets | Creates `.gitignore`, `.env.example`, ensures `.env` is untracked |
| headers | Generates security-headers middleware (Express, FastAPI, Flask) or HTML meta tags |
| cors | Restricts ACAO to explicit origin allowlist |
| csrf | Adds SameSite cookies, CSRF token middleware |
| rate_limiting | Generates rate-limit middleware |
| errors | Disables DEBUG, adds generic error handler |
| passwords | Replaces weak hashing with bcrypt/argon2 utils |
| uploads | Adds magic-byte validation, UUID renaming |
| webhooks | Generates Stripe webhook with signature verification |
| ssrf | Adds private-IP blocklist before URL fetch |
| dependencies | Pins exact versions, runs `npm audit fix` |

### Framework Auto-Detection

`fixes/framework.py` scans the target for:

- **Node.js**: `package.json` dependencies (express, next, react, vue)
- **Python**: `requirements.txt` or `pyproject.toml` (fastapi, django, flask)
- **Static HTML**: fallback when no backend framework is detected and `.html` files exist

Each fix module is tailored to the detected stack.

---

## Output Reports

```
$ tree ./reports/
├── AUDIT_SUMMARY.md       ← Human-readable markdown with per-category findings
├── audit-results.json     ← Machine-readable JSON (feeds fix tool)
├── FIX_REPORT.md          ← Post-fix summary with per-category status
└── fix-results.json       ← Machine-readable fix log
```

### Sample Report

The `security/` directory contains latest audit output from scanning `zknetwork-beta-client-v1`, showing all 17 checks passing with detailed per-file findings.

---

## Architecture

```
zknet-audit-toolkit/
├── run-audit                CLI entry point (subcommand-aware)
├── audit.py                 Scanner orchestrator — runs all 17 checks, generates reports
├── scanner.py               Centralized file iterator (exclusions, size limits, ext filtering)
├── checks/                  17 check modules
│   ├── secrets.py           database.py         auth_middleware.py
│   ├── idor.py              frontend_secrets    ssrf.py
│   ├── csrf.py              headers.py          cors.py
│   ├── rate_limiting.py     sqli.py             xss.py
│   ├── webhooks.py          file_upload.py      errors.py
│   ├── passwords.py         dependencies.py
├── fixes/                   11 fix modules + orchestrator + framework detector
│   ├── fixer.py             Orchestrator — reads audit JSON, applies fixes, generates fix report
│   ├── framework.py         Auto-detect stack (Express, Next.js, FastAPI, Django, Flask, React, Vue, static)
│   └── *.py                 One fix module per category (secrets, headers, cors, csrf, etc.)
├── reporters/               Report rendering (extensible — currently stubbed)
├── security/                Latest audit output on zknetwork-client
│   ├── AUDIT_SUMMARY.md
│   └── audit-results.json
├── reports/                 Report output directory (created on first run)
└── README.md
```

---

## Requirements

- **Python 3.8+** (stdlib only)
- **npm** (optional, only needed for dependency vulnerability auditing)

---

## Closing note

Built for the ZKNet ecosystem.

---

*"Trust, but verify." — every vibe needs a check.*
