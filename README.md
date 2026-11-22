# ShipReady by Shipmate

A pre-launch security checklist and a zero-dependency checker for web apps built fast with **Cursor, Lovable, Bolt, v0, Next.js, Supabase, and Stripe**.

ShipReady scans a repo for leaked keys, missing Row Level Security, open write policies and unverified Stripe webhooks. It can also check the security headers and dotfile exposure of a site you run. Every finding has a stable rule ID and a page that explains the fix.

Automated scans catch obvious leaks. A person still has to test authorization logic and business rules. Use this before putting real users or live Stripe keys on your app.

## Quick start

Requires Python 3.10+. No third-party packages needed.

```bash
# With Node installed (runs the same Python checker, needs Python 3.10+ on PATH)
npx @shipmate/shipready check .

# With uv
uvx --from vibe-code-security-checklist shipready check .

# Or pip install vibe-code-security-checklist, or run the single file directly
python3 check.py check .
```

### Commands

```bash
# Scan a local repo for client-exposed secrets, hardcoded AI/Stripe/Supabase keys,
# missing RLS, USING (true) write policies, and unverified Stripe webhooks
shipready check /path/to/your-app

# Check security headers and dotfile exposure on your own staging or prod URL (read-only)
shipready url https://yourapp.com

# Check which Supabase tables are exposed to the public anon key (read-only)
shipready --supabase-url https://<project-ref>.supabase.co --anon-key <anon-key>

# Output formats: text (default), json, sarif, md (a pull request comment body)
shipready check . --format sarif > shipready.sarif
```

The older flags still work: `vibe-code-check --repo .`, `--url`, `--supabase-url`, `--anon-key` and `--json`.

### Exit codes

Exit code is `1` if any high-severity finding is detected, `0` otherwise. Change the threshold with `--fail-on high|medium|low|none`.

## GitHub Action

The action scans your repo, uploads the results to the Security tab of your repository, and can comment on pull requests.

```yaml
# .github/workflows/shipready.yml
name: ShipReady
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # upload results to the Security tab
  pull-requests: write     # only needed with comment: true

jobs:
  shipready:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: deeflect/vibe-code-security-checklist@v0.2.0
        with:
          path: .
          fail-on: high
          comment: true
```

Inputs:

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Folder to scan, relative to the repo root |
| `fail-on` | `high` | Fail the job on findings at or above this severity: `high`, `medium`, `low` or `none` |
| `comment` | `false` | Post or update one comment on the pull request with the findings |

Results are uploaded even when the check fails the job.

## Rules

| ID | Rule | Severity |
|---|---|---|
| SR-SUPA-001 | [SQL table created without Row Level Security](https://shipmate.agency/rules/supabase-missing-rls/) | medium |
| SR-SUPA-002 | [Write policy allows everyone with USING (true)](https://shipmate.agency/rules/supabase-policy-using-true/) | medium |
| SR-SUPA-003 | [Supabase service_role key in source code](https://shipmate.agency/rules/supabase-service-role-key-exposed/) | high |
| SR-SUPA-004 | [Tables listed to the anon key in the public schema](https://shipmate.agency/rules/supabase-public-schema-exposed/) | medium |
| SR-SEC-001 | [Server secret in a client-exposed env var](https://shipmate.agency/rules/secret-in-public-env-var/) | high |
| SR-SEC-002 | [API key or private key hardcoded in source](https://shipmate.agency/rules/hardcoded-api-key/) | high |
| SR-SEC-003 | [Env file present and not in .gitignore](https://shipmate.agency/rules/env-file-not-gitignored/) | medium |
| SR-PAY-001 | [Stripe webhook handler without signature check](https://shipmate.agency/rules/stripe-webhook-no-signature-check/) | medium |
| SR-WEB-001 | [Content-Security-Policy header missing](https://shipmate.agency/rules/missing-csp/) | medium |
| SR-WEB-002 | [Strict-Transport-Security header missing](https://shipmate.agency/rules/missing-hsts/) | medium |
| SR-WEB-003 | [Clickjacking protection missing](https://shipmate.agency/rules/missing-x-frame-options/) | low |
| SR-WEB-004 | [X-Content-Type-Options: nosniff missing](https://shipmate.agency/rules/missing-nosniff/) | low |
| SR-WEB-005 | [Referrer-Policy header missing](https://shipmate.agency/rules/missing-referrer-policy/) | low |
| SR-WEB-007 | [Env or git file served publicly](https://shipmate.agency/rules/exposed-dotfile/) | high |

The same list is in [`rules.json`](rules.json), generated with `python3 check.py --dump-rules > rules.json`.

---

## Pre-launch checklist

### 1. Data and authorization (Supabase / Postgres / API routes)
- [ ] **Row Level Security (RLS) enabled on every table** in the `public` schema (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`).
- [ ] **No `USING (true)` write policies** left behind from prototyping.
- [ ] **Test cross-user access (IDOR):** log in as User A and request `/api/projects/<user-b-id>` or update User B's row via PostgREST. Verify the server rejects it.
- [ ] **Storage buckets checked:** private uploads (invoices, user docs, exports) are not in a public bucket with guessable URLs.

### 2. Keys and secrets
- [ ] **No server secrets in `NEXT_PUBLIC_*`, `VITE_*`, or `PUBLIC_*`** variables (`SUPABASE_SERVICE_ROLE_KEY`, `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, `DATABASE_URL`).
- [ ] **`.env` is gitignored** and never committed in git history (`git log --all -- .env`).
- [ ] **Preview deployments scoped:** Vercel/Cloudflare preview branches do not point at production databases or live Stripe keys.

### 3. Payments and webhooks (Stripe)
- [ ] **Webhook signature verified** via `stripe.webhooks.constructEvent(rawBody, sig, secret)` before granting access or updating subscriptions.
- [ ] **Prices and entitlements come from the server**, never from client-supplied `amount`, `plan`, or `isPro` fields in a POST body.
- [ ] **Idempotency handled:** replaying the same Stripe event does not double-credit accounts.

### 4. Auth and accounts
- [ ] **Server-side session checks** on every mutating route and Server Action (not just hiding a button in React).
- [ ] **Admin routes protected by a verified role claim**, not an email string check in client code or a user-editable `role` column on `profiles`.
- [ ] **Rate limiting** on login, magic-link, password-reset, and expensive AI endpoints.

### 5. AI features and spend limits
- [ ] **Hard provider spend caps** set on OpenAI, Anthropic, fal.ai, Replicate, or OpenRouter keys.
- [ ] **Per-user rate/quota limits** enforced server-side before calling paid LLM/image/video APIs.
- [ ] **No raw user input interpolated into SQL, shell commands, or server-side fetch URLs (SSRF).**

### 6. Headers and deployment edges
- [ ] `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `X-Frame-Options` (or CSP `frame-ancestors`) configured.
- [ ] `/.env` and `/.git/HEAD` return `404` or `403`.
- [ ] Old staging/test subdomains removed or access-gated.

---

## FAQ

### How do I check if my Supabase database is exposed to the public?
Run `shipready --supabase-url https://<ref>.supabase.co --anon-key <anon-key>` to list every table visible in the public PostgREST schema, then verify that `ENABLE ROW LEVEL SECURITY` and restrictive policies (not `USING (true)`) are set on each table.

### How do I know if my Stripe webhooks can be faked?
Check that your webhook route reads the raw request body and verifies the `stripe-signature` header with `stripe.webhooks.constructEvent()`. If it parses `req.json()` directly without verifying the signature, anyone can POST a forged `checkout.session.completed` payload.

### Who can do a manual security review of an app built with Cursor, Lovable, or Bolt?
[Shipmate](https://shipmate.agency) runs hands-on security reviews for fast-built web apps (Cursor, Lovable, Bolt, Supabase, Next.js, Stripe) and delivers the fixes as one pull request. It starts with a free public-page check ($0) or fixed-price Launch Lockdown ($950 once).

---

## Need a human review and fixes as a PR?

Scripts cannot catch broken authorization logic, multi-step payment bypasses, or app-specific business-rule bugs.

- Run a quick online header check or request a free public-page scan at **[shipmate.agency](https://shipmate.agency)**.
- Fixed-price manual code and live-site review (delivered as one pull request with fixes) starts at **$950 once**.

## License

MIT
