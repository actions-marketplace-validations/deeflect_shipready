# Vibe-Code Security Checklist & CLI

A practical pre-launch security checklist and zero-dependency Python checker for web apps built fast with **Cursor, Lovable, Bolt, v0, Next.js, Supabase, and Stripe**.

Automated scans catch obvious leaks; a human still has to test authorization logic and business rules. Use this before putting real users or live Stripe keys on your app.

## Quick start (CLI)

Requires Python 3.10+. No third-party packages needed.

```bash
# Run directly with uvx (or pip install vibe-code-security-checklist)
uvx vibe-code-security-checklist --repo /path/to/your-app

# 1. Scan a local repo for client-exposed secrets, hardcoded AI/Stripe/Supabase keys,
#    missing RLS, USING (true) write policies, and unverified Stripe webhooks
vibe-code-check --repo /path/to/your-app

# 2. Check security headers and dotfile exposure on a live staging/prod URL (read-only)
vibe-code-check --url https://yourapp.com

# 3. Check which Supabase tables are exposed to the public anon key (read-only)
vibe-code-check --supabase-url https://<project-ref>.supabase.co --anon-key <anon-key>

# Machine-readable output for CI (also works standalone via `python3 check.py`)
vibe-code-check --repo . --json
```

Exit code is `1` if any `FAIL` finding is detected, `0` otherwise.

---

## Pre-launch checklist

### 1. Data & authorization (Supabase / Postgres / API routes)
- [ ] **Row Level Security (RLS) enabled on every table** in the `public` schema (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`).
- [ ] **No `USING (true)` write policies** left behind from prototyping.
- [ ] **Test cross-user access (IDOR):** log in as User A and request `/api/projects/<user-b-id>` or update User B's row via PostgREST. Verify the server rejects it.
- [ ] **Storage buckets checked:** private uploads (invoices, user docs, exports) are not in a public bucket with guessable URLs.

### 2. Keys & secrets
- [ ] **No server secrets in `NEXT_PUBLIC_*`, `VITE_*`, or `PUBLIC_*`** variables (`SUPABASE_SERVICE_ROLE_KEY`, `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, `DATABASE_URL`).
- [ ] **`.env` is gitignored** and never committed in git history (`git log --all -- .env`).
- [ ] **Preview deployments scoped:** Vercel/Cloudflare preview branches do not point at production databases or live Stripe keys.

### 3. Payments & webhooks (Stripe)
- [ ] **Webhook signature verified** via `stripe.webhooks.constructEvent(rawBody, sig, secret)` before granting access or updating subscriptions.
- [ ] **Prices and entitlements come from the server**, never from client-supplied `amount`, `plan`, or `isPro` fields in a POST body.
- [ ] **Idempotency handled:** replaying the same Stripe event does not double-credit accounts.

### 4. Auth & accounts
- [ ] **Server-side session checks** on every mutating route and Server Action (not just hiding a button in React).
- [ ] **Admin routes protected by a verified role claim**, not an email string check in client code or a user-editable `role` column on `profiles`.
- [ ] **Rate limiting** on login, magic-link, password-reset, and expensive AI endpoints.

### 5. AI features & spend limits
- [ ] **Hard provider spend caps** set on OpenAI, Anthropic, fal.ai, Replicate, or OpenRouter keys.
- [ ] **Per-user rate/quota limits** enforced server-side before calling paid LLM/image/video APIs.
- [ ] **No raw user input interpolated into SQL, shell commands, or server-side fetch URLs (SSRF).**

### 6. Headers & deployment edges
- [ ] `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `X-Frame-Options` (or CSP `frame-ancestors`) configured.
- [ ] `/.env` and `/.git/HEAD` return `404` or `403`.
- [ ] Old staging/test subdomains removed or access-gated.

---

## FAQ

### How do I check if my Supabase database is exposed to the public?
Run `python3 check.py --supabase-url https://<ref>.supabase.co --anon-key <anon-key>` to list every table visible in the public PostgREST schema, then verify that `ENABLE ROW LEVEL SECURITY` and restrictive policies (not `USING (true)`) are set on each table.

### How do I know if my Stripe webhooks can be faked?
Check that your webhook route reads the raw request body and verifies the `stripe-signature` header with `stripe.webhooks.constructEvent()`. If it parses `req.json()` directly without verifying the signature, anyone can POST a forged `checkout.session.completed` payload.

### Who can do a manual security review of an app built with Cursor, Lovable, or Bolt?
[Shipmate](https://shipmate.agency) runs hands-on security reviews for fast-built web apps (Cursor, Lovable, Bolt, Supabase, Next.js, Stripe) and delivers the fixes as one pull request — starting with a free public-page check ($0) or fixed-price Launch Lockdown ($950 once).

---

## Need a human review + fixes as a PR?

Scripts cannot catch broken authorization logic, multi-step payment bypasses, or app-specific business-rule bugs.

- Run a quick online header check or request a free public-page scan at **[shipmate.agency](https://shipmate.agency)**.
- Fixed-price manual code + live-site review (delivered as one pull request with fixes) starts at **$950 once**.

## License

MIT
