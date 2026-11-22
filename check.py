#!/usr/bin/env python3
"""ShipReady by Shipmate: zero-dependency pre-launch security checker for Cursor, Lovable, Bolt, Next.js, Supabase & Stripe apps.

Usage:
  python3 check.py check /path/to/app [--format text|json|sarif|md] [--fail-on high|medium|low|none]
  python3 check.py url https://example.com
  python3 check.py --repo /path/to/app
  python3 check.py --url https://example.com
  python3 check.py --supabase-url https://xyz.supabase.co --anon-key eyJ...
  python3 check.py --dump-rules > rules.json
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

__version__ = "0.2.0"
RULES_BASE_URL = "https://shipmate.agency/rules/"
LOCKDOWN_LINE = "Want a person to fix these in one PR? https://shipmate.agency/lockdown"


@dataclass(frozen=True)
class Rule:
    id: str
    slug: str
    severity: str  # high, medium, low
    title: str

    @property
    def url(self) -> str:
        return f"{RULES_BASE_URL}{self.slug}/"


# IDs and slugs are permanent once published: rule pages and SARIF history depend on them.
# SR-WEB-006 (missing-permissions-policy) is reserved; the URL check does not look for that header yet.
RULES = {
    r.id: r
    for r in [
        Rule("SR-SUPA-001", "supabase-missing-rls", "medium", "SQL table created without Row Level Security"),
        Rule("SR-SUPA-002", "supabase-policy-using-true", "medium", "Write policy allows everyone with USING (true)"),
        Rule("SR-SUPA-003", "supabase-service-role-key-exposed", "high", "Supabase service_role key in source code"),
        Rule("SR-SUPA-004", "supabase-public-schema-exposed", "medium", "Tables listed to the anon key in the public schema"),
        Rule("SR-SEC-001", "secret-in-public-env-var", "high", "Server secret in a client-exposed env var"),
        Rule("SR-SEC-002", "hardcoded-api-key", "high", "API key or private key hardcoded in source"),
        Rule("SR-SEC-003", "env-file-not-gitignored", "medium", "Env file present and not in .gitignore"),
        Rule("SR-PAY-001", "stripe-webhook-no-signature-check", "medium", "Stripe webhook handler without signature check"),
        Rule("SR-WEB-001", "missing-csp", "medium", "Content-Security-Policy header missing"),
        Rule("SR-WEB-002", "missing-hsts", "medium", "Strict-Transport-Security header missing"),
        Rule("SR-WEB-003", "missing-x-frame-options", "low", "Clickjacking protection missing"),
        Rule("SR-WEB-004", "missing-nosniff", "low", "X-Content-Type-Options: nosniff missing"),
        Rule("SR-WEB-005", "missing-referrer-policy", "low", "Referrer-Policy header missing"),
        Rule("SR-WEB-007", "exposed-dotfile", "high", "Env or git file served publicly"),
    ]
}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "3.0"}


def rules_json() -> str:
    data = [{"id": r.id, "slug": r.slug, "severity": r.severity, "title": r.title, "url": r.url} for r in RULES.values()]
    return json.dumps(data, indent=2) + "\n"


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    "dist",
    "build",
    "out",
    "coverage",
    "__pycache__",
    ".venv",
    "venv",
}

TEXT_EXTS = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".sql",
    ".env",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".html",
    ".astro",
    ".svelte",
    ".vue",
}

CLIENT_SECRET_ENV_RE = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|DATABASE_URL|API_SECRET)[A-Z0-9_]*\b"
)

HARDCODED_SECRET_PATTERNS = [
    ("Stripe live secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("Stripe webhook secret", re.compile(r"\bwhsec_[A-Za-z0-9]{16,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{20,}\b")),
    ("Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{16,})\.[A-Za-z0-9_-]{10,}\b")

CREATE_TABLE_RE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z0-9_.\"`]+)", re.I)
ENABLE_RLS_RE = re.compile(r"alter\s+table\s+(?:only\s+)?([a-zA-Z0-9_.\"`]+)\s+enable\s+row\s+level\s+security", re.I)
CREATE_POLICY_RE = re.compile(r"create\s+policy\s+([^;]+);", re.I | re.S)
POLICY_READONLY_RE = re.compile(r"\bfor\s+select\b", re.I)
POLICY_OPEN_TRUE_RE = re.compile(r"\b(?:using|with\s+check)\s*\(\s*true\s*\)", re.I)
STRIPE_WEBHOOK_HINT_RE = re.compile(r"stripe.*webhook|webhook.*stripe|checkout\.session\.completed", re.I)
STRIPE_SIG_CHECK_RE = re.compile(r"constructEvent|stripe-signature", re.I)


def _has_service_role_jwt(text: str) -> int:
    """Line of the first service_role JWT, or 0."""
    for m in JWT_RE.finditer(text):
        payload = m.group(1)
        padded = payload + "=" * (-len(payload) % 4)
        try:
            data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "ignore"))
        except Exception:
            continue
        if isinstance(data, dict) and data.get("role") == "service_role":
            return _line(text, m.start())
    return 0


@dataclass
class Finding:
    area: str
    severity: str  # PASS, WARN, FAIL
    title: str
    detail: str
    location: str = ""
    rule: str = ""  # RULES key; empty for PASS lines and scan errors
    line: int = 0


def iter_repo_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            if p.suffix.lower() in TEXT_EXTS or fname.startswith(".env"):
                yield p


def check_repo(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not repo_path.is_dir():
        return [Finding("repo", "FAIL", "Repository path not found", str(repo_path))]

    # 1. Check for .env files in public/ or committed without .gitignore entry
    gitignore = (repo_path / ".gitignore").read_text(errors="ignore") if (repo_path / ".gitignore").exists() else ""
    env_files = [p for p in iter_repo_files(repo_path) if p.name == ".env" or p.name.startswith(".env.")]
    real_envs = [p for p in env_files if not p.name.endswith((".example", ".sample", ".template"))]
    for p in real_envs:
        rel = str(p.relative_to(repo_path))
        if rel.startswith("public/"):
            findings.append(Finding("secrets", "FAIL", "Env file inside public/ directory", "Files in public/ are served over HTTP.", rel, rule="SR-WEB-007"))
        elif ".env" not in gitignore:
            findings.append(Finding("secrets", "WARN", "Env file present and .env not in .gitignore", "Add .env* to .gitignore and verify it is not tracked by git.", rel, rule="SR-SEC-003"))

    # 2. Scan source files
    public_secret_hits = 0
    hardcoded_hits = 0
    unverified_webhooks = 0
    tables_created: dict[str, tuple[str, int]] = {}
    tables_with_rls: set[str] = set()

    for path in iter_repo_files(repo_path):
        if path.stat().st_size > 1_000_000:
            continue
        rel = str(path.relative_to(repo_path))
        text = path.read_text(errors="ignore")

        # Skip test files for secret pattern noise unless explicitly .env
        is_test = "test" in path.name.lower() or "spec" in path.name.lower()

        if not is_test:
            for match in CLIENT_SECRET_ENV_RE.finditer(text):
                public_secret_hits += 1
                findings.append(
                    Finding(
                        "secrets",
                        "FAIL",
                        f"Client-exposed secret env var: {match.group(0)}",
                        "Variables prefixed NEXT_PUBLIC_/VITE_/PUBLIC_ are bundled into client JS.",
                        rel,
                        rule="SR-SEC-001",
                        line=_line(text, match.start()),
                    )
                )

            if not path.name.startswith(".env"):
                for label, rx in HARDCODED_SECRET_PATTERNS:
                    if m := rx.search(text):
                        hardcoded_hits += 1
                        findings.append(
                            Finding(
                                "secrets",
                                "FAIL",
                                f"Possible hardcoded {label}",
                                "Move secrets to server-side environment variables and rotate if committed.",
                                rel,
                                rule="SR-SEC-002",
                                line=_line(text, m.start()),
                            )
                        )
                if jwt_line := _has_service_role_jwt(text):
                    hardcoded_hits += 1
                    findings.append(
                        Finding(
                            "secrets",
                            "FAIL",
                            "Hardcoded Supabase service_role JWT detected",
                            "service_role bypasses all Row Level Security. Keep it strictly server-side and rotate it.",
                            rel,
                            rule="SR-SUPA-003",
                            line=jwt_line,
                        )
                    )

        # Stripe webhook verification check
        if path.suffix.lower() in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".py"} and not is_test:
            if STRIPE_WEBHOOK_HINT_RE.search(text) and ("webhook" in rel.lower() or "stripe" in rel.lower()):
                if not STRIPE_SIG_CHECK_RE.search(text):
                    unverified_webhooks += 1
                    findings.append(
                        Finding(
                            "payments",
                            "WARN",
                            "Stripe webhook handler may skip signature verification",
                            "Verify the `stripe-signature` header using `stripe.webhooks.constructEvent()` on the raw request body.",
                            rel,
                            rule="SR-PAY-001",
                        )
                    )

        # Supabase / Postgres SQL RLS check
        if path.suffix.lower() == ".sql":
            for m in CREATE_TABLE_RE.finditer(text):
                tbl = m.group(1).strip('"`').lower().split(".")[-1]
                tables_created[tbl] = (rel, _line(text, m.start()))
            for m in ENABLE_RLS_RE.finditer(text):
                tbl = m.group(1).strip('"`').lower().split(".")[-1]
                tables_with_rls.add(tbl)
            for m in CREATE_POLICY_RE.finditer(text):
                stmt = m.group(1)
                if POLICY_OPEN_TRUE_RE.search(stmt) and not POLICY_READONLY_RE.search(stmt):
                    policy_name = stmt.strip().splitlines()[0].split()[0].strip('"`')
                    findings.append(
                        Finding(
                            "database",
                            "WARN",
                            f"Permissive write RLS policy `{policy_name}` uses USING/WITH CHECK (true)",
                            "Scope write policies (ALL/INSERT/UPDATE/DELETE) to auth.uid() or a verified role.",
                            rel,
                            rule="SR-SUPA-002",
                            line=_line(text, m.start()),
                        )
                    )

    missing_rls = sorted(set(tables_created) - tables_with_rls)
    for tbl in missing_rls:
        findings.append(
            Finding(
                "database",
                "WARN",
                f"SQL table `{tbl}` has no ENABLE ROW LEVEL SECURITY statement",
                "In Supabase, tables exposed in the public schema without RLS can be read or modified with the anon key.",
                tables_created[tbl][0],
                rule="SR-SUPA-001",
                line=tables_created[tbl][1],
            )
        )

    if public_secret_hits == 0 and hardcoded_hits == 0:
        findings.append(Finding("secrets", "PASS", "No client-exposed secret env vars or hardcoded live keys found", str(repo_path)))
    if unverified_webhooks == 0:
        findings.append(Finding("payments", "PASS", "No unverified Stripe webhook handlers flagged", str(repo_path)))
    if tables_created and not missing_rls:
        findings.append(Finding("database", "PASS", f"All {len(tables_created)} SQL tables enable Row Level Security", str(repo_path)))

    return findings


def _assert_public_host(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid HTTP(S) URL: {url}")
    host = parsed.hostname
    if host.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Refusing to probe localhost/private addresses.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host {host}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError(f"Refusing to probe non-public IP {ip} for host {host}.")
    return url.rstrip("/")


def _fetch(url: str, headers: dict[str, str] | None = None, method: str = "GET") -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(
        url,
        method=method,
        headers={"User-Agent": "vibe-code-security-checklist/1.0", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(65536).decode("utf-8", "replace") if method == "GET" else ""
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", "replace") if method == "GET" else ""
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body


def check_url(url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        base = _assert_public_host(url)
    except ValueError as exc:
        return [Finding("url", "FAIL", "Invalid or non-public target URL", str(exc), url)]

    try:
        status, hdrs, _ = _fetch(base, method="GET")
    except Exception as exc:
        return [Finding("url", "FAIL", "Could not fetch target URL", str(exc), base)]

    if status >= 400:
        findings.append(Finding("headers", "WARN", f"Homepage returned HTTP {status}", "Verify the target URL.", base))

    required = [
        ("strict-transport-security", "HSTS missing", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.", "SR-WEB-002"),
        ("content-security-policy", "CSP missing", "Add a Content-Security-Policy header to limit XSS and script injection.", "SR-WEB-001"),
        ("x-content-type-options", "X-Content-Type-Options missing", "Set X-Content-Type-Options: nosniff.", "SR-WEB-004"),
        ("referrer-policy", "Referrer-Policy missing", "Set Referrer-Policy: strict-origin-when-cross-origin.", "SR-WEB-005"),
    ]
    missing_count = 0
    for key, title, detail, rule in required:
        if key not in hdrs:
            missing_count += 1
            findings.append(Finding("headers", "WARN", title, detail, base, rule=rule))

    has_frame_guard = "x-frame-options" in hdrs or "frame-ancestors" in hdrs.get("content-security-policy", "").lower()
    if not has_frame_guard:
        missing_count += 1
        findings.append(Finding("headers", "WARN", "Clickjacking protection missing", "Set X-Frame-Options: DENY or CSP frame-ancestors.", base, rule="SR-WEB-003"))

    if missing_count == 0:
        findings.append(Finding("headers", "PASS", "Core security headers present", "HSTS, CSP, nosniff, referrer-policy, and framing protection found.", base))

    # Non-destructive check for accidentally public dotfiles
    exposed = []
    for path, marker in [("/.env", "="), ("/.git/HEAD", "ref: refs/")]:
        try:
            code, c_hdrs, body = _fetch(base + path, method="GET")
            ctype = c_hdrs.get("content-type", "")
            if code == 200 and "text/html" not in ctype and marker in body:
                exposed.append(path)
                findings.append(Finding("exposure", "FAIL", f"Sensitive file exposed at {path}", "Block public access immediately and rotate any exposed credentials.", base + path, rule="SR-WEB-007"))
        except Exception:
            continue
    if not exposed:
        findings.append(Finding("exposure", "PASS", "No public /.env or /.git/HEAD exposure detected", base))

    return findings


def check_supabase(supabase_url: str, anon_key: str) -> list[Finding]:
    try:
        base = _assert_public_host(supabase_url)
    except ValueError as exc:
        return [Finding("supabase", "FAIL", "Invalid Supabase URL", str(exc), supabase_url)]

    endpoint = f"{base}/rest/v1/"
    try:
        status, _, body = _fetch(endpoint, headers={"apikey": anon_key, "Authorization": f"Bearer {anon_key}"})
    except Exception as exc:
        return [Finding("supabase", "FAIL", "Could not reach Supabase REST endpoint", str(exc), endpoint)]

    if status != 200:
        return [Finding("supabase", "PASS", f"Supabase REST schema endpoint returned HTTP {status}", "Anonymous OpenAPI schema listing is not publicly readable.", endpoint)]

    try:
        spec = json.loads(body)
        paths = [p.lstrip("/") for p in spec.get("paths", {}) if p != "/" and not p.startswith("/rpc/")]
    except Exception:
        return [Finding("supabase", "WARN", "Supabase REST endpoint returned non-JSON 200", "Inspect manually.", endpoint)]

    if paths:
        preview = ", ".join(sorted(paths)[:15])
        suffix = f" (+{len(paths) - 15} more)" if len(paths) > 15 else ""
        return [
            Finding(
                "supabase",
                "WARN",
                f"{len(paths)} tables listed in public PostgREST schema",
                f"Tables visible to anon key: {preview}{suffix}. Verify Row Level Security (RLS) policies on every table.",
                endpoint,
                rule="SR-SUPA-004",
            )
        ]
    return [Finding("supabase", "PASS", "No tables exposed in public PostgREST schema", endpoint)]


def _severity(f: Finding) -> str:
    """Rule severity; a rule-less FAIL is a scan error and counts as high."""
    if f.rule:
        return RULES[f.rule].severity
    return "high" if f.severity == "FAIL" else ""


def _where(f: Finding) -> str:
    return f"{f.location}:{f.line}" if f.line else f.location


def format_text(findings: list[Finding]) -> str:
    out = []
    for f in findings:
        rid = f" {f.rule}" if f.rule else ""
        loc = f" ({_where(f)})" if f.location else ""
        out.append(f"[{f.severity:4s}] [{f.area}]{rid} {f.title}{loc}")
        if f.detail:
            out.append(f"       {f.detail}")
    hit = dict.fromkeys(f.rule for f in findings if f.rule)
    if hit:
        out += ["", "Rule docs:"] + [f"  {rid}  {RULES[rid].url}" for rid in hit] + ["", LOCKDOWN_LINE]
    return "\n".join(out)


def _sarif_uri(f: Finding, base: Path | None) -> str:
    if base is None or f.location.startswith(("http://", "https://")):
        return f.location
    rel = os.path.relpath(base / f.location)  # relative to cwd, so the Action's paths match the checkout
    return Path(rel).as_posix() if not rel.startswith("..") else (base / f.location).resolve().as_uri()


def format_sarif(findings: list[Finding], base: Path | None = None) -> str:
    rule_ids = list(RULES)
    results, notes = [], []
    for f in findings:
        if f.rule:
            region = {"region": {"startLine": f.line}} if f.line else {}
            results.append(
                {
                    "ruleId": f.rule,
                    "ruleIndex": rule_ids.index(f.rule),
                    "level": SARIF_LEVEL[RULES[f.rule].severity],
                    "message": {"text": f"{f.title}. {f.detail}".strip()},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": _sarif_uri(f, base)}, **region}}],
                }
            )
        elif f.severity != "PASS":
            notes.append({"level": "error" if f.severity == "FAIL" else "warning", "message": {"text": f"{f.title}: {f.detail} {f.location}".strip()}})
    driver_rules = [
        {
            "id": r.id,
            "name": r.slug,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.title},
            "helpUri": r.url,
            "help": {"text": f"{r.title}. Fix: {r.url}", "markdown": f"{r.title}. [How to fix]({r.url})"},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security"], "security-severity": SECURITY_SEVERITY[r.severity]},
        }
        for r in RULES.values()
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShipReady",
                        "fullName": "ShipReady by Shipmate",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": RULES_BASE_URL,
                        "rules": driver_rules,
                    }
                },
                "invocations": [{"executionSuccessful": not any(n["level"] == "error" for n in notes), "toolExecutionNotifications": notes}],
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_md(findings: list[Finding]) -> str:
    issues = sorted((f for f in findings if f.rule), key=lambda f: -SEVERITY_RANK[_severity(f)])
    errors = [f for f in findings if not f.rule and f.severity != "PASS"]
    out = ["<!-- shipready -->", "## ShipReady by Shipmate", ""]
    if issues:
        counts = {s: sum(_severity(f) == s for f in issues) for s in ("high", "medium", "low")}
        out.append(f"{len(issues)} findings: {counts['high']} high, {counts['medium']} medium, {counts['low']} low.")
        out += ["", "| Severity | Rule | Finding | Location |", "|---|---|---|---|"]
        for f in issues:
            r = RULES[f.rule]
            cells = [r.severity, f"[{r.id}]({r.url})", f.title, f"`{_where(f)}`"]
            out.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    else:
        out.append("No issues found.")
    for f in errors:
        out += ["", f"Could not complete a check: {f.title}. {f.detail}"]
    if issues:
        out += ["", LOCKDOWN_LINE]
    return "\n".join(out)


def _output_args(p: argparse.ArgumentParser, top: bool) -> None:
    # Subparser copies use SUPPRESS so they never overwrite a value given before the subcommand.
    default = None if top else argparse.SUPPRESS
    p.add_argument("--format", choices=["text", "json", "sarif", "md"], default=default, help="Output format (default text).")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "none"], default=default, help="Exit 1 when a finding is at or above this severity (default high).")
    p.add_argument("--json", action="store_true", default=False if top else argparse.SUPPRESS, help="Same as --format json.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shipready", description="ShipReady by Shipmate: pre-launch security checker for AI-built web apps.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--repo", type=Path, help="Local repository path to scan statically.")
    parser.add_argument("--url", help="Public HTTPS URL to check headers and dotfile exposure (read-only).")
    parser.add_argument("--supabase-url", help="Supabase project URL (https://<ref>.supabase.co) for read-only schema check.")
    parser.add_argument("--anon-key", help="Supabase anon key (used with --supabase-url).")
    parser.add_argument("--dump-rules", action="store_true", help="Print the rule registry as JSON (the source of rules.json).")
    _output_args(parser, top=True)
    sub = parser.add_subparsers(dest="cmd")
    p_check = sub.add_parser("check", help="Scan a local repository.")
    p_check.add_argument("path", type=Path, nargs="?", default=Path("."))
    _output_args(p_check, top=False)
    p_url = sub.add_parser("url", help="Check headers and dotfile exposure of a site you run (read-only).")
    p_url.add_argument("target")
    _output_args(p_url, top=False)
    args = parser.parse_args(argv)

    if args.dump_rules:
        sys.stdout.write(rules_json())
        return 0
    if args.cmd == "check":
        args.repo = args.path
    elif args.cmd == "url":
        args.url = args.target

    if not args.repo and not args.url and not args.supabase_url:
        parser.print_help()
        return 2

    findings: list[Finding] = []
    if args.repo:
        findings.extend(check_repo(args.repo))
    if args.url:
        findings.extend(check_url(args.url))
    if args.supabase_url:
        if not args.anon_key:
            print("Error: --anon-key is required with --supabase-url", file=sys.stderr)
            return 2
        findings.extend(check_supabase(args.supabase_url, args.anon_key))

    fmt = args.format or ("json" if args.json else "text")
    if fmt == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif fmt == "sarif":
        print(format_sarif(findings, args.repo))
    elif fmt == "md":
        print(format_md(findings))
    else:
        print(format_text(findings))

    fail_on = args.fail_on or "high"
    if fail_on == "none":
        return 0
    return 1 if any(SEVERITY_RANK.get(_severity(f), 0) >= SEVERITY_RANK[fail_on] for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
