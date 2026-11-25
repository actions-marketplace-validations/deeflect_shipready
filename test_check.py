import base64
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check

_HDR = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
_SRV = base64.urlsafe_b64encode(json.dumps({"iss": "supabase", "role": "service_role"}).encode()).decode().rstrip("=")

# One minimal repo per repo-level rule: {rule_id: {relative_path: content}}
REPO_FIXTURES = {
    "SR-SUPA-001": {"001_init.sql": "-- init\nCREATE TABLE public.invoices (id int);\n"},
    "SR-SUPA-002": {
        "p.sql": "CREATE TABLE t (id int);\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\nCREATE POLICY w ON t FOR ALL USING (true);\n"
    },
    "SR-SUPA-003": {"admin.ts": f"\nconst j = '{_HDR}.{_SRV}.signature12345';\n"},
    "SR-SEC-001": {"client.ts": "// x\nconst k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n"},
    "SR-SEC-002": {"aws.ts": "const id = 'AKIAIOSFODNN7EXAMPLE';\n"},
    "SR-SEC-003": {".env": "A=1\n"},
    "SR-PAY-001": {"stripe_webhook.ts": "if (body.type === 'checkout.session.completed') unlock();\n"},
    "SR-WEB-007": {"public/.env": "A=1\n"},
}
REPO_FIXTURE_LINES = {"SR-SUPA-001": 2, "SR-SUPA-002": 3, "SR-SUPA-003": 2, "SR-SEC-001": 2, "SR-SEC-002": 1}

# Headers a fully configured site sends; dropping one should raise exactly one rule.
GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-frame-options": "DENY",
}
HEADER_FIXTURES = {
    "SR-WEB-001": "content-security-policy",
    "SR-WEB-002": "strict-transport-security",
    "SR-WEB-003": "x-frame-options",
    "SR-WEB-004": "x-content-type-options",
    "SR-WEB-005": "referrer-policy",
}


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(content)


def _fake_site(headers: dict[str, str], dotfiles: dict[str, str] | None = None):
    """Stand-in for check._fetch: homepage returns `headers`, dotfile paths 404 unless listed."""

    def fetch(url, **_kw):
        for path, body in (dotfiles or {}).items():
            if url.endswith(path):
                return 200, {"content-type": "text/plain"}, body
        if url.endswith(("/.env", "/.git/HEAD")):
            return 404, {"content-type": "text/html"}, ""
        return 200, dict(headers), "<html></html>"

    return fetch


@contextlib.contextmanager
def _offline(fetch):
    with mock.patch.object(check, "_assert_public_host", side_effect=lambda u: u.rstrip("/")), mock.patch.object(check, "_fetch", side_effect=fetch):
        yield


def _run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = check.main(argv)
    return code, buf.getvalue()


class TestVibeCodeSecurityChecklist(unittest.TestCase):
    def test_clean_repo_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text(".env\nnode_modules\n")
            (root / "schema.sql").write_text(
                "CREATE TABLE public.orders (id uuid primary key);\n"
                "ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n"
            )
            (root / "stripe_webhook.ts").write_text(
                "const sig = req.headers.get('stripe-signature');\n"
                "const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);\n"
            )
            findings = check.check_repo(root)
            self.assertFalse(any(f.severity in {"FAIL", "WARN"} for f in findings), findings)

    def test_detects_exposed_client_secret_and_hardcoded_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "client.ts").write_text(
                "const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n"
                "const s = 'sk_live_1234567890abcdef123456';\n"
            )
            findings = check.check_repo(root)
            fails = [f for f in findings if f.severity == "FAIL"]
            self.assertEqual(len(fails), 2, findings)

    def test_detects_missing_rls_and_unverified_stripe_webhook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "001_init.sql").write_text("CREATE TABLE public.invoices (id int);\n")
            (root / "api_stripe_webhook.ts").write_text(
                "export async function POST(req) { const body = await req.json(); if (body.type === 'checkout.session.completed') unlock(); }\n"
            )
            findings = check.check_repo(root)
            warns = {f.area for f in findings if f.severity == "WARN"}
            self.assertIn("database", warns)
            self.assertIn("payments", warns)

    def test_refuses_localhost_and_private_ips(self) -> None:
        for bad in ["http://localhost:3000", "http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data"]:
            findings = check.check_url(bad)
            self.assertEqual(findings[0].severity, "FAIL")

    def test_detects_ai_keys_and_service_role_jwt_not_anon(self) -> None:
        import base64, json
        hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        srv = base64.urlsafe_b64encode(json.dumps({"iss": "supabase", "role": "service_role"}).encode()).decode().rstrip("=")
        anon = base64.urlsafe_b64encode(json.dumps({"iss": "supabase", "role": "anon"}).encode()).decode().rstrip("=")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.ts").write_text(f"export const ANON = '{hdr}.{anon}.signature12345';\n")
            self.assertFalse(any(f.severity == "FAIL" for f in check.check_repo(root)))
            (root / "leak.ts").write_text(
                f"const a = 'sk-ant-api03-1234567890abcdefghijklmno';\n"
                f"const o = 'sk-proj-1234567890abcdefghijklmno';\n"
                f"const j = '{hdr}.{srv}.signature12345';\n"
            )
            fails = [f for f in check.check_repo(root) if f.severity == "FAIL"]
            self.assertEqual(len(fails), 3, fails)

    def test_detects_open_write_rls_policy_allows_select(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "policies.sql").write_text(
                "CREATE TABLE public.posts (id int);\n"
                "ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY public_read ON public.posts FOR SELECT USING (true);\n"
                "CREATE POLICY dev_all ON public.posts FOR ALL USING (true) WITH CHECK (true);\n"
            )
            warns = [f for f in check.check_repo(root) if f.severity == "WARN"]
            self.assertEqual(len(warns), 1, warns)
            self.assertIn("dev_all", warns[0].title)

    def test_broken_symlink_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dangling.ts").symlink_to(root / "missing.ts")
            (root / "client.ts").write_text("const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n")
            self.assertEqual([f.rule for f in check.check_repo(root) if f.rule], ["SR-SEC-001"])

    def test_env_gitignore_uses_patterns_not_substring(self) -> None:
        cases = {".env*.local\n": [".env"], ".env*\n": [], "/.env\n.env.local\n": [], "# .env\n": [".env", ".env.local"]}
        for gitignore, expected in cases.items():
            with self.subTest(gitignore), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _write(root, {".gitignore": gitignore, ".env": "A=1\n", ".env.local": "A=1\n"})
                hits = sorted(f.location for f in check.check_repo(root) if f.rule == "SR-SEC-003")
                self.assertEqual(hits, expected)

    def test_ai_provider_key_in_public_env_var(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "chat.tsx").write_text(
                "const a = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n"
                "const b = import.meta.env.VITE_ANTHROPIC_API_KEY;\n"
                "const ok = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY + process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n"
            )
            self.assertEqual([f.line for f in check.check_repo(root) if f.rule == "SR-SEC-001"], [1, 2])

    def test_stripe_webhook_with_subscription_events_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {"app/api/webhooks/stripe/route.ts": (
                "import Stripe from 'stripe';\n"
                "export async function POST(req: Request) {\n"
                "  const event = await req.json();\n"
                "  if (event.type === 'customer.subscription.updated') grantPro(event);\n"
                "}\n"
            )})
            self.assertEqual([f.rule for f in check.check_repo(root) if f.rule], ["SR-PAY-001"])

    def test_only_real_test_files_are_skipped(self) -> None:
        leak = "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n"
        names = ["latest-posts.ts", "inspector.tsx", "contest.ts", "a.test.ts", "b.spec.js", "test_c.py", "d_test.py"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {n: leak for n in names})
            hits = sorted(f.location for f in check.check_repo(root) if f.rule == "SR-SEC-001")
        self.assertEqual(hits, ["contest.ts", "inspector.tsx", "latest-posts.ts"])

    def test_quoted_identifiers_and_alter_if_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dump.sql").write_text(
                'CREATE TABLE IF NOT EXISTS "public"."profiles" (id int);\n'
                'ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;\n'
                "CREATE TABLE public.notes (id int);\n"
                "ALTER TABLE IF EXISTS ONLY public.notes ENABLE ROW LEVEL SECURITY;\n"
                'CREATE TABLE "public"."invoices" (id int);\n'
            )
            hits = [f.title for f in check.check_repo(root) if f.rule == "SR-SUPA-001"]
        self.assertEqual(hits, ["SQL table `invoices` has no ENABLE ROW LEVEL SECURITY statement"])

    def test_open_policy_name_and_service_role_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "p.sql").write_text(
                "CREATE TABLE t (id int);\nALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
                'create policy "Service role full access" on t for all to service_role using (true) with check (true);\n'
                'create policy "Anyone can update" on t for update to anon, service_role using (true);\n'
            )
            hits = [f.title for f in check.check_repo(root) if f.rule == "SR-SUPA-002"]
        self.assertEqual(hits, ["Permissive write RLS policy `Anyone can update` uses USING/WITH CHECK (true)"])


class TestShipReadyRules(unittest.TestCase):
    def test_every_rule_has_a_fixture(self) -> None:
        covered = set(REPO_FIXTURES) | set(HEADER_FIXTURES) | {"SR-SUPA-004", "SR-WEB-007"}
        self.assertEqual(covered, set(check.RULES))

    def test_rules_json_matches_registry(self) -> None:
        on_disk = (Path(__file__).parent / "rules.json").read_text()
        self.assertEqual(on_disk, check.rules_json(), "regenerate with: python3 check.py --dump-rules > rules.json")
        for r in json.loads(on_disk):
            self.assertEqual(r["url"], f"https://shipmate.agency/rules/{r['slug']}/")
            self.assertIn(r["severity"], {"high", "medium", "low"})

    def test_repo_fixture_per_rule(self) -> None:
        for rule_id, files in REPO_FIXTURES.items():
            with self.subTest(rule_id), tempfile.TemporaryDirectory() as tmp:
                _write(Path(tmp), files)
                hits = [f for f in check.check_repo(Path(tmp)) if f.rule]
                self.assertEqual({f.rule for f in hits}, {rule_id}, hits)
                if rule_id in REPO_FIXTURE_LINES:
                    self.assertEqual(hits[0].line, REPO_FIXTURE_LINES[rule_id])

    def test_header_fixture_per_rule(self) -> None:
        with _offline(_fake_site(GOOD_HEADERS)):
            self.assertEqual([f.rule for f in check.check_url("https://example.com") if f.rule], [])
        for rule_id, header in HEADER_FIXTURES.items():
            with self.subTest(rule_id), _offline(_fake_site({k: v for k, v in GOOD_HEADERS.items() if k != header})):
                self.assertEqual([f.rule for f in check.check_url("https://example.com") if f.rule], [rule_id])

    def test_exposed_dotfile_over_http(self) -> None:
        with _offline(_fake_site(GOOD_HEADERS, {"/.git/HEAD": "ref: refs/heads/main\n"})):
            hits = [f for f in check.check_url("https://example.com") if f.rule]
        self.assertEqual([(f.rule, f.location) for f in hits], [("SR-WEB-007", "https://example.com/.git/HEAD")])

    def test_supabase_public_schema(self) -> None:
        spec = json.dumps({"paths": {"/": {}, "/profiles": {}, "/rpc/fn": {}}})
        with _offline(lambda url, **kw: (200, {}, spec)):
            hits = check.check_supabase("https://abc.supabase.co", "anon")
        self.assertEqual([f.rule for f in hits], ["SR-SUPA-004"])
        self.assertIn("profiles", hits[0].detail)


class TestShipReadyCli(unittest.TestCase):
    def _repo(self, rule_id: str) -> tempfile.TemporaryDirectory:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        _write(Path(tmp.name), REPO_FIXTURES[rule_id])
        return tmp.name

    def test_sarif_structure(self) -> None:
        root = self._repo("SR-SEC-001")
        _write(Path(root), REPO_FIXTURES["SR-SUPA-001"])
        code, out = _run(["check", root, "--format", "sarif"])
        self.assertEqual(code, 1)
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("sarif-2.1.0", sarif["$schema"])
        run = sarif["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "ShipReady")
        rule_ids = [r["id"] for r in driver["rules"]]
        self.assertEqual(rule_ids, list(check.RULES))
        for r in driver["rules"]:
            self.assertEqual(r["helpUri"], check.RULES[r["id"]].url)
            self.assertIn("text", r["shortDescription"])
        self.assertEqual(len(run["results"]), 2)
        for res in run["results"]:
            self.assertIn(res["ruleId"], rule_ids)
            self.assertEqual(rule_ids[res["ruleIndex"]], res["ruleId"])
            self.assertIn(res["level"], {"error", "warning", "note"})
            self.assertTrue(res["message"]["text"])
            loc = res["locations"][0]["physicalLocation"]
            self.assertTrue(loc["artifactLocation"]["uri"].endswith((".ts", ".sql")))
            self.assertEqual(loc["region"]["startLine"], 2)
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_sarif_scan_error_is_a_notification(self) -> None:
        code, out = _run(["check", "/no/such/dir", "--format", "sarif"])
        self.assertEqual(code, 1)
        run = json.loads(out)["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertFalse(run["invocations"][0]["executionSuccessful"])

    def test_md_format(self) -> None:
        code, out = _run(["check", self._repo("SR-SEC-001"), "--format", "md"])
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("<!-- shipready -->\n## ShipReady by Shipmate"))
        self.assertIn("| Severity | Rule | Finding | Location |", out)
        self.assertIn("[SR-SEC-001](https://shipmate.agency/rules/secret-in-public-env-var/)", out)
        self.assertIn("`client.ts:2`", out)
        self.assertIn(check.LOCKDOWN_LINE, out)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn("No issues found.", _run(["check", tmp, "--format", "md"])[1])

    def test_text_ends_with_rule_links_and_lockdown(self) -> None:
        _, out = _run(["check", self._repo("SR-PAY-001")])
        lines = out.rstrip("\n").splitlines()
        self.assertEqual(lines[-1], check.LOCKDOWN_LINE)
        self.assertIn("SR-PAY-001  https://shipmate.agency/rules/stripe-webhook-no-signature-check/", out)

    def test_exit_codes_and_fail_on(self) -> None:
        medium = self._repo("SR-SUPA-001")
        high = self._repo("SR-SEC-002")
        self.assertEqual(_run(["check", medium])[0], 0)
        self.assertEqual(_run(["check", medium, "--fail-on", "medium"])[0], 1)
        self.assertEqual(_run(["check", medium, "--fail-on", "low"])[0], 1)
        self.assertEqual(_run(["check", high])[0], 1)
        self.assertEqual(_run(["check", high, "--fail-on", "none"])[0], 0)
        self.assertEqual(_run(["--fail-on", "none", "check", high])[0], 0)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_run(["check", tmp, "--fail-on", "low"])[0], 0)

    def test_old_flags_still_work(self) -> None:
        root = self._repo("SR-SEC-002")
        code, out = _run(["--repo", root, "--json"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual([d["rule"] for d in data if d["rule"]], ["SR-SEC-002"])
        self.assertEqual(set(data[0]) >= {"area", "severity", "title", "detail", "location"}, True)
        self.assertEqual(_run(["check", root, "--json"])[1], out)
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(_run(["--supabase-url", "https://abc.supabase.co"])[0], 2)
        with _offline(_fake_site(GOOD_HEADERS)):
            self.assertEqual(_run(["--url", "https://example.com"])[0], 0)
        self.assertEqual(_run([])[0], 2)

    def test_url_subcommand_offline(self) -> None:
        with _offline(_fake_site({})):
            code, out = _run(["url", "https://example.com", "--format", "json"])
        self.assertEqual(code, 0)  # missing headers are medium/low
        rules = {d["rule"] for d in json.loads(out) if d["rule"]}
        self.assertEqual(rules, set(HEADER_FIXTURES))

    def test_url_subcommand_keeps_public_host_guard(self) -> None:
        for bad in ["http://localhost:3000", "http://127.0.0.1:8080", "ftp://example.com"]:
            with mock.patch.object(check, "_fetch", side_effect=AssertionError("must not fetch")):
                code, out = _run(["url", bad])
            self.assertEqual(code, 1, bad)
            self.assertIn("Invalid or non-public target URL", out)

    def test_dump_rules(self) -> None:
        code, out = _run(["--dump-rules"])
        self.assertEqual((code, out), (0, check.rules_json()))


if __name__ == "__main__":
    unittest.main()
