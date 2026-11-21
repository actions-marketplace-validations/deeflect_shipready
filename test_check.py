import tempfile
import unittest
from pathlib import Path

import check


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


if __name__ == "__main__":
    unittest.main()
