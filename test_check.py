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


if __name__ == "__main__":
    unittest.main()
