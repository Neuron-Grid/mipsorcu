import importlib.util
import unittest

SPEC = importlib.util.spec_from_file_location("ci_policy", "scripts/check-ci-policy.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class ProtectedPathTests(unittest.TestCase):
    def test_protects_ci_scripts_audit_configuration_and_tests(self):
        for path in (
            ".github/workflows/ci.yml",
            ".github/actions/setup/action.yml",
            "AGENTS.md",
            "subdir/AGENTS.md",
            "CODEOWNERS",
            ".github/CODEOWNERS",
            "supabase/config.toml",
            "scripts/check-core.sh",
            "scripts/e2e/run-all.sh",
            "scripts/failure-injection/01-no-auth.sh",
            "tests/authorization.rs",
            "supabase/tests/ledger.sql",
            "supply-chain/audits.toml",
            ".cargo/config.toml",
            "Cargo.toml",
            "Cargo.lock",
            "deny.toml",
        ):
            with self.subTest(path=path):
                self.assertTrue(POLICY.protected(path))

    def test_renamed_protected_file_remains_protected(self):
        paths = POLICY.response_paths([{"filename": "README.md", "previous_filename": "scripts/check-core.sh"}])
        self.assertTrue(any(POLICY.protected(path) for path in paths))

    def test_requires_event_revision_to_match_pull_request(self):
        pr = {"state": "open", "base": {"sha": "base"}, "head": {"sha": "head"}}
        POLICY.verify_revision(pr, "base", "head")
        with self.assertRaisesRegex(ValueError, "revision changed"):
            POLICY.verify_revision(pr, "base", "new-head")

    def test_leaves_unrelated_application_changes_open(self):
        for path in ("src/server.rs", "README.md", "supabase/migrations/9999_feature.sql"):
            with self.subTest(path=path):
                self.assertFalse(POLICY.protected(path))


if __name__ == "__main__":
    unittest.main()
