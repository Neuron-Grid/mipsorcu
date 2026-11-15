import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "check-cargo-vet-exemptions.py"
SPEC = importlib.util.spec_from_file_location("cargo_vet_exemptions", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CargoVetExemptionsTest(unittest.TestCase):
    def run_config(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(text, encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = CHECKER.check(path)
            return result, stdout.getvalue(), stderr.getvalue()

    def test_empty_exemptions_pass(self):
        result, stdout, _ = self.run_config("[cargo-vet]\nversion = \"0.10\"\n")
        self.assertEqual(result, 0)
        self.assertIn("no exemptions", stdout)

    def test_all_exemptions_are_reported_and_fail(self):
        result, stdout, _ = self.run_config(
            '[[exemptions.alpha]]\nversion = "1.2.3"\ncriteria = "safe-to-run"\n'
            '[[exemptions.beta]]\nversion = "2.0.0"\ncriteria = ["safe-to-deploy"]\n'
        )
        self.assertEqual(result, 1)
        self.assertIn("contains 2 exemption(s)", stdout)
        self.assertIn("alpha@1.2.3", stdout)
        self.assertIn("beta@2.0.0", stdout)

    def test_invalid_or_unparseable_config_fails_closed(self):
        for config in ("[[exemptions.alpha]]\nversion = 1\n", "[exemptions]\nalpha = true\n"):
            with self.subTest(config=config):
                result, _, stderr = self.run_config(config)
                self.assertEqual(result, 1)
                self.assertIn("ERROR:", stderr)


if __name__ == "__main__":
    unittest.main()
