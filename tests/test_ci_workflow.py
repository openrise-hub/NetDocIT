import pathlib
import unittest


class TestCiWorkflow(unittest.TestCase):
    def test_ci_contains_non_blocking_typecheck_job(self):
        workflow = (pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "python-ci.yml").read_text(encoding="utf-8")
        self.assertIn("typecheck:", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("python -m pyright", workflow)


if __name__ == "__main__":
    unittest.main()
