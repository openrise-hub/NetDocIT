import pathlib
import re
import unittest


class TestEntrypointWiring(unittest.TestCase):
    def test_project_script_targets_src_main(self):
        pyproject_path = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
        text = pyproject_path.read_text(encoding="utf-8")
        match = re.search(r'netdocit\s*=\s*"src\.main:main"', text)
        self.assertIsNotNone(match, "entry point 'netdocit = \"src.main:main\"' not found in pyproject.toml")


if __name__ == "__main__":
    unittest.main()
