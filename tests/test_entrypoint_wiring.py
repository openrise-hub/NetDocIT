import pathlib
import tomllib
import unittest


class TestEntrypointWiring(unittest.TestCase):
    def test_project_script_targets_src_main(self):
        pyproject_path = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        scripts = data.get("project", {}).get("scripts", {})
        self.assertEqual(scripts.get("netdocit"), "src.main:main")


if __name__ == "__main__":
    unittest.main()
