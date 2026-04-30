import json
import os
import tempfile
import unittest
from unittest.mock import patch

from src.backend.secrets import resolve_snmp_credentials


class TestSecretsLoader(unittest.TestCase):
    def test_loads_snmp_credentials_from_external_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            json.dump({
                "credentials": {"snmp": ["alpha", "beta"]},
                "metadata": {"rotation_due": "2026-06-01T00:00:00"},
            }, handle)
            secrets_path = handle.name

        try:
            with patch.dict(os.environ, {"NETDOCIT_SECRETS_FILE": secrets_path}, clear=False):
                credentials, audit = resolve_snmp_credentials(
                    override=None,
                    config={"credentials": {"snmp": ["legacy"]}},
                )

            self.assertEqual(credentials, ["alpha", "beta"])
            self.assertEqual(audit["source"], "external_file")
            self.assertTrue(audit["loaded"])
            self.assertEqual(audit["credential_count"], 2)
            self.assertIsNone(audit["load_error"])
            self.assertEqual(audit["rotation_due"], "2026-06-01T00:00:00")
        finally:
            os.unlink(secrets_path)

    def test_production_requires_external_file(self):
        with patch.dict(os.environ, {"NETDOCIT_ENV": "production"}, clear=False):
            credentials, audit = resolve_snmp_credentials(override=None, config={})

        self.assertEqual(credentials, [])
        self.assertEqual(audit["source"], "external_file")
        self.assertFalse(audit["loaded"])
        self.assertEqual(audit["credential_count"], 0)
        self.assertEqual(audit["load_error"], "secrets_file_required_in_production")

    def test_dev_mode_uses_legacy_config_fallback(self):
        with patch.dict(os.environ, {}, clear=True):
            credentials, audit = resolve_snmp_credentials(
                override=None,
                config={"credentials": {"snmp": ["legacy-public"]}},
            )

        self.assertEqual(credentials, ["legacy-public"])
        self.assertEqual(audit["source"], "legacy_config")
        self.assertTrue(audit["loaded"])
        self.assertEqual(audit["credential_count"], 1)
        self.assertIsNone(audit["load_error"])

    def test_dev_mode_uses_default_guesses_when_legacy_is_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            credentials, audit = resolve_snmp_credentials(
                override=None,
                config={"credentials": {"snmp": []}},
            )

        self.assertEqual(credentials, ["public", "monitor", "read-only"])
        self.assertEqual(audit["source"], "dev_defaults")
        self.assertTrue(audit["loaded"])
        self.assertEqual(audit["credential_count"], 3)
        self.assertIsNone(audit["load_error"])

    def test_production_does_not_use_default_guesses(self):
        with patch.dict(os.environ, {"NETDOCIT_ENV": "production"}, clear=True):
            credentials, audit = resolve_snmp_credentials(
                override=None,
                config={"credentials": {"snmp": []}},
            )

        self.assertEqual(credentials, [])
        self.assertEqual(audit["source"], "external_file")
        self.assertFalse(audit["loaded"])
        self.assertEqual(audit["load_error"], "secrets_file_required_in_production")


if __name__ == "__main__":
    unittest.main()
