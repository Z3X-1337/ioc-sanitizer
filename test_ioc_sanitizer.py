import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ioc_sanitizer import defang, extract_indicators, group_indicators, refang, render_text


class IocSanitizerTests(unittest.TestCase):
    def test_defang_and_refang_url_email_and_ip(self):
        self.assertEqual(defang("https://example.com/login"), "hxxps://example[.]com/login")
        self.assertEqual(defang("analyst@example.com"), "analyst[@]example[.]com")
        self.assertEqual(defang("203.0.113.7"), "203[.]0[.]113[.]7")
        self.assertEqual(refang("hxxps://example[.]com/login"), "https://example.com/login")
        self.assertEqual(refang("analyst[@]example[.]com"), "analyst@example.com")

    def test_extracts_expected_indicator_types(self):
        text = (
            "Alert from 198.51.100.24 for admin@example-security.com. "
            "Link: https://login.example-security.com/session?id=100. "
            "SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        indicators = extract_indicators(text)
        by_type = {item.type: item.value for item in indicators}

        self.assertEqual(by_type["ipv4"], "198.51.100.24")
        self.assertEqual(by_type["email"], "admin@example-security.com")
        self.assertEqual(by_type["url"], "https://login.example-security.com/session?id=100")
        self.assertEqual(by_type["sha256"], "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

    def test_deduplicates_case_insensitive_domains_and_urls(self):
        indicators = extract_indicators("Visit HTTPS://Example.com/path then https://example.com/path")
        urls = [item for item in indicators if item.type == "url"]
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0].value, "HTTPS://Example.com/path")

    def test_does_not_duplicate_domain_inside_url_or_email(self):
        indicators = extract_indicators("https://portal.example.org/login user@example.org example.net")
        grouped = group_indicators(indicators)
        domains = [item["value"] for item in grouped["domain"]]

        self.assertNotIn("portal.example.org", domains)
        self.assertNotIn("example.org", domains)
        self.assertEqual(domains, ["example.net"])

    def test_grouped_output_contains_all_supported_keys(self):
        grouped = group_indicators(extract_indicators("203.0.113.8 test@example.com"))
        self.assertEqual(set(grouped), {"url", "email", "ipv4", "sha256", "sha1", "md5", "domain"})
        self.assertEqual(grouped["ipv4"][0]["defanged"], "203[.]0[.]113[.]8")

    def test_text_renderer_has_stable_csv_header(self):
        output = render_text(extract_indicators("203.0.113.9"))
        self.assertTrue(output.startswith("type,value,defanged\n"))
        self.assertIn("ipv4,203.0.113.9,203[.]0[.]113[.]9", output)

    def test_cli_extract_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.txt"
            sample.write_text("Host 203.0.113.10", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "ioc_sanitizer.py", "extract", str(sample)],
                check=True,
                capture_output=True,
                text=True,
            )
        payload = json.loads(result.stdout)
        self.assertEqual(payload[0]["type"], "ipv4")
        self.assertEqual(payload[0]["value"], "203.0.113.10")


if __name__ == "__main__":
    unittest.main()
