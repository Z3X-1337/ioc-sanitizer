import unittest

from ioc_sanitizer import defang, extract_iocs, refang


class IocSanitizerTests(unittest.TestCase):
    def test_defang_and_refang_url(self):
        original = "https://example.com/login"
        safe = defang(original)
        self.assertEqual(safe, "hxxps://example[.]com/login")
        self.assertEqual(refang(safe), original)

    def test_extract_iocs(self):
        text = "IP 203.0.113.7 visited http://example.com and sent test@example.com"
        result = extract_iocs(text)
        self.assertIn("203.0.113.7", result["ipv4"])
        self.assertIn("http://example.com", result["urls"])
        self.assertIn("test@example.com", result["emails"])


if __name__ == "__main__":
    unittest.main()
