import unittest
from pathlib import Path
from php_scanner import scan_file

D = Path("test_files")

class TestScanner(unittest.TestCase):
    def issues(self, name):
        return {f[2] for f in scan_file(D / name)}

    def test_sqli(self):
        self.assertIn("SQL Injection", self.issues("vulnerable_sqli.php"))

    def test_xss(self):
        self.assertIn("XSS", self.issues("vulnerable_xss.php"))

    def test_crypto(self):
        self.assertIn("Cryptographic Failure", self.issues("vulnerable_crypto.php"))

    def test_safe_file_has_no_findings(self):
        self.assertEqual(scan_file(D / "safe.php"), [])

if __name__ == "__main__":
    unittest.main()
