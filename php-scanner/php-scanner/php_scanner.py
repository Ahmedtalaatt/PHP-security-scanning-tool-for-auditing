"""Talaat PHP Security Auditing Tool from the OWASP Top 10 vulnerabilities
Scans PHP files for: SQL Injection, XSS and Cryptographic Failures.
Usage:  python php_scanner.py <folder_or_file>
"""
import argparse
import re
import sys
from pathlib import Path

from colorama import Fore, Style, init  # open-source library: coloured terminal output

init(autoreset=True)

USER_INPUT = r"\$_(GET|POST|REQUEST|COOKIE)"

# Custom scanning logic: (issue, OWASP category, regex, short fix)
RULES = [
    ("SQL Injection", "A03 Injection",
     rf"(mysqli_query|mysql_query|->query)\s*\(.*({USER_INPUT}|\$\w+\s*\.|\"[^\"]*\$\w+)",
     "Use prepared statements (bind_param / PDO) instead of building queries with variables."),
    ("XSS", "A03 Injection",
     rf"^(?!.*htmlspecialchars).*\b(echo|print)\b.*{USER_INPUT}",
     "Escape output with htmlspecialchars() before printing user input."),
    ("Cryptographic Failure", "A02 Cryptographic Failures",
     r"\b(md5|sha1|crc32)\s*\(",
     "Use password_hash() / password_verify() for passwords; avoid MD5 and SHA-1."),
    ("Cryptographic Failure", "A02 Cryptographic Failures",
     r"(?i)\$(password|passwd|secret|api_key|key)\s*=\s*['\"][^'\"]+['\"]",
     "Do not hard-code secrets; load them from environment variables or a vault."),
    ("Cryptographic Failure", "A02 Cryptographic Failures",
     r"(?i)(MCRYPT_DES|DES-ECB|AES-128-ECB|mcrypt_)",
     "Use modern encryption such as AES-256-GCM via openssl_encrypt()."),
]


def scan_file(path):
    findings = []
    lines = path.read_text(errors="ignore").splitlines()
    for number, line in enumerate(lines, start=1):
        if line.strip().startswith(("//", "#", "*")):
            continue
        for issue, owasp, pattern, fix in RULES:
            if re.search(pattern, line):
                findings.append((path, number, issue, owasp, line.strip(), fix))
    return findings


def collect_files(target):
    target = Path(target)
    if target.is_file():
        return [target]
    return sorted(target.rglob("*.php"))


def main():
    parser = argparse.ArgumentParser(description="PHP OWASP Top 10 security scanner")
    parser.add_argument("target", help="PHP file or project folder to scan")
    parser.add_argument("-o", "--output", default="report.txt", help="report file name")
    args = parser.parse_args()

    files = collect_files(args.target)
    if not files:
        print("No PHP files found.")
        sys.exit(1)

    findings = []
    for f in files:
        findings += scan_file(f)

    report = []
    for path, number, issue, owasp, code, fix in findings:
        print(f"{Fore.RED}[{issue}]{Style.RESET_ALL} {path}:{number}  ({owasp})")
        print(f"    Code: {code}")
        print(f"    Fix : {fix}")
        report.append(f"[{issue}] {path}:{number} ({owasp})\n    Code: {code}\n    Fix : {fix}\n")

    counts = {}
    for f in findings:
        counts[f[2]] = counts.get(f[2], 0) + 1
    summary = [f"Files scanned: {len(files)}", f"Total findings: {len(findings)}"]
    summary += [f"  {k}: {v}" for k, v in counts.items()]

    print(f"\n{Fore.CYAN}=== SUMMARY ==={Style.RESET_ALL}")
    print("\n".join(summary))
    Path(args.output).write_text("SCAN REPORT\n\n" + "\n".join(report) + "\n=== SUMMARY ===\n" + "\n".join(summary) + "\n")
    print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
