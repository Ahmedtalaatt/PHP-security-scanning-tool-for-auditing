# PHP Security Scanner 🔍

A small command-line tool I built in Python that reads PHP code and
points out common security mistakes from the OWASP Top 10.
It scans SQL injection, cross-site scripting(XSS) and cryptographic failures

Think of it like a spell-checker, but for security bugs that may be found in a PHP code.

## What does it look for?


| **SQL Injection**| --> User input goes straight into a database query | `mysqli_query($conn, "... WHERE id = $id")` |
| **XSS** |--> User input is printed on the page without cleaning it | `echo $_GET['name'];` |
| **Cryptographic Failures** | --> Weak or missing protection for sensitive data | `md5($password)` or a hard-coded password |

## How does it work?

1. You give it a PHP file or a folder.
2. It reads every `.php` file line by line.
3. If a line matches a risky pattern, it flags it.
4. You get the file name, the line number, the risky code, and a tip on how to fix it.
5. At the end it prints a summary and saves everything to `report.txt`.

## Try it

You need Python installed. Then:

```
pip install -r requirements.txt
python php_scanner.py test_files
```

Scan your own stuff:

```
python php_scanner.py path\to\your\file.php
python php_scanner.py path\to\your\project
python php_scanner.py path\to\your\project -o my_report.txt
```

## What's in this repo?

```
php_scanner.py     the scanner itself
test_scanner.py    tests to check the scanner works
test_files/        PHP files with bugs on purpose (plus one safe file)
requirements.txt   libraries needed (just colorama for colors)
```

## Running the tests

```
python test_scanner.py
```

Each test scans a file with one planted bug and checks the scanner
finds it. One test scans `safe.php` and checks the scanner stays quiet.
If you see `OK`, everything works.

## Good to know

- It matches patterns, so it can sometimes flag safe code or miss
  tricky bugs. Always double-check what it finds.
- It's a learning project, not a replacement for a real security review.
- The vulnerable files in `test_files/` are fake samples, made on purpose.
- Only scan code you own or have permission to test.

## Built with

- Python (`argparse`, `re`, `pathlib`)
- [colorama](https://pypi.org/project/colorama/) for colored output
