#!/usr/bin/env python3
"""Tests for faspex_scanner. Run: python3 -m unittest discover -s tests -v"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from faspex_scanner import (
    CVE_ID,
    FIXED_IMAGE_STRING,
    detect_local,
    format_version,
    grade,
    parse_version,
    read_version_file,
)


class TestParsing(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_version("5.0.19"), ((5, 0, 19), None))
        self.assertEqual(parse_version("5.0.13"), ((5, 0, 13), None))
        self.assertEqual(parse_version("v5.0.18"), ((5, 0, 18), None))
        self.assertEqual(parse_version("  5.0.19  "), ((5, 0, 19), None))

    def test_rpm_build_ignored(self):
        self.assertEqual(parse_version("5.0.13.8706"), ((5, 0, 13), None))
        self.assertEqual(parse_version("5.0.19.8706"), ((5, 0, 19), None))

    def test_fix_pack_forms(self):
        self.assertEqual(parse_version("5.0.19 PL1"), ((5, 0, 19), 1))
        self.assertEqual(parse_version("5.0.19 PL0"), ((5, 0, 19), 0))
        self.assertEqual(parse_version("5.0.19 PL2"), ((5, 0, 19), 2))
        self.assertEqual(parse_version("5.0.19 Fix Pack 1"), ((5, 0, 19), 1))
        self.assertEqual(
            parse_version("5.0.19 (1ce4b13, Fix Pack: 1)"), ((5, 0, 19), 1)
        )
        self.assertEqual(
            parse_version(FIXED_IMAGE_STRING), ((5, 0, 19), 1)
        )

    def test_bare_and_garbage(self):
        self.assertIsNone(parse_version("5.0"))
        self.assertIsNone(parse_version("5"))
        self.assertIsNone(parse_version("hello"))
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version(None))


class TestGrading(unittest.TestCase):
    def test_vulnerable_range(self):
        for version in ("5.0.0", "5.0.13", "5.0.13.8706", "5.0.18",
                        "5.0.18.9999", "v5.0.17"):
            with self.subTest(version=version):
                result = grade(version)
                self.assertEqual(result["grade"], "VULNERABLE")
                self.assertIn(CVE_ID, result["note"])

    def test_bare_5019_is_unknown_not_clean(self):
        # The PL1 trap: bare 5.0.19 does not prove Fix Pack 1.
        for version in ("5.0.19", "5.0.19.8706", "v5.0.19"):
            with self.subTest(version=version):
                result = grade(version)
                self.assertEqual(result["grade"], "UNKNOWN")
                self.assertIn("PL1", result["note"])

    def test_fix_pack_zero_is_vulnerable(self):
        self.assertEqual(grade("5.0.19 PL0")["grade"], "VULNERABLE")
        self.assertEqual(
            grade("5.0.19 (abc1234, Fix Pack: 0)")["grade"], "VULNERABLE"
        )

    def test_patched(self):
        for version in ("5.0.19 PL1", "5.0.19 Fix Pack 1",
                        FIXED_IMAGE_STRING, "5.0.19 PL2", "5.0.20",
                        "5.1.0"):
            with self.subTest(version=version):
                result = grade(version)
                self.assertEqual(result["grade"], "PATCHED")

    def test_out_of_table_is_unknown_not_clean(self):
        for version in ("4.4.0", "4.0.3", "3.9.0", "6.0.0"):
            with self.subTest(version=version):
                result = grade(version)
                self.assertEqual(result["grade"], "UNKNOWN")

    def test_unparseable_is_unknown(self):
        for version in ("5.0", "garbage", ""):
            with self.subTest(version=version):
                self.assertEqual(grade(version)["grade"], "UNKNOWN")

    def test_format_version(self):
        self.assertEqual(format_version((5, 0, 19)), "5.0.19")


class TestLocalDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _detect(self, **kwargs):
        kwargs.setdefault("rpm_bin", "definitely-not-rpm")
        kwargs.setdefault("docker_bin", "definitely-not-docker")
        return detect_local(self.root, **kwargs)

    def test_version_txt(self):
        with open(os.path.join(self.root, "version.txt"), "w") as fh:
            fh.write("5.0.19 PL1\n")
        version, source = self._detect()
        self.assertEqual(version, "5.0.19 PL1")
        self.assertIn("version.txt", source)

    def test_version_file_fallback(self):
        with open(os.path.join(self.root, "VERSION"), "w") as fh:
            fh.write("5.0.19 (1ce4b13, Fix Pack: 1)\n")
        version, source = self._detect()
        self.assertEqual(version, "5.0.19 (1ce4b13, Fix Pack: 1)")
        self.assertIn("VERSION", source)

    def test_version_txt_wins_over_version(self):
        with open(os.path.join(self.root, "version.txt"), "w") as fh:
            fh.write("5.0.18\n")
        with open(os.path.join(self.root, "VERSION"), "w") as fh:
            fh.write("5.0.19 PL1\n")
        version, _ = self._detect()
        self.assertEqual(version, "5.0.18")

    def test_unparseable_file_is_skipped(self):
        with open(os.path.join(self.root, "version.txt"), "w") as fh:
            fh.write("not a version\n")
        with self.assertRaises(ValueError):
            self._detect()

    def test_empty_dir_is_error(self):
        with self.assertRaises(ValueError):
            self._detect()

    def test_missing_dir_is_error(self):
        with self.assertRaises(ValueError):
            detect_local(os.path.join(self.root, "nope"),
                         rpm_bin="definitely-not-rpm",
                         docker_bin="definitely-not-docker")


class TestVersionFile(unittest.TestCase):
    def test_first_line(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("5.0.19 (1ce4b13, Fix Pack: 1)\nsecond line\n")
            path = fh.name
        try:
            self.assertEqual(read_version_file(path),
                             "5.0.19 (1ce4b13, Fix Pack: 1)")
        finally:
            os.unlink(path)

    def test_missing_and_empty(self):
        with self.assertRaises(ValueError):
            read_version_file("/nonexistent/version.txt")
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                read_version_file(path)
        finally:
            os.unlink(path)


class TestCLI(unittest.TestCase):
    def run_cli(self, *argv):
        script = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "faspex_scanner.py",
        )
        return subprocess.run(
            [sys.executable, script, *argv],
            capture_output=True, text=True,
        )

    def test_vulnerable_exit_2(self):
        proc = self.run_cli("--version", "5.0.18")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("VULNERABLE", proc.stdout)

    def test_patched_exit_0(self):
        proc = self.run_cli("--version", FIXED_IMAGE_STRING)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PATCHED", proc.stdout)

    def test_unknown_exit_0_but_not_clean(self):
        proc = self.run_cli("--version", "5.0.19")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("UNKNOWN", proc.stdout)
        self.assertIn("PL1", proc.stdout)

    def test_json_output(self):
        proc = self.run_cli("--version", "5.0.18", "--json")
        self.assertEqual(proc.returncode, 2)
        data = json.loads(proc.stdout)
        self.assertEqual(data["grade"], "VULNERABLE")
        self.assertEqual(data["version"], "5.0.18")

    def test_list(self):
        proc = self.run_cli("--list")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("5.0.19 PL1", proc.stdout)
        self.assertIn("12 November 2026", proc.stdout)

    def test_no_args_errors(self):
        proc = self.run_cli()
        self.assertNotEqual(proc.returncode, 0)

    def test_inventory_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sites.json")
            with open(path, "w") as fh:
                json.dump([
                    {"label": "a", "version": "5.0.18"},
                    {"label": "b", "version": "5.0.19 PL1"},
                ], fh)
            proc = self.run_cli("--inventory-json", path)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("[a]", proc.stdout)
            self.assertIn("VULNERABLE", proc.stdout)
            self.assertIn("PATCHED", proc.stdout)

    def test_inventory_all_patched_exit_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sites.json")
            with open(path, "w") as fh:
                json.dump([{"label": "b", "version": "5.0.19 PL1"}], fh)
            proc = self.run_cli("--inventory-json", path)
            self.assertEqual(proc.returncode, 0)

    def test_local_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "version.txt"), "w") as fh:
                fh.write("5.0.18\n")
            proc = self.run_cli("--local", tmp)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("VULNERABLE", proc.stdout)
            self.assertIn("version.txt", proc.stdout)

    def test_local_missing_dir_is_error(self):
        proc = self.run_cli("--local", "/nonexistent/faspex")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("error", proc.stderr)


if __name__ == "__main__":
    unittest.main()
