#!/usr/bin/env python3
"""Detection-only local triage for IBM Aspera Faspex CVE-2026-123218.

CVE-2026-123218 (CWE-863, incorrect authorization, CVSS 3.1 9.8) lets an
authorized Faspex user craft a specific message that bypasses user
authorization and gains full administrative privileges. IBM Aspera
Faspex 5.0.0 through 5.0.19 is affected; the fix is 5.0.19 PL1 (Fix
Pack 1), published 7 November 2026 in IBM security bulletin 7295921.
CISA added the flaw to the Known Exploited Vulnerabilities catalog on
9 November 2026 with a federal remediation deadline of 12 November
2026, which means CISA has evidence of active exploitation. IBM lists
no workaround, so patching is the only fix.

The trap this tool exists for: the fix is not "5.0.19", it is "5.0.19
PL1". A bare 5.0.19 does not prove Fix Pack 1 is installed, so it
grades UNKNOWN, not clean. IBM's own check for a patched deployment is
the faspex-core container image reading "5.0.19 (1ce4b13, Fix Pack: 1)".

This tool sends no traffic, probes no server, and sends no crafted
message. It only compares Faspex 5 version strings you supply, or a
version it reads from a local install, against the fixed release. A
VULNERABLE grade means the version is below the fix; it does not mean
the system was compromised, and a PATCHED grade does not prove it was
never attacked. If compromise is suspected, preserve evidence and audit
admin accounts before upgrading, because an upgrade alone does not undo
a created admin account or a stolen credential.

Usage:
    python3 faspex_scanner.py --version 5.0.18
    python3 faspex_scanner.py --version "5.0.19 (1ce4b13, Fix Pack: 1)"
    python3 faspex_scanner.py --local
    python3 faspex_scanner.py --local /opt/aspera/faspex
    python3 faspex_scanner.py --version-file version.txt
    python3 faspex_scanner.py --inventory-json sites.json
    python3 faspex_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error (missing argument, bad input). UNKNOWN does not change the
exit code, but it is not clean: an unparseable, bare, or out-of-table
version has not been cleared, it has simply not been graded.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

CVE_ID = "CVE-2026-123218"
# Affected range and fix, per IBM security bulletin 7295921 (published
# 7 November 2026) and corroborated by the CISA KEV entry (added
# 9 November 2026, due 12 November 2026) and the NVD record.
AFFECTED_MIN = (5, 0, 0)
AFFECTED_MAX = (5, 0, 19)
FIXED = (5, 0, 19)
FIXED_PACK = 1
# IBM's own check for a patched container deployment.
FIXED_IMAGE_STRING = "5.0.19 (1ce4b13, Fix Pack: 1)"
DEFAULT_LOCAL_ROOT = "/opt/aspera/faspex"

# A Faspex release is major.minor.patch with an optional fourth numeric
# segment (the RPM build, as in ibm-aspera-faspex-5.0.13.8706). The
# fourth segment is ignored for grading: a build number is not a fix
# pack. The fix pack, when present, rides along as "PL1", "Fix Pack 1",
# or "Fix Pack: 1", including inside the container image string.
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?")
_FIX_PACK_RE = re.compile(r"\b(?:fix\s*pack|pl)\s*:?\s*(\d+)", re.IGNORECASE)


def parse_version(text):
    """Return (version_tuple, fix_pack) or None for an unparseable string.

    Accepts an optional leading `v`, an optional fourth numeric segment
    (ignored), and an optional fix-pack marker. A bare `5.0` with no
    patch number cannot be graded and returns None.
    """
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    version = tuple(int(part) for part in match.groups()[:3])
    pack_match = _FIX_PACK_RE.search(text)
    fix_pack = int(pack_match.group(1)) if pack_match else None
    return version, fix_pack


def format_version(version):
    return ".".join(str(part) for part in version)


def grade(version_text):
    """Grade one version string against CVE-2026-123218.

    Returns a dict with grade, fixed, and note keys. Grades: PATCHED,
    VULNERABLE, UNKNOWN.
    """
    parsed = parse_version(version_text)
    if parsed is None:
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "note": f"version {version_text!r} does not parse as a Faspex "
            "release like 5.0.19 or 5.0.19 PL1; a bare 5.0 with no patch "
            "number cannot be graded, and is not clean",
        }
    version, fix_pack = parsed
    if version[0] != 5:
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "note": f"Faspex {version[0]}.x is outside the bulletin, which "
            "covers Faspex 5 only (5.0.0 through 5.0.19). It has not been "
            "cleared, only left ungraded; check it against IBM's guidance "
            "for that line, do not treat it as safe",
        }
    if version < AFFECTED_MIN:
        return {
            "grade": "UNKNOWN",
            "fixed": None,
            "note": f"{format_version(version)} is below the affected "
            "range, which starts at 5.0.0; that is not a clean grade, the "
            "install was not covered by the bulletin",
        }
    if version < FIXED:
        return {
            "grade": "VULNERABLE",
            "fixed": f"{format_version(FIXED)} PL{FIXED_PACK}",
            "note": f"vulnerable to {CVE_ID}; upgrade to "
            f"{format_version(FIXED)} PL{FIXED_PACK} or later, there is "
            "no workaround",
        }
    if version == FIXED:
        if fix_pack is None:
            return {
                "grade": "UNKNOWN",
                "fixed": f"{format_version(FIXED)} PL{FIXED_PACK}",
                "note": "bare 5.0.19 does not prove Fix Pack 1 is "
                "installed, and the fix is 5.0.19 PL1, not 5.0.19. A "
                "5.0.19 install without the fix pack is still "
                "vulnerable, so this has not been cleared, only left "
                "ungraded; confirm the faspex-core image reads "
                f"{FIXED_IMAGE_STRING!r}",
            }
        if fix_pack == 0:
            return {
                "grade": "VULNERABLE",
                "fixed": f"{format_version(FIXED)} PL{FIXED_PACK}",
                "note": f"Fix Pack 0 is the base 5.0.19 release, which is "
                f"still vulnerable to {CVE_ID}; upgrade to "
                f"{format_version(FIXED)} PL{FIXED_PACK} or later",
            }
        return {
            "grade": "PATCHED",
            "fixed": f"{format_version(FIXED)} PL{FIXED_PACK}",
            "note": f"at the fixed {format_version(FIXED)} "
            f"PL{fix_pack}; CISA KEV deadline was 12 November 2026, "
            "audit admin accounts for any privilege escalation that "
            "happened before the patch",
        }
    return {
        "grade": "PATCHED",
        "fixed": f"{format_version(FIXED)} PL{FIXED_PACK}",
        "note": f"later than the fixed {format_version(FIXED)} "
        f"PL{FIXED_PACK}; the fix is in the line, audit admin accounts "
        "for any privilege escalation that happened before the upgrade",
    }


def _read_first_line(path):
    try:
        text = Path(path).read_text(errors="replace").strip()
    except OSError:
        return None
    if not text:
        return None
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def _rpm_version(rpm_bin="rpm"):
    """Read the installed Faspex version from the RPM database, or None."""
    if shutil.which(rpm_bin) is None:
        return None, None
    try:
        proc = subprocess.run(
            [rpm_bin, "-q", "ibm-aspera-faspex"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    if proc.returncode != 0:
        return None, None
    output = proc.stdout.strip()
    match = re.match(r"ibm-aspera-faspex-(\d+\.\d+\.\d+(?:\.\d+)?)-", output)
    if not match:
        return None, None
    return match.group(1), "rpm -q ibm-aspera-faspex"


def _docker_versions(docker_bin="docker"):
    """Yield (version, source) for Faspex containers, if docker exists."""
    if shutil.which(docker_bin) is None:
        return
    try:
        proc = subprocess.run(
            [docker_bin, "ps", "--format", "{{.Names}} {{.Image}}"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return
    if proc.returncode != 0:
        return
    for line in proc.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        if "faspex" not in line.lower():
            continue
        for version_file in ("VERSION", "version.txt"):
            try:
                inner = subprocess.run(
                    [docker_bin, "exec", name, "cat",
                     f"/opt/aspera/faspex/{version_file}"],
                    capture_output=True, text=True, timeout=15,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if inner.returncode != 0:
                continue
            text = inner.stdout.strip().splitlines()
            if text and text[0].strip():
                yield text[0].strip(), (
                    f"docker exec {name} cat "
                    f"/opt/aspera/faspex/{version_file}"
                )
                break


def detect_local(path=DEFAULT_LOCAL_ROOT, rpm_bin="rpm",
                 docker_bin="docker"):
    """Read the installed Faspex 5 version from a local install.

    Tries, in order: version.txt / VERSION under the install root, the
    RPM database, then running faspex containers. Returns
    (version_string, source). Raises ValueError when no Faspex install
    is found: an undetected install has not been graded.
    """
    root = Path(path)
    if not root.is_dir():
        raise ValueError(f"local path {path} is not a directory")
    tried = []
    for version_file in ("version.txt", "VERSION"):
        candidate = root / version_file
        tried.append(str(candidate))
        text = _read_first_line(candidate) if candidate.is_file() else None
        if text and parse_version(text) is not None:
            return text, str(candidate)
    version, source = _rpm_version(rpm_bin)
    if version is not None:
        return version, source
    tried.append("rpm -q ibm-aspera-faspex")
    for version, source in _docker_versions(docker_bin):
        if parse_version(version) is not None:
            return version, source
    tried.append("docker ps (faspex containers)")
    raise ValueError(
        "no Faspex install detected; checked " + ", ".join(tried) +
        ". This tool grades the version on the host it runs on, or a "
        "version you supply with --version"
    )


def read_version_file(path):
    text = _read_first_line(path)
    if text is None:
        try:
            Path(path).read_text()
        except OSError as exc:
            raise ValueError(f"cannot read version file {path}: {exc}") from exc
        raise ValueError(f"version file {path} is empty")
    return text


def render(result, version_text, label=None, source=None):
    lines = []
    if label:
        lines.append(f"[{label}]")
    if source:
        lines.append(f"source:     {source}")
    lines.append(f"version:    {version_text}")
    lines.append(f"grade:      {result['grade']}")
    if result["fixed"]:
        lines.append(f"fixed in:   {result['fixed']}")
    lines.append(f"note:       {result['note']}")
    return "\n".join(lines)


def load_inventory(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read inventory {path}: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("inventory JSON must be a list of entries")
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("each inventory entry must be an object")
        if "version" not in entry and "local" not in entry:
            raise ValueError(
                "each inventory entry needs a 'version' or 'local' key"
            )
    return data


def grade_entry(entry):
    """Grade one inventory entry, resolving `local` paths to versions."""
    if "version" in entry:
        return entry["version"], None
    version, source = detect_local(entry["local"])
    return version, source


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for IBM Aspera Faspex "
                    "CVE-2026-123218 (CVSS 9.8, CISA KEV)."
    )
    parser.add_argument("--version", help="Faspex 5 version, e.g. 5.0.18 "
                        "or '5.0.19 (1ce4b13, Fix Pack: 1)'")
    parser.add_argument("--local", nargs="?", const=DEFAULT_LOCAL_ROOT,
                        help="detect the installed version under the "
                        "Faspex root (default /opt/aspera/faspex)")
    parser.add_argument("--version-file",
                        help="file holding the version, e.g. version.txt "
                        "or VERSION from a faspex-core container")
    parser.add_argument("--inventory-json",
                        help="JSON list of version/local entries")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--list", action="store_true",
                        help="print the advisory table")
    args = parser.parse_args(argv)

    if args.list:
        print(
            f"{CVE_ID}: Faspex 5 {format_version(AFFECTED_MIN)} through "
            f"{format_version(AFFECTED_MAX)} affected, fixed in "
            f"{format_version(FIXED)} PL{FIXED_PACK} and later"
        )
        print("container check: the faspex-core image must read "
              f"{FIXED_IMAGE_STRING!r}")
        print("CISA KEV: added 9 November 2026, federal due date "
              "12 November 2026, no workaround")
        return 0
    if args.inventory_json:
        try:
            entries = load_inventory(args.inventory_json)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        results = []
        vulnerable = False
        for entry in entries:
            try:
                version, source = grade_entry(entry)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            result = grade(version)
            if result["grade"] == "VULNERABLE":
                vulnerable = True
            results.append({
                "label": entry.get("label"),
                "version": version,
                "source": source,
                **result,
            })
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for result in results:
                print(render(result, result["version"],
                             label=result["label"], source=result["source"]))
                print()
        return 2 if vulnerable else 0
    version = None
    source = None
    if args.version:
        version = args.version
    elif args.local:
        try:
            version, source = detect_local(args.local)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    elif args.version_file:
        try:
            version = read_version_file(args.version_file)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        source = args.version_file
    else:
        parser.error("--version, --local, or --version-file is required "
                     "(or --inventory-json / --list)")
    result = grade(version)
    if args.json:
        print(json.dumps({
            "version": version,
            "source": source,
            **result,
        }, indent=2))
    else:
        print(render(result, version, source=source))
    return 2 if result["grade"] == "VULNERABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
