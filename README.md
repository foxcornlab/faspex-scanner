# `faspex-scanner`

Local triage for `CVE-2026-123218`, a critical authorization bypass in `IBM Aspera Faspex 5` that hands an authorized user full administrative control. Give it a `Faspex` version you own, or the install root on the host, and it tells you whether that install is still open. It never touches the network, never probes a server, never sends a crafted message.

## `The flaw`

`CVE-2026-123218` is an incorrect authorization flaw (`CWE-863`) in `IBM Aspera Faspex 5`. An authorized user can craft a specific message that bypasses user authorization and gains full administrative privileges. `IBM` rates it `CVSS 3.1 9.8` (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). The bulletin (`7295921`) was published on `7 November 2026`. Two days later, on `9 November`, `CISA` added the flaw to its `Known Exploited Vulnerabilities` catalog with a federal remediation deadline of `12 November 2026`. That three-day deadline is unusually short, and `CISA` only lists flaws it has evidence are actively exploited. `IBM` lists no workaround, so patching is the only fix.

The fix is `Faspex 5.0.19 PL1` (`Fix Pack 1`). `IBM`'s own check for a patched container deployment is that the `faspex-core` image reads `5.0.19 (1ce4b13, Fix Pack: 1)`. The affected range is every `Faspex 5` release from `5.0.0` through `5.0.19`, which means every `Faspex 5` install that has not taken this fix pack is open.

## `The traps`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| A bare `5.0.19` | `UNKNOWN` | **The PL1 trap.** The fix is `5.0.19 PL1`, not `5.0.19`. A bare `5.0.19` does not prove `Fix Pack 1` is installed, and a `5.0.19` install without the fix pack is still vulnerable. This tool refuses to clear it. Confirm the `faspex-core` image reads `5.0.19 (1ce4b13, Fix Pack: 1)`. |
| `5.0.19 (1ce4b13, Fix Pack: 1)` | `PATCHED` | That is `IBM`'s own validation string for the fixed container image. |
| `5.0.19 PL0` or `Fix Pack: 0` | `VULNERABLE` | `Fix Pack 0` is the base `5.0.19` release. The fix pack number is the whole difference between open and patched. |
| An `RPM` build number, for example `5.0.19.8706` | `UNKNOWN` | The fourth segment is the `RPM` build, not a fix pack. A build number says nothing about whether `PL1` is installed. |
| `Faspex 4.x`, for example `4.4.0` | `UNKNOWN` | The bulletin covers `Faspex 5` only. A `4.x` install has not been cleared, only left ungraded. Check it against `IBM`'s guidance for that line. Do not treat it as safe. |
| `5.0.20` or later | `PATCHED` | Later than the fixed release, so the fix is in the line. |
| A version read off a banner or login page | Not graded | This tool grades version strings you supply or files on the host. It does not fetch a version from a server. |

## `What it checks`

- `One install` (`--version 5.0.18`): graded against the fixed release
- `The container string` (`--version "5.0.19 (1ce4b13, Fix Pack: 1)"`): the `IBM` validation string grades `PATCHED`
- `The host it runs on` (`--local`): reads `version.txt` or `VERSION` under `/opt/aspera/faspex`, falls back to `rpm -q ibm-aspera-faspex`, then to running `faspex` containers
- `A version file` (`--version-file version.txt`): first line is the version, which may be the full container string
- `A fleet, offline` (`--inventory-json sites.json`): a `JSON` list of `{label, version}` or `{label, local}` entries
- `The full table` (`--list`): affected range, fixed release, container check, `KEV` deadline
- `Machine output` (`--json`): the same grades as `JSON`

```sh
python3 faspex_scanner.py --version 5.0.18
python3 faspex_scanner.py --version "5.0.19 (1ce4b13, Fix Pack: 1)"
python3 faspex_scanner.py --local
python3 faspex_scanner.py --local /opt/aspera/faspex
python3 faspex_scanner.py --version-file version.txt
python3 faspex_scanner.py --inventory-json sites.json
```

```json
[
  {"label": "faspex-prod", "version": "5.0.18"},
  {"label": "faspex-dr", "local": "/opt/aspera/faspex"}
]
```

Exit codes: `0` nothing vulnerable found, `2` vulnerable finding, `1` scan error. `UNKNOWN` does not change the exit code, but it is not clean.

Find your `Faspex` version in the admin UI, in `/opt/aspera/faspex/version.txt` on the host, from `rpm -q ibm-aspera-faspex`, or from `docker exec <faspex-core> cat /opt/aspera/faspex/VERSION` on a container deployment. This tool reads version strings you supply; it does not log in to a server to fetch one.

## `The table`

| `CVE` | `Score` | `Auth` | `Affected` | `Fixed in` |
| --- | --- | --- | --- | --- |
| `CVE-2026-123218` | `9.8` | Authorized user | `Faspex 5` `5.0.0` to `5.0.19` | `5.0.19 PL1` (`Fix Pack 1`) |

## `What this tool does not do`

It does not test the authorization bypass. Testing it would mean sending crafted messages to a live `Faspex` server, which is an attack, not a version check. It does not scan the network for `Faspex` installs, and it does not grade an install from a banner or a login page. It does not fetch or use any proof of concept.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`29` tests, all passing: version parsing in every accepted form (`PL1`, `Fix Pack: 1`, the container image string, `RPM` builds, `v`-prefix), the bare-`5.0.19` trap, `Fix Pack 0`, the `5.0.19` boundary on both sides, `Faspex 4.x` and unparseable `UNKNOWN` grades, local detection from `version.txt` and `VERSION` (including priority and unparseable-file handling), version-file reading, `CLI` exit codes, `JSON` output, and inventory grading.

## `Sources`

- `IBM` security bulletin `7295921`, published `7 November 2026`, read `10 November 2026`: affected `Faspex 5.0.0` through `5.0.19`, fixed in `5.0.19 PL1`, `CVSS 3.1 9.8` (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), `CWE-863`, workarounds `None`, container check `5.0.19 (1ce4b13, Fix Pack: 1)`
- `CISA Known Exploited Vulnerabilities` catalog feed, checked `10 November 2026`: `CVE-2026-123218` added `9 November 2026`, due `12 November 2026`, `knownRansomwareCampaignUse Unknown`, forensic triage required, notes link the `IBM` bulletin
- `NVD` record for `CVE-2026-123218`, checked `10 November 2026`: published `2026-11-07T04:17:28Z`, `CVSS 3.1 9.8` with the same vector, status `Undergoing Analysis`
- `IBM Aspera Faspex 5.0.13` release notes: the install root `/opt/aspera/faspex`, the `version.txt` file, and the `RPM` name `ibm-aspera-faspex-5.0.13.8706`
- `IBM Aspera Faspex 5.0 Guide`: install layout, `rpm -ivh ibm-aspera-faspex-version.build.x86_64.rpm`, `Faspex` UI at `/aspera/faspex`

Three disagreements to note. First, the `CVSS` vector says `PR:N`, no privileges required, while `IBM`'s own prose, the `CVE` description, and `CISA` all describe an authorized or authenticated user crafting a message; this tool follows the prose for exposure, an account is needed, and external-user and guest accounts are the exposure, while keeping the published `9.8`. Second, several trackers still list the fix as `Fixed in -` as of `9 November`; the `IBM` bulletin names `5.0.19 PL1`, and this tool follows the vendor bulletin. Third, the `IBM` bulletin page shows a `Modified date` of `6 November 2026` before its `Initial Publish date` of `7 November 2026`; this tool uses `7 November` as publication, which matches the `NVD` published timestamp and the bulletin's own change history.

No public detection-only scanner for this `CVE` was found at publication time: no `nuclei` template exists for `CVE-2026-123218`, checked `10 November 2026`. No `foxcornlab` repo covered `Faspex` before this one.

## `Disclaimer`

Defensive triage only, for systems you own or are authorized to assess. This tool grades exposure from version strings you supply. It does not exploit anything, and it is not a substitute for the vendor update. Patching closes the hole; it does not undo an admin account created through it, so audit admin accounts after upgrading.

## `Thanks to`

- `IBM` security team for the bulletin and the fixed release
- `CISA` for the `KEV` listing and the three-day deadline that made the urgency clear

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
