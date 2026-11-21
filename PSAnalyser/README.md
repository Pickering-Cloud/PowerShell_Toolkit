# PSAnalyser

A standalone linter, formatter and static security analyser for PowerShell scripts, in the spirit of [ruff](https://docs.astral.sh/ruff/) for Python. One script, no modules to install, and it runs on both Windows PowerShell 5.1 and PowerShell 7.

PSAnalyser reads your scripts with PowerShell's own parser and checks them against a catalogue of rules: formatting, common mistakes, security problems, and features that only work on one PowerShell version. Many formatting and lint issues can be fixed automatically. **It never runs, dot-sources or imports the scripts it analyses.**

> Version 0.1.0 is the first milestone. The rule catalogue and output formats will grow; see [Roadmap](#roadmap).

## Features

- 26 rules across formatting, lint, security, compatibility and toolkit conformance
- Safe automatic fixes, with a diff preview, a backup of every changed file, and automatic rollback if a fix would break the script
- Security rules mapped to [CWE](#what-is-cwe) and, where relevant, MITRE ATT&CK
- Hard-coded secrets are never shown: snippets, diffs, logs and reports are masked
- Console, log file, CSV and JSON output
- Per-folder configuration file, plus suppression comments that require a written reason
- CI-friendly: never prompts when unattended, and `-FailOnSeverity` turns findings into a non-zero exit code

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.x. No modules are needed.
- Outbound HTTPS to `pickering.cloud` for the optional update check and telemetry (both can be disabled, see below).
- Write access to the log, report and backup folders. All three are created if they do not exist.

Running under PowerShell 7 gives the most complete results: Windows PowerShell 5.1 cannot parse PowerShell 7 syntax such as `??` or `&&`, so under 5.1 those lines are reported from the parse errors instead (see PSC001).

## Usage

```powershell
# Analyse the scripts in the current folder
.\PSAnalyser.ps1

# Analyse a folder recursively
.\PSAnalyser.ps1 -Path .\Scripts -Recurse

# Preview the safe fixes as a diff, without changing anything
.\PSAnalyser.ps1 -Path .\Scripts -Recurse -Fix -WhatIf

# Apply the safe fixes without being asked
.\PSAnalyser.ps1 -Path .\Scripts -Recurse -Fix

# Security rules only, JSON report, fail the build on anything High
.\PSAnalyser.ps1 -Path . -Recurse -Rules PSS* -Report Json -FailOnSeverity High

# Show the rule catalogue
.\PSAnalyser.ps1 -ListRules
```

In an interactive session, if safe fixes are available and you did not use `-Fix`, PSAnalyser asks once for all files:

```
12 findings: 9 safe fixes available, 2 suggestions, 1 warning
Apply 9 safe fix(es) now? (y/N/d=show diff)
```

`d` shows the diff and asks again. After fixes are applied, the files are scanned again and whatever remains (suggestions and warnings) is listed. In an unattended session, for example a scheduled task, a CI job or anything started with `-NonInteractive`, PSAnalyser never prompts: it reports only, unless `-Fix` was used.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Path` | current folder | Files or folders to analyse. Folders are searched for `.ps1`, `.psm1` and `.psd1` files. |
| `-Recurse` | off | Search folders recursively. |
| `-Exclude` | none | Wildcards for files to skip, matched against the file name, the path relative to the scanned folder and the full path. |
| `-ConfigPath` | `.psanalyser.json` in the scanned folder | Configuration file. Without one, the built-in defaults are used. |
| `-Fix` | off | Apply every safe fix without prompting. With `-WhatIf`, show the diff and write nothing. |
| `-Rules` | all | Only run these rule IDs. Wildcards are allowed, for example `PSS*`. |
| `-ExcludeRules` | none | Skip these rule IDs. Wildcards are allowed. |
| `-MinimumSeverity` | `Info` | Only show, report and fix findings at or above this severity: `Info`, `Low`, `Medium` or `High`. |
| `-FailOnSeverity` | `None` | Exit with code 2 if any finding is at or above this severity. Checked against every finding, whatever `-MinimumSeverity` is. |
| `-Report` | none | Write reports: `Csv`, `Json`, or both. |
| `-BackupPath` | `C:\ProgramData\PickeringCloud\PSAnalyser\Backups` | Where originals are copied before a fix. Each run writes to its own timestamped subfolder. |
| `-ListRules` | off | Print the rule catalogue and exit. |
| `-LogPath` | `C:\ProgramData\PickeringCloud\PSAnalyser\Logs\PSAnalyser.log` | Log file location. |
| `-LoggingLevel` | `Info` | `Debug`, `Verbose`, `Info`, `Warn`, `Error`, `Critical` or `None` (or 1 to 7, with 0 also meaning `None`). |
| `-ReportPath` | `C:\ProgramData\PickeringCloud\PSAnalyser\Reports` | Folder for CSV and JSON reports. |
| `-RetentionDays` | `30` | Reports older than this are removed. `0` disables cleanup. Only this tool's own reports are touched. |
| `-DisableUpdateCheck` | off | Skip the check for a newer version. |
| `-DisableTelemetry` | off | Do not send anonymous usage telemetry. |

`-Rules`, `-ExcludeRules`, `-Exclude` and `-Report` also accept comma-separated values in one argument (for example `-Report Csv,Json`). This matters with `powershell -File`, which passes a comma-separated list as a single string.

## Configuration

Put a `.psanalyser.json` file in the folder you scan, or point to one with `-ConfigPath`. Every setting is optional; anything left out uses the default shown here.

```json
{
  "targetVersions": ["5.1", "7"],
  "indent": { "style": "spaces", "size": 4, "detect": false },
  "lineEnding": "crlf",
  "exclude": ["**/vendor/**"],
  "rules": {
    "PSL004": { "enabled": false },
    "PSS007": { "severity": "Medium" }
  },
  "toolkit": { "templateVersion": "1.1.1" }
}
```

| Setting | Meaning |
|---|---|
| `targetVersions` | The PowerShell versions your scripts must run on: `"5.1"`, `"7"`, or both. Drives the compatibility rules (PSC001 needs 5.1, PSC002 needs 7) and PSF005. |
| `indent.style` / `indent.size` | `"spaces"` or `"tabs"`, and how many columns one level is. |
| `indent.detect` | When `true`, each file is checked against its own dominant indentation instead of `indent.style`. |
| `lineEnding` | `"crlf"` or `"lf"`. |
| `exclude` | Globs matched against paths relative to the scanned folder. `**` matches any number of folders and `*` matches within one name. A pattern with no `/` matches at any depth. |
| `rules` | Per rule: `"enabled": false` to turn it off, or `"severity"` to change its severity. |
| `toolkit.templateVersion` | The canonical `PC-TEMPLATE` version that PST001 checks toolkit scripts against. |

An invalid configuration file stops the run with exit code 1, rather than analysing with the wrong settings. Unknown settings are logged as a warning and ignored.

## Rules

Severity is one of Info, Low, Medium or High. The fix tier says what PSAnalyser can do about a finding:

- **Safe**: fixed automatically by `-Fix` or the prompt. Safe fixes do not change what the script does, with two deliberate exceptions that correct real bugs: PSL003 (null comparisons) and PSF005 (how Windows PowerShell 5.1 reads non-ASCII characters). PSF004 also normalises line endings inside here-strings.
- **Suggest**: a suggested change is shown, but you make it yourself.
- **None**: a warning only.

| ID | Severity | Fix tier | CWE | What it finds |
|---|---|---|---|---|
| PSF001 | Info | Safe | | Trailing whitespace. Whitespace inside multi-line strings is left alone. |
| PSF002 | Info | Safe | | Indentation with tabs instead of spaces, or the other way round. |
| PSF003 | Info | Safe | | No line break at the end of the file. |
| PSF004 | Info | Safe | | Mixed line endings, or ones that do not match `lineEnding`. Reported once per file. |
| PSF005 | Medium | Safe | | Non-ASCII characters in a file without a UTF-8 byte order mark. Windows PowerShell 5.1 reads such files as ANSI and misreads the characters. The fix adds the byte order mark. |
| PSL000 | High | None | | Syntax error. |
| PSL001 | Low | Safe | | Alias used in a script. Built-in aliases that mean the same cmdlet on 5.1 and 7 are expanded. `sc`, `curl` and `wget` run native programs on PowerShell 7, so they are reported without a fix. Names the script defines itself are skipped. |
| PSL002 | Low | Suggest | | Unapproved verb in a function name, with a suggested replacement (Delete to Remove, Create to New, Check to Test and so on). Never renamed automatically. |
| PSL003 | Medium | Safe | | `$x -eq $null`. When `$x` is a collection this filters it instead of testing for null. The fix puts `$null` on the left. |
| PSL004 | Info | Suggest | | `Write-Host`. |
| PSL005 | Low | None | CWE-390 | Empty `catch` block. |
| PSL006 | Info | Safe | | Redundant semicolon at the end of a line. |
| PSL007 | Low | None | | Suppression comment without a reason. |
| PSS001 | Medium | Suggest | CWE-95 | `Invoke-Expression` or `iex`. |
| PSS002 | High | None | CWE-494 | Download and execute, for example piping `Invoke-WebRequest` into `Invoke-Expression` (ATT&CK T1105). |
| PSS003 | Medium | Suggest | CWE-312 | `ConvertTo-SecureString -AsPlainText`, `ConvertFrom-SecureString -AsPlainText`, or a `[string]` parameter named like a password. |
| PSS004 | High | None | CWE-798 | Hard-coded secrets: password, secret, token and key assignments, Bearer tokens, common token formats and long random-looking strings. |
| PSS005 | High | None | CWE-295 | Certificate validation turned off: a callback that returns `$true`, `-SkipCertificateCheck`, or a trust-all certificate policy. |
| PSS006 | Medium | Suggest | CWE-327, CWE-319 | SSL 2.0, SSL 3.0, TLS 1.0 or TLS 1.1 enabled, or a web request over plain `http://`. |
| PSS007 | Low | Suggest | CWE-328 | MD5 or SHA1, via `Get-FileHash` or the .NET classes. |
| PSS008 | Medium | Suggest | CWE-78 | Command lines built from variables for `Start-Process`, `cmd /c`, `powershell -Command` or the call operator. `$env:` variables and `$PSScriptRoot` do not count. |
| PSS009 | High | Suggest | CWE-89 | SQL built from variables for `Invoke-Sqlcmd` or a `SqlCommand`. |
| PSS010 | Medium | Suggest | CWE-693 | Execution policy set to Bypass or Unrestricted (T1059.001), encoded commands (T1027), or Microsoft Defender exclusions and protections changed (T1562.001). |
| PSC001 | High | None | | Syntax, cmdlets or parameters that need PowerShell 7: `??`, `??=`, the ternary operator, `&&`, `\|\|`, `?.`, `?[]`, `ForEach-Object -Parallel` and others. Only when 5.1 is a target. |
| PSC002 | Medium | Suggest | | Cmdlets removed in PowerShell 7, such as `Get-WmiObject` and the classic event log cmdlets, with what to use instead. Only when 7 is a target. |
| PST001 | Medium | None | | For toolkit scripts: the `PC-TEMPLATE` region is missing, malformed, or not at the canonical version. |

Run `.\PSAnalyser.ps1 -ListRules` to see the catalogue for the version you have.

### What is CWE?

CWE (Common Weakness Enumeration) is a public catalogue of software weakness types, maintained by MITRE. Each type has a number, so CWE-78 always means OS command injection and CWE-798 always means hard-coded credentials. The CWE ID on a security finding lets you look up a full explanation, examples and mitigations at `https://cwe.mitre.org/data/definitions/<number>.html`, and lets security tools and auditors talk about the same problem in the same terms. Each finding's `HelpUrl` links straight to its CWE page.

Some findings also carry a MITRE ATT&CK technique ID, such as T1059.001 (PowerShell). ATT&CK describes how attackers behave rather than how code goes wrong, so it is useful when the pattern found is one that attackers commonly use.

## Suppressing a finding

When a finding is deliberate, suppress it with a comment. **A reason is required**, after `--`. A suppression without a reason is not applied and is itself reported (PSL007).

```powershell
Write-Host 'Done' # psa-ignore PSL004 -- console banner by design

# psa-ignore PSS001 -- the expression is a fixed internal constant
Invoke-Expression $command

# psa-disable PSC002 -- this block only runs on Windows PowerShell 5.1
Get-WmiObject Win32_BIOS
# psa-enable PSC002
```

- `psa-ignore` applies to its own line and the next line.
- `psa-disable` applies until a matching `psa-enable`, or the end of the file.
- Several rule IDs can be listed, separated by commas or spaces.

## How fixes stay safe

- Each safe fix is a small text edit. Edits are applied from the end of the file backwards, and edits that overlap are skipped (they are applied on the next run).
- The file's encoding, byte order mark and line endings are preserved, unless a PSF rule is fixing exactly that.
- Before a file is changed, the original is copied to the backup folder, under a path that mirrors its full path so names cannot collide.
- The new file is written to a temporary file and then swapped in, so a failure never leaves a half-written script.
- If the fixed text would have more parse errors than the original, nothing is written and the run fails with an error. If anything goes wrong after writing, the original is restored from the backup.
- Fixes are idempotent: running `-Fix` again changes nothing.

## Output

Findings are printed grouped by file, with the line and column, rule ID, severity, fix tier, message, a snippet of the code and a suggestion. Everything printed is also written to the log file.

With `-Report`, reports go to `-ReportPath` as `PSAnalyser_<timestamp>.csv` and `PSAnalyser_<timestamp>.json`. Both contain one row per finding with these fields: `RuleId`, `Category`, `Severity`, `FixTier`, `File`, `Line`, `Column`, `Message`, `Snippet`, `Suggestion`, `Cwe`, `AttackId` and `HelpUrl`. The JSON report also has a summary by severity and fix tier. If fixes were applied, the reports describe the files after fixing.

Hard-coded secret values are never printed. Any finding on a line that holds a secret has its snippet masked, and diffs mask secret values too.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The run completed. Findings do not change this unless `-FailOnSeverity` is used. |
| 1 | The run failed: invalid configuration, a path that does not exist, a rule error, or a fix that had to be rolled back. |
| 2 | `-FailOnSeverity` was used and at least one finding met the threshold. |

## Using it in CI

```yaml
- name: Lint PowerShell
  shell: pwsh
  run: ./PSAnalyser/PSAnalyser.ps1 -Path . -Recurse -FailOnSeverity High -Report Json -DisableTelemetry -DisableUpdateCheck
```

## Update check and telemetry

After each run, the script checks a static version file on `pickering.cloud` and tells you if a newer version exists. It never downloads or installs anything. Unless disabled, it also sends anonymous usage data: tool name and version, OS and build, PowerShell version and edition, timezone ID, and whether the run was interactive or unattended. No file names, paths, code or findings are ever sent. See [TELEMETRY.md](../TELEMETRY.md) for the full policy.

Turn them off with `-DisableUpdateCheck` and `-DisableTelemetry`, or turn telemetry off for every tool by setting `PICKERINGCLOUD_NOTELEMETRY=1` or `DO_NOT_TRACK=1`.

## Running the tests

The tests use [Pester](https://pester.dev) 5, which is only needed for development.

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -SkipPublisherCheck
Invoke-Pester -Path .\PSAnalyser\tests -Output Detailed
```

Run them under both `powershell` and `pwsh`: each run tests the engine it is running on. The fixtures in `tests\fixtures` are compared byte for byte, so their `.gitattributes` turns off line-ending conversion. Each rule has a `bad.ps1` and a `good.ps1`, with the expected counts in `expected.psd1`. Each safe fix has a `before.ps1` and `after.ps1` pair under `fix`.

## Limitations

- The analysis is static and pattern-based. It does not follow data through variables, so the injection rules (PSS008, PSS009) flag string building, not proven attacker-controlled input.
- PSC002 cannot tell when a removed cmdlet is guarded by a version check. Suppress those findings with a reason.
- Under Windows PowerShell 5.1, a file that uses PowerShell 7 syntax has parse errors, so other rules may see less of it. Run under PowerShell 7 for full coverage.
- PSF004 also converts line endings inside here-strings, as Git and most editors do.
- Approved verbs come from `Get-Verb` on the running engine, so `Build` and `Deploy` (added in PowerShell 7) are accepted under 7 but not under 5.1.

## Roadmap

Planned for later milestones: HTML and SARIF reports, a baseline file to accept existing findings, parameter alias expansion, more security rules, a known-vulnerabilities (CVE) advisories file, and simple taint tracking within a function.

## Licence and contributions

See the repository root for the licence, `CONTRIBUTING.md` and `SECURITY.md`.
