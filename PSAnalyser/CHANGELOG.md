# Changelog

All notable changes to PSAnalyser are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this tool adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-21

### Added

- First release (milestone 1): a standalone, dependency-free linter, formatter and static security analyser for PowerShell, running on Windows PowerShell 5.1 and PowerShell 7.
- 26 rules: formatting (PSF001 to PSF005), lint (PSL000 to PSL007), security (PSS001 to PSS010, each with a CWE), compatibility (PSC001, PSC002) and toolkit conformance (PST001).
- Safe automatic fixes for PSF001 to PSF005, PSL001, PSL003 and PSL006, through `-Fix` or an interactive prompt. Includes a diff preview with `-WhatIf`, backups, atomic writes, rollback on failure, and idempotent edits.
- `.psanalyser.json` configuration: target versions, indentation, line endings, exclusions, and per-rule enable and severity settings.
- Suppression comments (`psa-ignore`, `psa-disable`, `psa-enable`) that require a written reason.
- Console, log file, CSV and JSON output, plus `-ListRules`.
- `-FailOnSeverity` for CI (exit code 2).
- Hard-coded secrets are masked in snippets, diffs, logs and reports.
- Pester 5 test suite and a GitHub Actions workflow that runs it on Windows PowerShell 5.1 and PowerShell 7.
