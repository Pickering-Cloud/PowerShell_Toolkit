# WSUS-ClientSync

Forces a Windows client to check in against its configured WSUS server, collects diagnostic information, and optionally remediates common synchronisation and installation errors automatically.

Designed to run unattended, including via PowerShell remoting across many machines simultaneously.

## Features

- Reads the currently configured WSUS server and status server from Group Policy, forces a `gpupdate`, and re-reads afterward to catch any policy change.
- Verifies DNS resolution, network reachability (ping and port), and, for HTTPS-configured servers, whether the server's certificate is genuinely trusted, without failing if WSUS isn't using SSL at all.
- Checks for a pending reboot (component servicing, Windows Update, pending file rename, computer/domain rename, and via the SCCM client if present), low disk space on the system drive, and disabled prerequisite services.
- Attempts synchronisation against WSUS via three mechanisms (Windows Update Agent COM API, `UsoClient`, and legacy `wuauclt`), retrying up to a configured number of times.
- Reviews update history for errors that occurred during this run specifically (not historical noise from before the script started).
- With `-AutomaticallyRemediate`, attempts known fixes for recognised error codes, then retries synchronisation once more. Some detected issues (policy-managed settings such as a disabled Windows Update policy) are never auto-remediated regardless of this switch, since fixing those automatically would override a deliberate administrative decision.
- Full-fidelity logging to a read-only-protected log file (Debug through Critical), plus a smaller set of Application Event Log entries for anything worth monitoring centrally.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+, Windows only.
- No external module dependencies. Uses only built-in Windows Update Agent COM APIs, `UsoClient.exe`, `wuauclt.exe`, and the built-in `BitsTransfer` module.
- Local administrator rights are required for most of the checks and all remediation actions (service control, folder resets, event log source registration).
- Safe to run without `-AutomaticallyRemediate` first, in that mode the script only reports findings and never changes anything on the machine.

## Usage

```powershell
# Run diagnostics and a sync attempt, reporting any issues found without changing anything
.\WSUS-ClientSync.ps1

# Run diagnostics, attempt automatic remediation of recognised issues, and retry sync afterward
.\WSUS-ClientSync.ps1 -AutomaticallyRemediate

# Use a custom log file location
.\WSUS-ClientSync.ps1 -CustomLogPath D:\Logs\wsus.log

# Preview what remediation would do, without changing anything
.\WSUS-ClientSync.ps1 -AutomaticallyRemediate -WhatIf

# Skip the update check and telemetry
.\WSUS-ClientSync.ps1 -DisableUpdateCheck -DisableTelemetry

# Run across many machines via remoting (logging level defaults to Info automatically
# in a remote session, since the interactive prompt cannot be shown)
Invoke-Command -ComputerName $computers -FilePath .\WSUS-ClientSync.ps1 -ArgumentList $true
```

### Parameters

| Parameter | Type | Default | Description |
|:---|:---:|:---|:---|
| `AutomaticallyRemediate` | `switch` | `off` | Attempts automatic fixes for recognised issues rather than only reporting them. |
| `CustomLogPath` | `string` | `C:\Pickering-Cloud\Logs\WSUS-Client\WSUS-ClientSync.log` | Path to the log file. |
| `DisableUpdateCheck` | `switch` | `off` | Skips the check for a newer version. |
| `DisableTelemetry` | `switch` | `off` | Stops anonymous usage telemetry being sent. |

The script also supports `-WhatIf` and `-Confirm`. With `-WhatIf`, nothing on the machine is changed, no synchronisation is triggered, and no telemetry is sent.

## Logging level

If `$loggingLevel` (near the top of the script) is left unset, and the script detects it's running in a normal interactive session, it will prompt for a level (Debug, Verbose, Info, Warn, Error, Critical, or None). If it detects it's running inside a remote session (e.g. via `Invoke-Command`), it defaults to Info automatically rather than prompting, since there's no interactive host available to answer.

To skip the prompt entirely for unattended/scheduled use, edit the default directly near the top of the script:

```powershell
[Nullable[int]]$loggingLevel = 3  # Info
```

## Exit codes

| Code | Meaning |
|:---:|:---|
| 0 | The script ran to completion. This includes runs where synchronisation failed, so check the event log (events 1007, 1008 and 1016) rather than the exit code to detect a failed sync. |
| 1 | A critical configuration or connectivity problem stopped the run (events 1002 to 1005). |

## Update check and telemetry

When the script finishes it can check for a newer version and send anonymous usage data. Both are optional and independent of each other, and neither can change the outcome of the run.

**Update check.** A plain GET request to `https://pickering.cloud/tools/versions.json` with a generic user agent. Nothing is sent. If a newer version exists the script writes a notice to the log. In an interactive session it also offers to open the release page (GitHub links only). In a remote or unattended session, or with `-WhatIf`, it never prompts. It never downloads or installs anything.

**Telemetry.** A single anonymous POST to `https://pickering.cloud/api/telemetry` containing the tool name and version, OS name and build, PowerShell version and edition, timezone ID and whether the run was interactive or unattended. The server also records the country (taken from the request) and a daily salted hash of the IP address, so repeat use can be counted without storing the address. No WSUS server names, machine names, update titles or error details are ever sent. Run the script with `-Verbose` to see the exact payload. The full disclosure is in `TELEMETRY.md` in the repository root.

If you run the script across many machines, each machine makes its own request. Machines without internet access simply skip both (each attempt times out after five seconds and is logged at Info level). To opt out:

| Method | Effect |
|:---|:---|
| `-DisableUpdateCheck` | No version check |
| `-DisableTelemetry` | No telemetry |
| `PICKERINGCLOUD_NOTELEMETRY=1` (or `true`) | No telemetry in any tool in this toolkit, for every user of the machine if set system-wide |

## Event Log reference

All events are written to the **Application** log under the source **WSUS Client Sync Script**.

| Event ID | Type | Meaning |
|:---:|:---|:---|
| 1001 | Information | Script completed |
| 1002 | Error | No WSUS server configured in policy |
| 1003 | Error | No WSUS Status server configured in policy |
| 1004 | Error | Unable to resolve DNS name for the configured WSUS server |
| 1005 | Error | Unable to reach the WSUS server on its configured port |
| 1006 | Warning | WSUS server's certificate is not trusted |
| 1007 | Error | Initial synchronisation attempts exhausted without success |
| 1008 | Error | An update failed to install or uninstall |
| 1009 | Warning | Repair-8000FFFF invoked (generic unexpected error) |
| 1010 | Warning | Repair-800F0831 invoked (component store corruption) |
| 1011 | Warning | Repair-80244022 invoked (WSUS server reported overloaded) |
| 1012 | Warning | Repair-80072EE2 invoked (timeout reaching WSUS server) |
| 1013 | Error | Repair-80072EE5 invoked (malformed WSUS URL), policy issue, not auto-fixed |
| 1014 | Error | Repair-8024002E invoked (Windows Update disabled by policy), not auto-fixed |
| 1015 | Error | A required service failed to restart after a remediation action, manual attention required |
| 1016 | Error | Synchronisation still failed even after remediation |

## Remediation actions

Each recognised update error code has a corresponding `Repair-<code>` function. These call into a small set of shared, idempotent actions, each one only runs once per script execution even if multiple error codes would otherwise trigger it:

| Shared action | What it does |
|:---|:---|
| `Invoke-SFCScanOnce` | Runs `sfc /scannow`. |
| `Invoke-DISMRestoreHealthOnce` | Runs `DISM /Online /Cleanup-Image /RestoreHealth`. |
| `Invoke-ResetFolderCache` | Stops `wuauserv`/`bits`/`cryptsvc`, renames `SoftwareDistribution` and `catroot2`, restarts the services regardless of whether the rename succeeded. |
| `Invoke-BitsQueueReset` | Removes stuck/errored jobs from the BITS transfer queue via `Get-BitsTransfer`/`Remove-BitsTransfer`. Escalates to `Invoke-BitsQueueFileReset` if the API itself fails to respond. |
| `Invoke-BitsQueueFileReset` | More invasive fallback: stops BITS, deletes the queue database files directly, restarts BITS regardless of outcome. Only reached if the API-based approach can't run at all. |

Currently recognised error codes: `0x8000FFFF`, `0x800F0831`, `0x80244022`, `0x80072EE2`, `0x80072EE5`, `0x8024002E`. Any error code without a matching `Repair-<code>` function is logged as unrecognised rather than silently ignored.

## Known limitations

- Some error codes (malformed WSUS URL, Windows Update disabled by policy) are deliberately never auto-remediated, since both indicate a policy-level configuration decision that a script shouldn't override unattended. These are logged clearly with guidance instead.
- Network/timeout-related errors (`0x80072EE2` and similar) get a lightweight retry (DNS cache clear, port re-check) rather than a full component reset, since the root cause is typically external (firewall, proxy, WSUS server load) and a component reset wouldn't address it.
- The certificate trust check does not validate revocation status (`RevocationMode = NoCheck`) by default, since a WSUS server on an internal network may not have outbound access to a public CRL/OCSP endpoint, which would otherwise produce a false "untrusted" result.
- Has not been tested end-to-end against a live WSUS server or a genuinely faulted machine. Error code detection, remediation actions, and the sync retry logic are built against documented behaviour and community-verified troubleshooting guidance, but worth validating carefully in a test environment before relying on this in production, particularly `-AutomaticallyRemediate`.

## License

See [`LICENSE`](../LICENSE) at the repository root.