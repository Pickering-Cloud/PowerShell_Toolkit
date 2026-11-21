# Telemetry and update checks

The tools in this repository can make two network requests to pickering.cloud. Both are optional and independent of each other, and either can be turned off. This page explains exactly what each one sends, what is kept, and how to opt out.

## Who runs the service

The tools and the service behind them are written and run by me, Bradley Pickering, as a personal project. The service runs on a server I manage, behind Cloudflare.

## Which tools take part

These tools make the update check and send telemetry. The name in the second column is the value sent in the `tool` field.

| Tool | `tool` value |
|------|--------------|
| [ADAccountAudit](ActiveDirectoryManagement/ADAccountAudit/README.md) | `ADAccountAudit` |
| [EntraAppExpiryScanner](EntraAppExpiryScanner/README.md) | `EntraAppExpiryScanner` |
| [FileSigning](FileSigning/README.md) | `FileSigning` |
| [OutlookWebAccessManagement](OutlookWebAccessManagement/README.md) | `OutlookWebAccessManagement` |
| [PSAnalyser](PSAnalyser/README.md) | `PSAnalyser` |
| [WSUS-ClientSync](WSUS/ClientSync/README.md) | `ClientSync` |

Both requests happen after the tool has finished its work, and neither can change its result or exit code. A run with `-WhatIf` never sends telemetry.

## Update check

Each tool can download a small file listing the latest version of every tool:

```
GET https://www.pickering.cloud/tools/versions.json
```

The tool compares the version in that file with its own and tells you if a newer one is available. Nothing about you or your environment is sent. As with any web request, your IP address and your PowerShell User-Agent string reach the server, but requests for this file are not logged.

## Telemetry

If you have not opted out, each tool sends one small report when it runs:

```
POST https://www.pickering.cloud/api/telemetry
```

This tells me roughly how many installations exist, which versions are in use and which platforms they run on. That helps me decide what to support and test.

### What the tool sends

The report contains exactly these fields and nothing else:

| Field | Example | Meaning |
|-------|---------|---------|
| `tool` | `EntraAppExpiryScanner` | Which tool is running |
| `version` | `1.0.0` | The tool's version |
| `os` | `Microsoft Windows Server 2022 Standard` | Operating system name |
| `osBuild` | `20348` | Operating system build number |
| `psVersion` | `5.1.20348.2849` | PowerShell version |
| `psEdition` | `Desktop` | PowerShell edition (`Desktop` or `Core`) |
| `timezone` | `GMT Standard Time` | The machine's time zone setting |
| `runMode` | `interactive` | Whether someone ran it by hand or it ran unattended, for example as a scheduled task |

The server rejects any report with a tool name it does not recognise, or with values in the wrong format or over the length limits. Any other fields in a report are thrown away without being stored.

### What the server adds

- **Country.** A two-letter country code worked out from your IP address by Cloudflare, for example `GB`. If no country is available, `XX` is stored.
- **A daily client hash.** A 16-character code made by hashing your IP address together with a secret value that changes every day. It lets me count distinct installations per day without storing IP addresses. Because the secret changes daily, the same machine gets an unrelated code each day, so reports cannot be linked across days. Within a single day, reports from the same IP address share a code. This makes the data pseudonymous rather than anonymous.
- **Date and time.** The UTC date, the time of the first and last report that day, and how many reports arrived that day.

### What is never collected

- Your IP address is never stored. It is used in memory to work out the country code, the daily hash and rate limits, and is then discarded. It is not written to the database or to any log, and web server access logging is turned off for both addresses above.
- Your User-Agent string is never stored or logged.
- No tenant IDs, domain names, hostnames, usernames, application names, scan results or anything else about the environment a tool examines.

Requests pass through Cloudflare's network, which processes IP addresses in order to deliver traffic, under [Cloudflare's own privacy policy](https://www.cloudflare.com/privacypolicy/).

### How long it is kept

Records are deleted automatically 365 days after the day they relate to. There is no public interface for reading the data. I use it only to see how the tools are used, and I do not sell or share it.

## How to opt out

Telemetry and update checks are controlled separately. Turning one off does not affect the other.

- **Turn off telemetry for one run:** add the `-DisableTelemetry` switch.
- **Turn off update checks for one run:** add the `-DisableUpdateCheck` switch.
- **Turn off telemetry permanently:** set the environment variable `PICKERINGCLOUD_NOTELEMETRY` to `1` (or `true`). The tools also honour the general-purpose `DO_NOT_TRACK` variable in the same way. For example, for your user account:

  ```powershell
  [Environment]::SetEnvironmentVariable('PICKERINGCLOUD_NOTELEMETRY', '1', 'User')
  ```

  Or for every account on the machine (run as administrator):

  ```powershell
  [Environment]::SetEnvironmentVariable('PICKERINGCLOUD_NOTELEMETRY', '1', 'Machine')
  ```

  Open a new PowerShell window afterwards for the change to take effect.

If a request fails or the server cannot be reached, the tool carries on as normal.

## Questions

Email [website@pickering.cloud](mailto:website@pickering.cloud), or open an issue in the [PowerShell_Scripts repository](https://github.com/Pickering-Cloud/PowerShell_Scripts/issues).
