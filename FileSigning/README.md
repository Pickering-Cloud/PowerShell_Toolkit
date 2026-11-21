# FileSigning

Signs one or more files with a code signing certificate, obtaining that certificate automatically from an existing store entry, Active Directory Certificate Services (ADCS), or a self-signed fallback.

## Features

- Checks the local certificate store for an existing, in-date code signing certificate before doing anything else.
- Requests a certificate from ADCS via default AD-integrated enrollment (no explicit CEP/CES URL required on a domain-joined machine), with an availability check (`certutil -ping`) so an unreachable CA fails fast rather than hanging.
- Falls back to creating and trusting a self-signed certificate if ADCS is unavailable or a request fails, unless `-RequireADCSCertificate` is set, in which case the failure is surfaced instead.
- Handles ADCS requests left `Pending` CA manager approval, persisting the request so a later run can retrieve the issued certificate without resubmitting.
- Signs one file via `-Path`, or opens an interactive, multi-select file picker filtered to PowerShell-signable and general Authenticode-signable file types.
- Optional RFC 3161 timestamping, so signatures remain valid after the signing certificate itself expires.
- Centrally governed settings via an optional JSON config file, where config values always override command-line parameters, intended for IT-controlled deployment to developer machines.
- Optional update check and anonymous usage telemetry, each with its own opt-out.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+, on Windows only (this script relies on the Windows certificate store, `certutil`, and WinForms, none of which exist on other platforms).
- The `PKI` module, which ships with the AD CS Remote Server Administration Tools feature (Windows 8.1 / Server 2012 R2 and later). The script checks for this and provides guidance if it's missing, rather than attempting to install anything.
- Outbound HTTPS to `pickering.cloud` for the optional update check and telemetry. Both can be disabled, see [Update check and telemetry](#update-check-and-telemetry).
- **PowerShell must be running in STA mode for the interactive file picker.** Windows PowerShell 5.1 defaults to STA. PowerShell 7+ defaults to MTA and needs to be started with `pwsh.exe -STA`. This only matters if `-Path` is omitted.

## Usage

```powershell
# Sign a single file, using an existing certificate or creating a self-signed one if needed

.\FileSigning.ps1 -Path .\Deploy-Server.ps1



# Open the interactive file picker, and require an ADCS-issued certificate

.\FileSigning.ps1 -RequireADCSCertificate -Verbose



# Preview what would happen without making any changes

.\FileSigning.ps1 -Path .\Deploy-Server.ps1 -WhatIf



# Generate a template config file and exit, without signing anything

.\FileSigning.ps1 -BuildConfig

```

### Parameters

#### Policy-governed
 
These can be set via config file, which always takes precedence over the value shown here if both are present. See [Configuration file](#configuration-file).
 
| Parameter | Type | Default | Description |
|:---|:---:|:---|:---|
| `RequireADCSCertificate` | `switch` | `off` | Only an ADCS-issued certificate is acceptable. Any ADCS failure stops the script rather than falling back to self-signed. |
| `UsePersonalCertificate` | `switch` | `off` | Uses `Cert:\CurrentUser\My` instead of `Cert:\LocalMachine\My`. Does not require an elevated session, unlike the default. |
| `KeyLength` | `int` | `2048` | RSA key length (2048, 3072, or 4096) for a self-signed certificate. No effect on an ADCS-issued certificate. |
| `CertificateValidity` | `int` | `3` | Validity period, in years, for a self-signed certificate. No effect on an ADCS-issued certificate. |
| `CodeSigningTemplate` | `string` | `CodeSigning` | ADCS certificate template name (not display name, if they differ). |
| `CompanyName` | `string` | `Company Name Here` | Certificate subject name (CN). Override this before real use. |
| `TimestampingAuthority` | `string` | none | RFC 3161 timestamp server URL, e.g. `http://timestamp.digicert.com`. If omitted or unreachable, signing proceeds without a timestamp. |
 
#### Runtime only
 
Always taken from the command line, never overridden by config.
 
| Parameter | Type | Default | Description |
|:---|:---:|:---|:---|
| `Path` | `string` | none | Path to a single file to sign. If omitted, the interactive file picker is shown instead. Required in unattended runs (for example `-NonInteractive`), where the picker cannot be shown. |
| `ConfigFilePath` | `string` | `SignFileConfig.json` alongside the script | Path to the JSON config file. |
| `BuildConfig` | `switch` | `off` | Writes a template config file to `-ConfigFilePath` using the script's current parameter values, then exits without signing anything. Always overwrites any existing file at that path. |
| `LogPath` | `string` | `C:\ProgramData\PickeringCloud\FileSigning\Logs\FileSigning.log` | Log file location. |
| `LoggingLevel` | `string` | `Info` | `Debug`, `Verbose`, `Info`, `Warn`, `Error`, `Critical` or `None` (or 1 to 7, with 0 also meaning `None`). `-Debug` and `-Verbose` raise it when this is not set. |
| `ReportPath` | `string` | | Standard toolkit parameter. Unused, as this tool writes no reports. |
| `RetentionDays` | `int` | | Standard toolkit parameter. Unused, as this tool writes no reports. |
| `DisableUpdateCheck` | `switch` | `off` | Do not check for a newer version. |
| `DisableTelemetry` | `switch` | `off` | Do not send anonymous usage telemetry. The update check still runs unless `-DisableUpdateCheck` is also used. |

## Logging

Every run appends to a single log file, `C:\ProgramData\PickeringCloud\FileSigning\Logs\FileSigning.log` by default, rotated at 10 MB with five older copies kept. Versions before 1.2.0 wrote a dated file per day under `C:\Pickering-Cloud\Logs\FileSigning\`. Files already there are left alone.

The log is written during `-WhatIf` runs too, so you can review what would have happened. Secrets in log messages are masked on a best-effort basis.

## Configuration file

Settings marked as policy-governed can be centrally controlled via a JSON config file rather than left to individual command-line invocations. Where a config file is present, its values always take precedence over the command line, so an organisation can deploy a locked-down config (e.g. read-only to developers via NTFS permissions) alongside the script.

Generate a starting template with:

```powershell
.\FileSigning.ps1 -BuildConfig -ConfigFilePath .\SignFileConfig.json
```

Example schema, see [`SignFileConfig.json.EXAMPLE`](./SignFileConfig.json.EXAMPLE):

```json
{
   "RequireADCSCertificate": true,

   "UsePersonalCertificate": false,

   "CompanyName": "Contoso IT",

   "ValidityLength": 3,

   "KeyLength": 2048,

   "CertTemplate": "CodeSigning",

   "TimestampingAuthority": "http://timestamp.digicert.com"

}
```

A `null` value for any setting means "no policy set", the command-line value or built-in default is used instead. An explicit `true`/`false`/value means that setting is locked to config, and a warning is written if a conflicting command-line value was also supplied.

## Certificate acquisition order

1. **Existing valid certificate** in the configured store (`Cert:\LocalMachine\My` by default), matched on code signing Enhanced Key Usage, private key availability, and remaining validity.

2. **ADCS**, if no valid existing certificate is found. Availability is checked first; a `Pending` result is persisted to `pending-request-state.json` for retrieval on a later run.

3. **Self-signed fallback**, if ADCS is unavailable or the request fails, unless `-RequireADCSCertificate` is set.

## Update check and telemetry

When the script finishes, it does two optional things. Neither can affect signing or the exit code, and any failure is ignored.

**Update check.** The script reads a small static file (`https://pickering.cloud/tools/versions.json`) and tells you if a newer version is available. It sends no data. In an interactive session it offers to open the release page, and in an unattended run it only writes a line to the log. It never downloads or installs anything. Disable it with `-DisableUpdateCheck`.

**Anonymous usage telemetry.** So the author can see roughly how many installs exist and which platforms to support, the script sends: tool name, tool version, OS name and build, PowerShell version and edition, timezone ID, and whether the run was interactive or unattended. The server adds the country from the request and a hash of the IP address that changes daily and cannot be linked across days. The raw IP address and User-Agent are never stored. File names, certificate details, host names and user names are never sent. Disable it with `-DisableTelemetry`, or for every tool at once by setting the environment variable `PICKERINGCLOUD_NOTELEMETRY=1` or `DO_NOT_TRACK=1` (organisations can set this centrally, for example through Group Policy).

The two are independent. You can keep update checks and turn telemetry off. Run with `-Debug` to see the exact telemetry payload in the log. See `TELEMETRY.md` in the repository root for the full policy.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (files signed, or config file generated via `-BuildConfig`). |
| `1` | No usable certificate available, no files selected (including an unattended run without `-Path`), or one or more files failed to sign. |

The update check and telemetry never change the exit code.

## Known limitations

- The ADCS request path has been validated against Microsoft's documented `Get-Certificate` cmdlet reference, but has not been tested end-to-end against a live CA. Validate template name, policy server reachability, and approval workflow in a test environment before relying on this in production.

- Third-party CAs (DigiCert, Sectigo, etc.) are not supported. `Get-Certificate` only speaks the ADCS enrollment protocol.

- Post-quantum signing (ML-DSA) is out of scope for this version. It requires a parallel ADCS hierarchy on Windows Server 2025 and is not something `New-SelfSignedCertificate` currently supports for the self-signed path.

- A self-signed certificate is not trusted on any machine other than the one it was created on, and only after being added to that machine's Trusted Root and Trusted Publisher stores, which this script does automatically for the self-signed path only.

## License

See [`LICENSE`](../LICENSE) at the repository root.