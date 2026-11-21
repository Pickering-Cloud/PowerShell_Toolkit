<#
    .SYNOPSIS
        Signs one or more files with a code signing certificate.

    .DESCRIPTION
        Obtains a code signing certificate, either an existing valid one already
        installed, a newly requested one from Active Directory Certificate Services
        (ADCS), or a self-signed fallback, then signs the specified file(s) using
        Set-AuthenticodeSignature.

        Settings can be supplied via command line parameters or a JSON config file.
        Where both are present, the config file takes precedence for policy-governed
        settings (RequireADCSCertificate, UsePersonalCertificate, CompanyName,
        ValidityLength, KeyLength, CertTemplate, TimestampingAuthority), so an
        organisation can centrally control signing policy while still allowing the
        script to be distributed and run by individual developers.

        If no -Path is supplied, an interactive multi-select file picker is shown
        instead, filtered to PowerShell-signable and general Authenticode-signable
        file types.

    .PARAMETER RequireADCSCertificate
        If set, only an ADCS-issued certificate is acceptable. If ADCS is
        unreachable or a request fails, the script stops rather than falling back
        to a self-signed certificate. If not set, a self-signed certificate is
        created automatically when ADCS is unavailable or a request fails.

    .PARAMETER Path
        Path to a single file to be signed. If omitted, an interactive file picker
        is shown, which also supports selecting multiple files.

    .PARAMETER ConfigFilePath
        Path to the JSON configuration file. Defaults to 'SignFileConfig.json'
        alongside this script. Values in this file, where present, override the
        equivalent command line parameters for policy-governed settings.

    .PARAMETER UsePersonalCertificate
        If set, uses the CurrentUser\My certificate store instead of the default
        LocalMachine\My. Note this does not require an elevated session, unlike
        the LocalMachine default.

    .PARAMETER KeyLength
        RSA key length, in bits, used when creating a self-signed certificate.
        Must be 2048, 3072, or 4096. Has no effect when a certificate is obtained
        from ADCS. Defaults to 2048.

    .PARAMETER CertificateValidity
        Validity period, in years, for a newly created self-signed certificate.
        Has no effect when a certificate is obtained from ADCS, since ADCS
        template validity is controlled by the CA. Defaults to 3.

    .PARAMETER CodeSigningTemplate
        ADCS certificate template name to request against. This must match the
        template name configured on the CA, not its display name if they differ.
        Defaults to 'CodeSigning'.

    .PARAMETER CompanyName
        Subject name (CN) used for the certificate, whether self-signed or
        requested from ADCS. Defaults to 'Company Name Here', worth overriding
        via parameter or config before real use.

    .PARAMETER TimestampingAuthority
        URL of an RFC 3161 timestamp server, e.g. http://timestamp.digicert.com,
        used to timestamp each signature so it remains valid after the signing
        certificate itself expires. If omitted, or unreachable, signing proceeds
        without a timestamp, and each signature's validity becomes tied to the
        signing certificate's own expiry.

    .PARAMETER BuildConfig
        If set, writes a template SignFileConfig.json to -ConfigFilePath using the
        script's current parameter values (or $null for anything not explicitly
        set), then exits immediately without checking for or signing any files.
        Always overwrites any existing file at that path.

    .PARAMETER LogPath
        Log file location. Defaults to
        C:\ProgramData\PickeringCloud\FileSigning\Logs\FileSigning.log. The file is
        appended to across runs and rotated at 10 MB.

    .PARAMETER LoggingLevel
        Debug, Verbose, Info, Warn, Error, Critical or None (1 to 7, 0 also means
        None). Defaults to Info. -Debug and -Verbose raise it if this is not set.

    .PARAMETER ReportPath
        Standard toolkit parameter. This tool writes no reports, so it is unused.

    .PARAMETER RetentionDays
        Standard toolkit parameter. This tool writes no reports, so it is unused.

    .PARAMETER DisableUpdateCheck
        If set, the script does not check for a newer version. No network request
        is made for this purpose.

    .PARAMETER DisableTelemetry
        If set, anonymous usage telemetry is not sent. The update check still runs
        unless -DisableUpdateCheck is also set. Telemetry can also be disabled for
        every tool at once by setting the environment variable
        PICKERINGCLOUD_NOTELEMETRY (or DO_NOT_TRACK) to 1, for example via Group
        Policy.

    .EXAMPLE
        .\FileSigning.ps1 -Path .\Deploy-Server.ps1

        Signs a single named file, using an existing certificate if one is
        available, or creating a self-signed certificate if not.

    .EXAMPLE
        .\FileSigning.ps1 -RequireADCSCertificate -Verbose

        Opens the interactive file picker for file selection, and requires an
        ADCS-issued certificate, failing rather than falling back to self-signed
        if ADCS is unreachable. Verbose output shows each step as it happens.

    .EXAMPLE
        .\FileSigning.ps1 -Path .\Deploy-Server.ps1 -TimestampingAuthority 'http://timestamp.sectigo.com' -WhatIf

        Shows what would happen (certificate creation, trust store changes,
        signing) without making any actual changes.

    .EXAMPLE
        .\FileSigning.ps1 -BuildConfig -RequireADCSCertificate -CompanyName 'Contoso IT'

        Writes a template config file with RequireADCSCertificate set to true and
        CompanyName set to 'Contoso IT', then exits without signing anything.

    .OUTPUTS
        None. Writes verbose/warning output describing progress and results, and
        sets a non-zero exit code if no usable certificate is available, no files
        are selected, or any file fails to sign. In an unattended session (for
        example -NonInteractive) -Path is required, since the file picker cannot be
        shown.

    .NOTES
        Author: Bradley Pickering
        Version: 1.2.0
        Requires: PKI module (ships with AD CS Remote Server Administration Tools,
        Windows 8.1 / Server 2012 R2 and later)
        Requires: PowerShell running in STA mode if the interactive file picker is
        used (default for Windows PowerShell 5.1; PowerShell 7+ needs 'pwsh.exe -STA')

        Update check and telemetry: after the run, the script reads a static version
        file from pickering.cloud and tells you if a newer version exists. It never
        downloads or installs anything. Unless disabled, it also sends anonymous usage
        data (tool, version, OS, PowerShell version, timezone, run mode). No file
        names, certificate details or host details are sent. See TELEMETRY.md in the
        repository root for the full list.
#>

##################################################
# Script Parameters
##################################################

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    # ---- Script-specific parameters go here (each one ends with a comma) ----
    [switch]$RequireADCSCertificate,
    [string]$Path,
    [string]$ConfigFilePath = (Join-Path -Path $PSScriptRoot -ChildPath "SignFileConfig.json"),
    [switch]$UsePersonalCertificate,
    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength = 2048,
    [ValidateRange(1, 25)]
    [int]$CertificateValidity = 3,
    [string]$CodeSigningTemplate = "CodeSigning",
    [string]$CompanyName  = "Company Name Here",
    [string]$TimestampingAuthority,
    [switch]$BuildConfig,

    # ---- Standard toolkit parameters (do not remove) ----
    [string]$LogPath,
    [string]$LoggingLevel,
    [string]$ReportPath,
    [ValidateRange(0, 3650)]
    [int]$RetentionDays,
    [switch]$DisableUpdateCheck,
    [switch]$DisableTelemetry
)

#region PC-CONFIG

# Per-tool values
$ScriptName    = 'FileSigning'
$ScriptVersion = '1.2.0'

# Toolkit-wide values
$UpdateCheckUrl        = 'https://pickering.cloud/tools/versions.json'
$TelemetryUrl          = 'https://pickering.cloud/api/telemetry'
$NetworkUserAgent      = 'PickeringCloud-Toolkit'
$UpdateUrlAllowPattern = '^https://github\.com/'
$TelemetryOptOutEnvVar = 'PICKERINGCLOUD_NOTELEMETRY'
$TelemetryDocName      = 'TELEMETRY.md'
$VendorFolderName      = 'PickeringCloud'

# Defaults used when the matching parameter is not supplied
$DefaultLoggingLevel  = 'Info'
$DefaultRetentionDays = 30
$DefaultDataRoot      = Join-Path -Path ([Environment]::GetFolderPath('CommonApplicationData')) -ChildPath ('{0}\{1}' -f $VendorFolderName, $ScriptName)
$DefaultLogPath       = Join-Path -Path $DefaultDataRoot -ChildPath ('Logs\{0}.log' -f $ScriptName)
$DefaultReportPath    = Join-Path -Path $DefaultDataRoot -ChildPath 'Reports'

# Log file behaviour
$LogMaxSizeMB      = 10      # Rotate at this size. 0 disables rotation.
$LogArchivesToKeep = 5       # Rotated copies kept (Name.1.log is the newest).
$RedactLogSecrets  = $true   # Best-effort masking of passwords, secrets and tokens.

# Windows event log
$EventLogName   = 'Application'
$EventLogSource = $ScriptName
#endregion PC-CONFIG

#region PC-TEMPLATE v1.1.1
$TemplateVersion = '1.1.1'

# NONE sits above Critical so that a threshold of NONE suppresses every message.
$logLevelMap = @{
    'DEBUG'    = 1
    'VERBOSE'  = 2
    'INFO'     = 3
    'WARN'     = 4
    'ERROR'    = 5
    'CRITICAL' = 6
    'NONE'     = 7
}

# ------------------------------------------------------------------------------
# Text helpers
# ------------------------------------------------------------------------------
function Limit-Text {
    <#
    .SYNOPSIS
        Strips control characters and trims text to a maximum length.
    .DESCRIPTION
        Used for anything that comes from outside the script (remote files, system
        values) before it is logged or sent.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$Text,
        [int]$Max = 256
    )

    $clean = ($Text -replace '[\x00-\x1F\x7F]', '').Trim()
    if ($clean.Length -gt $Max) { $clean = $clean.Substring(0, $Max) }
    return $clean
}

function Protect-LogText {
    <#
    .SYNOPSIS
        Masks common secret patterns in text before it is logged.
    .DESCRIPTION
        Best effort only. It catches "Bearer <token>" and key=value or key: value pairs
        where the key looks like a password, secret, token or API key. It does not replace
        simply never logging secrets.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Text)

    if (-not $RedactLogSecrets -or [string]::IsNullOrEmpty($Text)) { return $Text }

    $masked = $Text -replace '(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer ***'
    $masked = $masked -replace '(?i)\b(password|passwd|pwd|secret|client_?secret|token|access_?token|api[_-]?key)\b(["'']?\s*[=:]\s*)("[^"]*"|''[^'']*''|\S+)', '$1$2***'
    return $masked
}

# ------------------------------------------------------------------------------
# Configuration checks and run mode
# ------------------------------------------------------------------------------
function Test-ToolConfig {
    <#
    .SYNOPSIS
        Checks the CONFIG block and returns a list of problems (empty if all is well).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $problems = New-Object -TypeName 'System.Collections.Generic.List[string]'

    if ($ScriptName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') {
        $problems.Add('ScriptName must be 1 to 64 characters: letters, digits, dot, underscore or hyphen.')
    }

    $parsedVersion = $null
    if (-not [version]::TryParse((([string]$ScriptVersion -split '-')[0]), [ref]$parsedVersion)) {
        $problems.Add('ScriptVersion must look like 1.2.3 (an optional -suffix is allowed).')
    }

    foreach ($name in 'UpdateCheckUrl', 'TelemetryUrl') {
        $value = [string](Get-Variable -Name $name -ValueOnly -ErrorAction SilentlyContinue)
        if ($value -notmatch '^https://') {
            $problems.Add(('{0} must be an https:// address.' -f $name))
        }
    }

    if ([string]::IsNullOrWhiteSpace($NetworkUserAgent)) { $problems.Add('NetworkUserAgent must not be empty.') }
    if ([string]::IsNullOrWhiteSpace($EventLogSource)) { $problems.Add('EventLogSource must not be empty.') }
    if ($LogMaxSizeMB -lt 0 -or $LogArchivesToKeep -lt 0) { $problems.Add('LogMaxSizeMB and LogArchivesToKeep must not be negative.') }

    return $problems.ToArray()
}

function Get-RunMode {
    <#
    .SYNOPSIS
        Returns 'interactive' or 'unattended'.
    .DESCRIPTION
        Unattended means no prompt may ever be shown: no user session, -NonInteractive
        was passed, or input is redirected. A script can set $script:RunMode itself
        before this template runs to override the detection.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $nonInteractiveFlag = @([Environment]::GetCommandLineArgs() | Where-Object { $_ -like '-noni*' }).Count -gt 0

    if (-not [Environment]::UserInteractive -or $nonInteractiveFlag -or [Console]::IsInputRedirected) {
        return 'unattended'
    }
    return 'interactive'
}

function Resolve-LogLevel {
    <#
    .SYNOPSIS
        Converts a level name or number to its numeric value, or returns -1 if invalid.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([string]$Value)

    $text = $Value.Trim().ToUpper()

    if ($logLevelMap.ContainsKey($text)) { return [int]$logLevelMap[$text] }

    $number = 0
    if ([int]::TryParse($text, [ref]$number) -and $number -ge 0 -and $number -le 7) {
        if ($number -eq 0) { return [int]$logLevelMap['NONE'] }
        return $number
    }
    return -1
}

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
function Invoke-LogRotation {
    <#
    .SYNOPSIS
        Rotates the log file when it has grown past the size limit.
    .DESCRIPTION
        Name.log becomes Name.1.log, Name.1.log becomes Name.2.log, and so on. The oldest
        copy beyond $LogArchivesToKeep is deleted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [int]$MaxSizeMB,
        [int]$Keep
    )

    if ($MaxSizeMB -le 0 -or $Keep -le 0) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    if ((Get-Item -LiteralPath $Path).Length -lt ($MaxSizeMB * 1MB)) { return }

    $folder = Split-Path -Path $Path -Parent
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $ext = [System.IO.Path]::GetExtension($Path)

    for ($i = $Keep; $i -ge 1; $i--) {
        if ($i -eq 1) { $source = $Path }
        else { $source = Join-Path -Path $folder -ChildPath ('{0}.{1}{2}' -f $base, ($i - 1), $ext) }
        $target = Join-Path -Path $folder -ChildPath ('{0}.{1}{2}' -f $base, $i, $ext)

        if (Test-Path -LiteralPath $source) {
            if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force -ErrorAction Stop -WhatIf:$false }
            Move-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop -WhatIf:$false
        }
    }
}

function Initialize-ToolLogging {
    <#
    .SYNOPSIS
        Creates the log folder and file, rotating first if needed.
    .DESCRIPTION
        The file is created read-only to discourage accidental edits. Write-LogFile uses
        -Force to write past that attribute. Failure to create the log is a failed run.
        Logging is never gated behind WhatIf, so -WhatIf runs are logged too.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Logging is not available yet, so errors go straight to the console.')]
    [CmdletBinding()]
    param()

    try {
        $logFolder = Split-Path -Path $Script:LogPath -Parent
        [void][System.IO.Directory]::CreateDirectory($logFolder)

        try {
            Invoke-LogRotation -Path $Script:LogPath -MaxSizeMB $LogMaxSizeMB -Keep $LogArchivesToKeep
        }
        catch {
            Write-Host ('Log rotation failed, continuing with the current file: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
        }

        if (-not (Test-Path -LiteralPath $Script:LogPath -PathType Leaf)) {
            [System.IO.File]::Create($Script:LogPath).Dispose()
            Set-ItemProperty -LiteralPath $Script:LogPath -Name IsReadOnly -Value $true -WhatIf:$false
        }
    }
    catch {
        Write-Host ('Unable to create the log file {0}: {1}' -f $Script:LogPath, $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}

function Write-LogFile {
    <#
    .SYNOPSIS
        Writes a message to the log file, subject to the configured logging level.
    .DESCRIPTION
        Appends a timestamped, level-tagged, single-line entry. The message is only written
        if its level is at or above $Script:LogThreshold. Secrets are masked first when
        $RedactLogSecrets is on.
    .PARAMETER message
        The text to log.
    .PARAMETER level
        Debug, Verbose, Info, Warn, Error or Critical.
    .EXAMPLE
        Write-LogFile -level Info -message 'Scan completed successfully.'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$message,
        [Parameter(Mandatory)]
        [ValidateSet('Debug', 'Verbose', 'Info', 'Warn', 'Error', 'Critical')]
        [string]$level
    )

    $levelName = $level.ToUpper()
    if ($logLevelMap[$levelName] -ge $Script:LogThreshold) {
        $singleLine = (Protect-LogText -Text $message) -replace '[\r\n]+', ' '
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        $line = '{0} | [{1}] | {2}' -f $timestamp, $levelName, $singleLine
        Add-Content -LiteralPath $Script:LogPath -Value $line -Encoding UTF8 -Force -ErrorAction Stop -WhatIf:$false
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Logs a message to the log file and echoes it to the console.
    .DESCRIPTION
        Calls Write-LogFile, then echoes the same message to the console if its level meets
        the logging threshold. -Success only changes the console colour. The entry is still
        logged at the level supplied. Never gated behind WhatIf: logging always runs.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output is intentional; the log file is the durable record.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [ValidateSet('Debug', 'Verbose', 'Info', 'Warn', 'Error', 'Critical')]
        [string]$Level = 'Info',

        [switch]$Success
    )

    $safeMessage = Protect-LogText -Text $Message

    try {
        Write-LogFile -level $Level -message $safeMessage
    }
    catch {
        Write-Host ('[LOGGING FAILURE] {0}' -f $_.Exception.Message) -ForegroundColor Red
    }

    if ($logLevelMap[$Level.ToUpper()] -ge $Script:LogThreshold) {
        $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level.ToUpper(), $safeMessage

        if ($Success) { Write-Host $line -ForegroundColor Green }
        else {
            switch ($Level) {
                'Critical' { Write-Host $line -ForegroundColor Red }
                'Error' { Write-Host $line -ForegroundColor Red }
                'Warn' { Write-Host $line -ForegroundColor Yellow }
                'Debug' { Write-Host $line -ForegroundColor DarkGray }
                'Verbose' { Write-Host $line -ForegroundColor DarkGray }
                default { Write-Host $line }
            }
        }
    }
}

# ------------------------------------------------------------------------------
# Windows event log
# ------------------------------------------------------------------------------
function Initialize-EventLogSource {
    <#
    .SYNOPSIS
        Registers the event source if possible and records whether event writes will work.
    .DESCRIPTION
        Registration needs an elevated session, and the event log cmdlets do not exist in
        PowerShell 7. Either way the scan carries on and event writes are skipped.
    #>
    [CmdletBinding()]
    param()

    $Script:eventLogReady = $false

    if (-not (Get-Command -Name Write-EventLog -ErrorAction SilentlyContinue)) {
        Write-LogFile -level Debug -message 'Event log cmdlets are not available in this PowerShell edition. Event log writes are skipped.'
        return
    }

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
        }
        $Script:eventLogReady = $true
    }
    catch {
        Write-LogFile -level Warn -message "Could not register event log source '$EventLogSource': $($_.Exception.Message). Event log writes will be skipped until this is resolved (requires an elevated session)."
    }
}

function Write-LogEvent {
    <#
    .SYNOPSIS
        Writes an entry to the Windows Application Event Log.
    .DESCRIPTION
        Wraps Write-EventLog under the script's registered source. Used for the subset of
        conditions worth surfacing to central monitoring, distinct from the full file log.
    .PARAMETER eventID
        The event ID to log. See the tool README for the event ID map.
    .PARAMETER entryType
        Error, Warning, Information, SuccessAudit or FailureAudit.
    .EXAMPLE
        Write-LogEvent -eventID 3010 -entryType Error -message 'Entra app expiry scan failed.'
    #>
    [CmdletBinding()]
    param (
        [string]$logSource = $EventLogSource,
        [string]$logName = $EventLogName,
        [Parameter(Mandatory)]
        [string]$message,
        [Parameter(Mandatory)]
        [int]$eventID,
        [Parameter(Mandatory)]
        [System.Diagnostics.EventLogEntryType]$entryType
    )

    # Event messages are capped by Windows at roughly 31,800 characters.
    $text = Protect-LogText -Text $message
    if ($text.Length -gt 30000) { $text = $text.Substring(0, 30000) }

    Write-EventLog -LogName $logName -Source $logSource -EntryType $entryType -Category 0 -EventId $eventID -Message $text
}

function Send-LogEvent {
    <#
    .SYNOPSIS
        Writes an Application event log entry if the event source is available.
    .DESCRIPTION
        Wraps Write-LogEvent so a missing event source never stops the scan. Failures are
        logged as Warn.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.EventLogEntryType]$EntryType
    )

    if (-not $Script:eventLogReady) {
        Write-LogFile -level Debug -message ('Event {0} not written, event log source unavailable.' -f $EventId)
        return
    }

    try {
        Write-LogEvent -eventID $EventId -entryType $EntryType -message $Message
    }
    catch {
        Write-LogFile -level Warn -message ('Event log write failed for event {0}: {1}' -f $EventId, $_.Exception.Message)
    }
}

# ------------------------------------------------------------------------------
# Report folder and retention
# ------------------------------------------------------------------------------
function Initialize-OutputFolder {
    <#
    .SYNOPSIS
        Creates the report folder, refusing a drive root.
    #>
    [CmdletBinding()]
    param()

    # Folder creation is deliberately not gated: reports need somewhere to go.
    $root = [System.IO.Path]::GetPathRoot($Script:ReportPath)
    if ($Script:ReportPath.TrimEnd('\', '/') -eq $root.TrimEnd('\', '/')) {
        throw ('ReportPath {0} is a drive root. Choose a subfolder.' -f $Script:ReportPath)
    }

    [void][System.IO.Directory]::CreateDirectory($Script:ReportPath)
}

function Remove-ExpiredOutput {
    <#
    .SYNOPSIS
        Removes this tool's old .csv and .html reports.
    .DESCRIPTION
        Only files named "<ScriptName>_*" are considered, so other files in the folder are
        never touched. Drive roots are refused.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Folder,

        [Parameter(Mandatory = $true)]
        [int]$OlderThanDays
    )

    if ($OlderThanDays -le 0) {
        Write-Log 'Retention cleanup disabled (RetentionDays is 0).' -Level Debug
        return
    }

    $cutoff = (Get-Date).AddDays(-$OlderThanDays)
    $namePattern = '{0}_*' -f $ScriptName
    $removed = 0

    foreach ($path in $Folder) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            Write-Log 'Retention cleanup skipped: the folder path is empty.' -Level Warn
            continue
        }

        $root = [System.IO.Path]::GetPathRoot($path)
        if ($path.TrimEnd('\', '/') -eq $root.TrimEnd('\', '/')) {
            Write-Log ('Retention cleanup skipped for {0}: it is a drive root.' -f $path) -Level Warn
            continue
        }

        try {
            $oldFiles = Get-ChildItem -LiteralPath $path -File -ErrorAction Stop |
                Where-Object { $_.LastWriteTime -lt $cutoff -and $_.Name -like $namePattern -and $_.Extension -in '.csv', '.html' }

            foreach ($file in $oldFiles) {
                if ($PSCmdlet.ShouldProcess($file.FullName, 'Remove report past retention period')) {
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                    $removed++
                    Write-Log ('Removed old file: {0}' -f $file.FullName) -Level Debug
                }
            }
        }
        catch {
            Write-Log ('Retention cleanup failed in {0}: {1}' -f $path, $_.Exception.Message) -Level Warn
        }
    }

    Write-Log ('Retention cleanup complete. Reports removed: {0} (older than {1} days).' -f $removed, $OlderThanDays)
}

# ------------------------------------------------------------------------------
# Update check and telemetry
# Both run after the scan, are optional, and can never affect its result. Every
# failure is logged at Debug and ignored. Nothing is downloaded or installed.
# ------------------------------------------------------------------------------
function Enable-ModernTls {
    <#
    .SYNOPSIS
        Makes sure TLS 1.2 is allowed on Windows PowerShell 5.1. PowerShell 7 needs nothing.
    #>
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -ne 'Core') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
}

function Get-LatestToolVersion {
    <#
    .SYNOPSIS
        Reads the latest published version of this tool from the static version file.
    .DESCRIPTION
        Makes a plain GET request with a generic User-Agent and sends no data. Remote
        values are cleaned before use. Returns $null if the check fails for any reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    try {
        Enable-ModernTls
        $response = Invoke-RestMethod -Uri $UpdateCheckUrl -Method Get -TimeoutSec 5 -UserAgent $NetworkUserAgent -ErrorAction Stop
        $entry = $response.tools.$ScriptName

        if (-not $entry) {
            Write-Log ('Update check: {0} is not listed in the version file.' -f $ScriptName) -Level Debug
            return $null
        }

        $latestText = Limit-Text -Text ([string]$entry.version) -Max 32
        $latest = [version](($latestText -split '-')[0])
        $current = [version](($ScriptVersion -split '-')[0])

        return [pscustomobject]@{
            Version  = $latestText
            Released = Limit-Text -Text ([string]$entry.released) -Max 32
            Url      = Limit-Text -Text ([string]$entry.url) -Max 300
            Newer    = ($latest -gt $current)
        }
    }
    catch {
        Write-Log ('Update check failed: {0}' -f $_.Exception.Message) -Level Debug
        return $null
    }
}

function Show-UpdateNotice {
    <#
    .SYNOPSIS
        Tells the user a newer version exists and, in an interactive session only, offers to
        open the release page.
    .DESCRIPTION
        The link is only shown and opened if it matches $UpdateUrlAllowPattern, in case the
        version file were ever tampered with.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Latest
    )

    $urlIsSafe = $Latest.Url -match $UpdateUrlAllowPattern

    if ($urlIsSafe) {
        Write-Log ('Update available: {0} {1} (you have {2}). Release page: {3}' -f $ScriptName, $Latest.Version, $ScriptVersion, $Latest.Url)
    }
    else {
        Write-Log ('Update available: {0} {1} (you have {2}). The version file gave no trusted release link, so none is shown.' -f $ScriptName, $Latest.Version, $ScriptVersion) -Level Warn
    }

    # Never prompt in unattended runs or dry runs.
    if ($script:RunMode -ne 'interactive' -or $WhatIfPreference -or -not $urlIsSafe) {
        return
    }

    $answer = Read-Host 'Open the release page in your browser now? (y/N)'
    if ($answer.Trim().ToLower() -in 'y', 'yes') {
        Start-Process -FilePath $Latest.Url
    }
}

function Send-ToolTelemetry {
    <#
    .SYNOPSIS
        Sends anonymous usage telemetry.
    .DESCRIPTION
        Sends tool name, tool version, OS caption and build, PowerShell version and
        edition, timezone ID and run mode. The server adds the country from the request
        and a daily salted hash of the IP address. No tenant, user, host or application
        data is ever included. See TELEMETRY.md in the repository root.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    try {
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $osCaption = [string]$osInfo.Caption
            $osBuild = [string]$osInfo.BuildNumber
        }
        catch {
            $osCaption = [Environment]::OSVersion.VersionString
            $osBuild = [string][Environment]::OSVersion.Version.Build
        }

        if ($PSVersionTable.PSEdition -eq 'Core') { $_psEdition = 'Core' } else { $_psEdition = 'Desktop' }

        $payload = [ordered]@{
            tool      = $ScriptName
            version   = $ScriptVersion
            os        = Limit-Text -Text $osCaption -Max 64
            osBuild   = Limit-Text -Text $osBuild -Max 32
            psVersion = Limit-Text -Text $PSVersionTable.PSVersion.ToString() -Max 32
            psEdition = $_psEdition
            timezone  = Limit-Text -Text ([TimeZoneInfo]::Local.Id) -Max 64
            runMode   = $script:RunMode
        }

        $json = $payload | ConvertTo-Json -Compress
        Write-Log ('Telemetry payload: {0}' -f $json) -Level Debug

        if ($PSCmdlet.ShouldProcess($TelemetryUrl, 'Send anonymous usage telemetry')) {
            Enable-ModernTls
            $bytes = [Text.Encoding]::UTF8.GetBytes($json)
            Invoke-RestMethod -Uri $TelemetryUrl -Method Post -Body $bytes -ContentType 'application/json' -TimeoutSec 5 -UserAgent $NetworkUserAgent -ErrorAction Stop | Out-Null
            Write-Log 'Telemetry sent.' -Level Debug
        }
    }
    catch {
        Write-Log ('Telemetry not sent: {0}' -f $_.Exception.Message) -Level Debug
    }
}

function Invoke-UpdateCheckAndTelemetry {
    <#
    .SYNOPSIS
        Runs the optional update check and telemetry. Call it last in the script.
    .DESCRIPTION
        Telemetry is on by default (opt-out). It is skipped if -DisableTelemetry is used or
        either the tool's opt-out variable or DO_NOT_TRACK is set to 1 or true.
    #>
    [CmdletBinding()]
    param()

    if ($DisableUpdateCheck) {
        Write-Log 'Update check disabled.' -Level Debug
    }
    else {
        $latest = Get-LatestToolVersion
        if ($latest -and $latest.Newer) {
            Show-UpdateNotice -Latest $latest
        }
        elseif ($latest) {
            Write-Log ('Update check: {0} {1} is the latest version.' -f $ScriptName, $ScriptVersion) -Level Debug
        }
    }

    $toolOptOut = [Environment]::GetEnvironmentVariable($TelemetryOptOutEnvVar)
    $doNotTrack = [Environment]::GetEnvironmentVariable('DO_NOT_TRACK')
    $telemetryOff = $DisableTelemetry -or ($toolOptOut -in '1', 'true') -or ($doNotTrack -in '1', 'true')

    if ($telemetryOff) {
        Write-Log 'Telemetry disabled.' -Level Debug
    }
    else {
        Write-Log ('Anonymous usage telemetry is on. Disable it with -DisableTelemetry, {0}=1 or DO_NOT_TRACK=1. See {1} in the repository root.' -f $TelemetryOptOutEnvVar, $TelemetryDocName)
        Send-ToolTelemetry
    }
}

# ------------------------------------------------------------------------------
# Initialisation (runs when the script starts)
# ------------------------------------------------------------------------------
$configProblems = @(Test-ToolConfig)
if ($configProblems.Count -gt 0) {
    foreach ($problem in $configProblems) {
        Write-Host ('Configuration error: {0}' -f $problem) -ForegroundColor Red
    }
    exit 1
}

$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Apply CONFIG defaults for anything not supplied, then resolve to full paths. The
# PowerShell location is used for relative paths, not the .NET working directory.
if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = $DefaultLogPath }
if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = $DefaultReportPath }
if (-not $PSBoundParameters.ContainsKey('RetentionDays')) { $RetentionDays = $DefaultRetentionDays }
$LogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
$ReportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)

# Run mode: a script may preset $script:RunMode to override detection.
if ($null -eq (Get-Variable -Name RunMode -Scope Script -ValueOnly -ErrorAction SilentlyContinue)) {
    $script:RunMode = Get-RunMode
}

# Logging level: an explicit -LoggingLevel wins, then -Debug or -Verbose, then the default.
$defaultLevelName = $DefaultLoggingLevel
if ($VerbosePreference -ne 'SilentlyContinue') { $defaultLevelName = 'VERBOSE' }
if ($DebugPreference -ne 'SilentlyContinue') { $defaultLevelName = 'DEBUG' }

if ([string]::IsNullOrWhiteSpace($LoggingLevel)) { $requestedLevel = $defaultLevelName } else { $requestedLevel = $LoggingLevel }

$resolvedLevel = Resolve-LogLevel -Value $requestedLevel
$levelWarning = $null
if ($resolvedLevel -lt 1) {
    $levelWarning = 'Unrecognised logging level "{0}". Using INFO.' -f (Limit-Text -Text $requestedLevel -Max 32)
    $resolvedLevel = $logLevelMap['INFO']
}
$Script:LogThreshold = $resolvedLevel
$levelName = $logLevelMap.Keys | Where-Object { $logLevelMap[$_] -eq $Script:LogThreshold } | Select-Object -First 1

Initialize-ToolLogging
Initialize-EventLogSource

if ($levelWarning) { Write-Log $levelWarning -Level Warn }

Write-LogFile -level Verbose -message 'Logging has been configured'
Write-LogFile -level Debug -message ('logPath={0}; eventLogSource={1}; eventLogName={2}; template={3}; runMode={4}' -f $LogPath, $EventLogSource, $EventLogName, $TemplateVersion, $script:RunMode)
Write-LogFile -level Info -message ('{0} {1} starting - logging level is {2}' -f $ScriptName, $ScriptVersion, $levelName)
#endregion PC-TEMPLATE v1.1.1

# ==============================================================================
# Script body starts here
# ==============================================================================

function Exit-WithError {
    <#
    .SYNOPSIS
        Logs a Critical message, optionally writes an Error event, and exits with code 1.
    .DESCRIPTION
        Replaces the pre-template behaviour where Write-Log -Level CRITICAL also exited
        the script. The main body runs inside try/finally, so the update check and
        telemetry still run on this exit path.
    .PARAMETER Message
        The reason the run failed.
    .PARAMETER EventId
        Optional Application event ID to write as an Error entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [int]$EventId = 0
    )

    Write-Log $Message -Level Critical
    if ($EventId -gt 0) {
        Send-LogEvent -EventId $EventId -EntryType Error -Message $Message
    }
    exit 1
}
##################################################
# Functions
##################################################

# Builds config file and exits
function New-SignFileConfig {
    <#
    .SYNOPSIS
        Writes a config file populated with the script's current parameter values.
    .DESCRIPTION
        Builds a JSON config file from whatever values the top-level script
        parameters currently hold, defaults where set, $null where not. Always
        writes unconditionally, since this function only ever runs as a direct
        result of -BuildConfig, at which point any existing file at the target
        path is deliberately being replaced.
    .EXAMPLE
        New-SignFileConfig

        Writes a config file to $ConfigFilePath using the current session's
        top-level parameter values (RequireADCSCertificate, CompanyName, etc.).
        Only ever called internally when -BuildConfig is passed to the script.
    .OUTPUTS
        None. Writes the config file to disk at $ConfigFilePath.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($RequireADCSCertificate.IsPresent) {
        $RequireADCSCertificateJSON = $true
    }
    else {
        $RequireADCSCertificateJSON = $null
    }
    if ($UsePersonalCertificate.IsPresent) {
        $UsePersonalCertificateJSON = $true
    }
    else {
        $UsePersonalCertificateJSON = $null
    }
    $configTemplate = [ordered]@{
        RequireADCSCertificate = $RequireADCSCertificateJSON 
        UsePersonalCertificate = $UsePersonalCertificateJSON
        CompanyName            = $CompanyName
        ValidityLength         = $CertificateValidity
        KeyLength               = $KeyLength
        CertTemplate            = $CodeSigningTemplate
        TimestampingAuthority   = $TimestampingAuthority
    }
    if ($PSCmdlet.ShouldProcess($ConfigFilePath, 'Write config file')) {
        $configTemplate | ConvertTo-Json -Depth 3 | Set-Content -Path $ConfigFilePath -Encoding UTF8 -Force
        Write-Log "Config file written to '$ConfigFilePath'."
    }
}

# Ensure all prerequesites are available
function Test-Prerequisites {
    <#
    .SYNOPSIS
        Verifies the PKI module is available before the script proceeds.
    .DESCRIPTION
        Checks whether the PKI module (which provides Get-Certificate, used for
        ADCS enrollment) is present on the machine. This is a Windows-native
        module shipped with AD CS Remote Server Administration Tools, not
        something installable from the PowerShell Gallery, so a missing module
        is reported with guidance on enabling the correct Windows feature rather
        than attempted installation.
    .EXAMPLE
        Test-Prerequisites

        Checks for the PKI module and throws a terminating error with
        remediation guidance if it isn't available.
    .OUTPUTS
        None. Throws a terminating error if the PKI module is unavailable.
    #>
    [CmdletBinding()]
    param()
    if (-not (Get-Module -ListAvailable -Name PKI)) {
        Exit-WithError "The PKI module is not available on this machine. It ships with the AD CS Remote Server Administration Tools feature (Windows 8.1 / Server 2012 R2 and later). Enable it via 'Add-WindowsFeature RSAT-ADCS' (Server) or the Windows Optional Features UI (client), then re-run this script."
    }
    Import-Module -Name PKI -Scope Local -ErrorAction Stop
    Write-Log "PKI module loaded successfully."
}

# Script Variables
function Get-ScriptVariables {
    <#
    .SYNOPSIS
        Resolves effective script settings from command line parameters and an optional config file.

    .DESCRIPTION
        Merges command line parameters with a JSON config file, where present.
        For policy-governed settings, config file values always take precedence
        over the command line, since the intent is that an organisation's IT
        function controls these centrally and individual developers cannot
        silently override them by passing different parameters. A warning is
        written whenever a command line value is overridden by config, so the
        discrepancy is visible rather than silent.

    .PARAMETER RequireADCSCertificate
        Command line value for the RequireADCSCertificate policy setting.

    .PARAMETER UsePersonalCertificate
        Command line value for the UsePersonalCertificate policy setting.

    .PARAMETER ConfigFilePath
        Path to the JSON config file to check for policy overrides.

    .PARAMETER validityLength
        Command line value for self-signed certificate validity, in years.

    .PARAMETER certTemplate
        Command line value for the ADCS certificate template name.

    .PARAMETER companyName
        Command line value for the certificate subject name.

    .PARAMETER keyLength
        Command line value for the self-signed certificate key length, in bits.

    .PARAMETER timestampServer
        Command line value for the RFC 3161 timestamp server URL.

    .EXAMPLE
        Get-ScriptVariables -ConfigFilePath .\SignFileConfig.json -CompanyName 'Contoso IT' -KeyLength 2048

        Resolves the effective settings, merging the supplied command line
        values with any policy-governed overrides found in the config file.

    .OUTPUTS
        System.Management.Automation.PSCustomObject with properties:
        RequireADCSCertificate, CertificateStore, CompanyName, KeyLength,
        ValidityLength, CertTemplate, TimestampServer.
    #>
    [CmdletBinding()]
    param(
        [switch]$RequireADCSCertificate,
        [switch]$UsePersonalCertificate,
        [string]$ConfigFilePath,
        [string]$validityLength,
        [string]$certTemplate,
        [string]$companyName,
        [int]$keyLength,
        [string]$timestampServer
    )
    <## 
    Policy-governed settings. If a config file is present, its values always win over
    whatever was passed at the command line, since the intent is that IT controls these
    centrally and developers cannot silently override them by passing different switches.
    ##>
    if (Test-Path -Path $configFilePath) {
        Write-Log "Loading configuration from $($configFilePath)"

        try {
            $config = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json -ErrorAction Stop
        } 
        catch {
            Exit-WithError "Failed to parse config file $($configFilePath): $($_.Exception.Message)"
        }

        if ($null -ne $config.RequireADCSCertificate) {
            if ($RequireADCSCertificate.IsPresent -and (-not $config.RequireADCSCertificate)) {
                    Write-Log "RequireADCSCertificate was requested at the command line but config policy overrides it. Policy value in use: $($config.RequireADCSCertificate)." -Level WARN
            }
            $requireADCSCertificate = [bool]$config.RequireADCSCertificate
        }

        if ($null -ne $config.UsePersonalCertificate) {
            $usePersonalCertificate = [bool]$config.UsePersonalCertificate
        } 
        
        if ($null -ne $config.CompanyName) {
            $companyName = $config.CompanyName
        }

        if ($null -ne $config.ValidityLength) {
            $validityLength = $config.ValidityLength
        }

        if ($null -ne $config.KeyLength) {
            $keyLength = $config.KeyLength
        }

        if ($null -ne $config.CertTemplate) {
            $certTemplate = $config.CertTemplate
        }

        if ($null -ne $config.TimestampingAuthority) {
            $timestampServer = $config.TimestampingAuthority
        }

    }
    else {
        Write-Log "No config file found at $($ConfigFilePath). Using command line parameters and defaults."
    }

    $CertificateStore = if ($UsePersonalCertificate) { 'Cert:\CurrentUser\My' } else { 'Cert:\LocalMachine\My' }

    $variables = [PSCustomObject]@{
        RequireADCSCertificate = $RequireADCSCertificate
        CertificateStore = $CertificateStore
        CompanyName = $companyName
        KeyLength = $keyLength
        ValidityLength = $validityLength
        CertTemplate = $certTemplate
        TimestampServer = $timestampServer
    }
    return $variables
}

# Get existing code signing cert
function Get-ExistingCodeSigningCert {
    <#
    .SYNOPSIS
        Checks the certificate store for an existing, usable code signing certificate.

    .DESCRIPTION
        Searches the specified certificate store for certificates with the code
        signing Enhanced Key Usage, a usable private key, and remaining validity.
        Returns the certificate with the longest remaining validity if more than
        one match is found. No side effects.

    .PARAMETER CertificateStore
        Certificate store path to search, e.g. Cert:\LocalMachine\My.

    .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2 if a
        usable certificate is found, otherwise $false.

    .NOTES
        Returns $false rather than $null on failure to find a usable certificate,
        by design, to give calling code a simple boolean-style check while still
        returning a rich certificate object on success.
    #>
    [CmdletBinding()]
    [OutputType('System.Security.Cryptography.X509Certificates.X509Certificate2', 'System.Boolean')]
    param(
        [Parameter()]
        $CertificateStore
    )

    try {
        Write-Log "Checking for existing code signing certificate"
        $codeSigningCerts = Get-ChildItem $CertificateStore -CodeSigningCert

        if ($codeSigningCerts) {
            $codeSigningCert = $codeSigningCerts | Where-Object { $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey -eq $true } | Select-Object -First 1
        }
        
        if ($codeSigningCert) {
            Write-Log -Message "Found existing usable code signing certificate: $($codeSigningCert.Thumbprint), expires $($codeSigningCert.NotAfter)."
            return $codeSigningCert
        }
        else {
            Write-Log -Message "No usable existing code signing certificate found in $CertificateStore."
            return $false
        }
    }
    catch {
    Write-Log "Checking for existing code signing certificate failed: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

# Generates and installs new code signing cert
function New-CodesigningCert {
    <#
    .SYNOPSIS
        Obtains a code signing certificate from ADCS, or creates a self-signed one.

    .DESCRIPTION
        Attempts to request a certificate from Active Directory Certificate
        Services (ADCS) using the PKI module's Get-Certificate cmdlet, relying
        on default AD-integrated enrollment discovery (no explicit CEP/CES URL
        is used). Availability is checked first via 'certutil -ping' so an
        unreachable CA fails fast rather than hanging.

        If ADCS is unreachable, or the request fails or is denied, a self-signed
        certificate is created and trusted instead (added to both the Root and
        TrustedPublisher stores in the same scope as CertStore), unless
        -ADCSRequired is set, in which case the failure is thrown rather than
        falling back.

        If a request comes back Pending (CA manager approval required), the
        request's thumbprint is saved to a state file so a subsequent run can
        retrieve the issued certificate without submitting a duplicate request.

    .PARAMETER CertStore
        Certificate store to request into or create the certificate in. Must end
        in \My, since Get-Certificate only supports the My store. Alias:
        CertificateStore.

    .PARAMETER ADCSRequired
        If set, a certificate must come from ADCS. Any ADCS failure (CA
        unreachable, request denied, unexpected status) is thrown rather than
        falling back to self-signed.

    .PARAMETER CompanyName
        Subject name (CN) for the requested or created certificate.

    .PARAMETER KeyLength
        RSA key length, in bits, for a self-signed certificate. Has no effect on
        an ADCS-issued certificate, since that's controlled by the template.

    .PARAMETER ValidityLength
        Validity period, in years, for a self-signed certificate. Has no effect
        on an ADCS-issued certificate.

    .PARAMETER PendingStateFile
        Path used to persist a Pending ADCS request's thumbprint between runs.
        Defaults to a file alongside this script.

    .PARAMETER CertTemplate
        ADCS certificate template name to request against (not its display
        name, if they differ).

    .EXAMPLE
        New-CodesigningCert -CertStore 'Cert:\LocalMachine\My' -CompanyName 'Contoso IT' -CertTemplate 'CodeSigning'

        Attempts to obtain a certificate from ADCS using the 'CodeSigning'
        template, falling back to a self-signed certificate if ADCS is
        unreachable or the request fails.

    .EXAMPLE
        New-CodesigningCert -CertStore 'Cert:\LocalMachine\My' -CompanyName 'Contoso IT' -ADCSRequired -WhatIf

        Shows what would happen when requiring an ADCS-issued certificate,
        without making any actual changes.

    .OUTPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2, or
        nothing if a request is left Pending CA manager approval.

    .NOTES
        The ADCS request path has been validated against Microsoft's documented
        cmdlet reference for Get-Certificate, but has not been tested end-to-end
        against a live CA. Validate template name, policy server reachability,
        and approval workflow in a test environment before relying on this in
        production.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType('System.Security.Cryptography.X509Certificates.X509Certificate2')]
    param(
        [Alias("CertificateStore")]
        [Parameter(
            Mandatory    
        )]
        [string]$CertStore,

        [Parameter()]
        [switch]$ADCSRequired,
        
        [Parameter()]
        [string]$CompanyName,
        
        [Parameter()]
        [ValidateSet(2048, 3072, 4096)]
        [int]$KeyLength,
        
        [Parameter()]
        [ValidateRange(1, 25)]
        [int]$ValidityLength,

        [Parameter()]
        [string]$PendingStateFile = (Join-Path -Path $PSScriptRoot -ChildPath 'pending-request-state.json'),

        [Parameter()]
        [string]$CertTemplate
    )

    # Define the certificate store

    if ($CertStore -like "*LocalMachine*") {
        $Scope = "LocalMachine"
    }
    else {
        $Scope = "CurrentUser"
    }

    # If requesting certificate from ADCS
    try {
        if ($CertStore -notmatch '\\My$') {
            throw "Get-Certificate only supports the 'My' certificate store. CertStore was $($CertStore)."
        }

        $output = certutil -ping 2>&1
        $ADCSAvailable = $LASTEXITCODE -eq 0

        if (-not $ADCSAvailable) {
            throw "No certification authority reachable via certutil -ping: $($output)"
        }

        if (Test-Path -Path $PendingStateFile) {
            Write-Log "Found pending request state file at '$PendingStateFile', checking status."
            $state = Get-Content -Path $PendingStateFile -Raw | ConvertFrom-Json
            $requestPath = "Cert:\$Scope\Request\$($state.Thumbprint)"
            $existingRequest = Get-ChildItem -Path $requestPath -ErrorAction SilentlyContinue

            if ($existingRequest) {
                if ($PSCmdlet.ShouldProcess($state.Thumbprint, 'Retrieve pending ADCS certificate request')) {
                    $result = Get-Certificate -Request $existingRequest -ErrorAction Stop
                    if ($result.Status -eq 'Issued') {
                        Remove-Item -Path $PendingStateFile -Force
                        $newCert = $result.Certificate
                        Write-Log -Message "Previously pending ADCS request (thumbprint $($state.Thumbprint)) is now issued."
                    }
                    else {
                        Write-Log "Request $($state.Thumbprint) is still $($result.Status). Re-run once approved." -Level WARN
                        return
                    }
                }
            }
            else {
                Write-Log 'Referenced pending request no longer exists, submitting fresh request.'
                Remove-Item -Path $PendingStateFile -Force
            }
        }

        if (-not $newCert) {
            if ($PSCmdlet.ShouldProcess("CN=$($CompanyName)", "Request code signing certificate from ADCS (template: $($CertTemplate))")) {
                $params = @{
                    Template          = $CertTemplate
                    SubjectName       = "CN=$CompanyName"
                    CertStoreLocation = $CertStore
                    ErrorAction       = 'Stop'
                }

                $result = Get-Certificate @params

                switch ($result.Status) {
                    'Issued' {
                        $newCert = $result.Certificate
                        Write-Log -Message "ADCS issued certificate $($newCert.Thumbprint) using template '$CertTemplate'."
                    }
                    'Pending' {
                        $thumbprint = $result.Request.Thumbprint
                        Write-Log "Request submitted but requires CA manager approval (thumbprint: $($thumbprint)). Re-run once approved." -Level WARN
                        @{ Thumbprint = $thumbprint; SubmittedUtc = (Get-Date).ToUniversalTime().ToString('o') } |
                            ConvertTo-Json | Set-Content -Path $PendingStateFile -Encoding UTF8
                        return
                    }
                    default {
                        throw "ADCS request returned unexpected status '$($result.Status)'."
                    }
                }
            }
        }
    }

    # If ADCS was unreachable or the request failed, fall back to self-signed
    catch {
        if ($ADCSRequired) {
            Exit-WithError "ADCSRequired is set but a certificate could not be obtained from ADCS: $($_.Exception.Message)"
        }

        Write-Log "ADCS certificate unavailable, falling back to self-signed: $($_.Exception.Message)" -Level WARN

        if ($PSCmdlet.ShouldProcess("CN=$CompanyName", 'Create self-signed code signing certificate')) {
            $newCert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$($CompanyName)" -CertStoreLocation $CertStore -KeySpec Signature -KeyUsage DigitalSignature -KeyLength $KeyLength -HashAlgorithm SHA256 -NotAfter ((Get-Date).AddYears($ValidityLength)) -FriendlyName "Self-signed code signing cert - generated $(Get-Date -Format 'yyyy-MM-dd')" -KeyExportPolicy Exportable
            Write-Log -Message "Self-signed certificate created: $($newCert.Thumbprint), expires $($newCert.NotAfter)." -Level WARN
        }
        $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::$Scope

        # Install cert in Root and Trusted Publishers
        foreach ($storeName in @('Root', 'TrustedPublisher')) {
            if ($PSCmdlet.ShouldProcess($newCert.Thumbprint, "Add to Cert:\$Scope\$storeName")) {
                $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
                try {
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $store.Add($newCert)
                    Write-Log "Added $($newCert.Thumbprint) to Cert:\$Scope\$storeName."
                }
                finally {
                    $store.Close()
                }
            }
        }
    }
    
    return $newCert
        
}

# Get file(s)
function Get-FileToSign {
    <#
    .SYNOPSIS
        Gets the file(s) to be signed, either from a parameter or an interactive file picker.
    .DESCRIPTION
        If -Path is supplied, validates and returns those paths. If not, opens a
        multi-select Windows file picker with filters for PowerShell-signable file
        types, a broader Authenticode-signable category, and an all-files fallback.
    .PARAMETER Path
        A file path supplied directly, e.g. from the command line. If
        omitted, an interactive file picker is shown instead.
    .EXAMPLE
        Get-FileToSign -Path .\Deploy-Server.ps1

        Validates and returns the resolved path to the specified file.
    .EXAMPLE
        Get-FileToSign

        Opens an interactive, multi-select file picker filtered to
        PowerShell-signable and general Authenticode-signable file types.
    .OUTPUTS
        System.String[]
    .NOTES
        Requires PowerShell to be running in a Single-Threaded Apartment (STA) for the
        file picker dialog to behave reliably. Windows PowerShell 5.1 defaults to STA.
        PowerShell 7+ defaults to MTA, and will need to be started with 'pwsh.exe -STA'
        for the dialog to work correctly.
        PowerShell-signable extension list combines Microsoft's documented set
        (.ps1, .psm1, .psd1, .ps1xml, .cdxml, .xaml) with the SIP-registered extensions
        identified by community research (.psc1, .mof). Worth confirming against
        Get-AuthenticodeSignature in your environment if a type you rely on is missing.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter()]
        [string]$Path
    )
        if ($Path) {
        if (-not (Test-Path -Path $Path -PathType Leaf)) {
            Write-Log "No file found at '$Path'. Falling back to interactive file picker." -Level WARN
        }
        else {
            return @((Resolve-Path -Path $Path).ProviderPath)
        }
    }
    else {
        Write-Log "No -Path supplied, opening file picker."
    }
    if ($script:RunMode -ne 'interactive') {
        Exit-WithError "The file picker cannot be shown in an unattended session. Supply -Path with the file to sign."
    }
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        Write-Log "PowerShell is not running in STA mode. The file picker may fail or behave unexpectedly. If it does, restart with 'pwsh.exe -STA' (or 'powershell.exe -STA' on Windows PowerShell)." -Level WARN
    }
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = [System.Windows.Forms.OpenFileDialog]::new()
    $dialog.Title = 'Select file(s) to sign'
    $dialog.Multiselect = $true
    $dialog.Filter = 'PowerShell Files (*.ps1;*.psm1;*.psd1;*.ps1xml;*.psc1;*.cdxml;*.mof;*.xaml)|*.ps1;*.psm1;*.psd1;*.ps1xml;*.psc1;*.cdxml;*.mof;*.xaml|Other Signable Files (*.exe;*.dll;*.msi;*.cat;*.js;*.vbs;*.ocx;*.cab)|*.exe;*.dll;*.msi;*.cat;*.js;*.vbs;*.ocx;*.cab|All Files (*.*)|*.*'
    $dialog.FilterIndex = 1
    $result = $dialog.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK -or $dialog.FileNames.Count -eq 0) {
        Write-Log "No files selected." -Level WARN
        return @()
    }
    Write-Log "$($dialog.FileNames.Count) file(s) selected."
    return $dialog.FileNames
}

# Sign file(s)
function Set-FileSignature {
    <#
    .SYNOPSIS
        Signs one or more files with a code signing certificate.
    .DESCRIPTION
        Wraps Set-AuthenticodeSignature for each file in the supplied list,
        optionally applying an RFC 3161 timestamp. Each file's signing result is
        checked explicitly (Set-AuthenticodeSignature does not throw on failure
        by default), and a summary of successes and failures is returned so the
        caller can decide how to handle partial failure, including setting an
        appropriate exit code for unattended runs.
    .PARAMETER FileList
        One or more file paths to sign.
    .PARAMETER SigningCertificate
        The code signing certificate to sign with.
    .PARAMETER TimestampServer
        URL of an RFC 3161 timestamp server. If omitted, files are signed
        without a timestamp, meaning each signature's validity becomes tied to
        the signing certificate's own expiry rather than remaining valid
        indefinitely.
    .OUTPUTS
        System.Management.Automation.PSCustomObject with properties: Total,
        Succeeded, Failed (an array of file paths that failed to sign).
    .EXAMPLE
        Set-FileSignature -FileList $files -SigningCertificate $cert -TimestampServer 'http://timestamp.digicert.com'
        Signs each file in $files with $cert, applying a trusted timestamp.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string[]]$FileList,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,
        [Parameter()]
        [string]$TimestampServer
    )
        $failures = @()
    foreach ($file in $FileList) {
        $signParams = @{
            Certificate   = $SigningCertificate
            FilePath      = $file
            IncludeChain  = 'All'
            HashAlgorithm = 'SHA256'
        }
        if ($TimestampServer) {
            $signParams['TimestampServer'] = $TimestampServer
        }
        if ($PSCmdlet.ShouldProcess($file, 'Sign file')) {
            $result = Set-AuthenticodeSignature @signParams
            if ($result.Status -eq 'Valid') {
                Write-Log "Signed successfully: $($file)"
            }
            else {
                $failures += $file
                Write-Log "Failed to sign $($file). Status: $($result.Status). $($result.StatusMessage)" -Level WARN
            }
        }
    }
    if ($failures) {
        Write-Log "$($failures.Count) of $($fileList.Count) file(s) failed to sign." -Level WARN
    }
    return [PSCustomObject]@{
        Total     = $fileList.Count
        Succeeded = $fileList.Count - $failures.Count
        Failed    = $failures
    }
}

##################################################
# Script
##################################################

# Build Config file
if ($BuildConfig) {
    New-SignFileConfig
    exit 0
}

try {
    # Check for prerequesites
    Test-Prerequisites

    # Initialise variables
    $variables = Get-ScriptVariables -RequireADCSCertificate:$RequireADCSCertificate -UsePersonalCertificate:$UsePersonalCertificate -ConfigFilePath $ConfigFilePath -validityLength $CertificateValidity -certTemplate $CodeSigningTemplate -companyName $CompanyName -keyLength $KeyLength -timestampServer $TimestampingAuthority

    # Check/generate code signing cert
    $codeSigningCert = Get-ExistingCodeSigningCert -CertificateStore $variables.CertificateStore
    if (-not $codeSigningCert) {
        $codeSigningCert = New-CodesigningCert -CertStore $variables.CertificateStore -ADCSRequired:$variables.RequireADCSCertificate -CompanyName $variables.CompanyName -KeyLength $variables.KeyLength -ValidityLength $variables.ValidityLength -CertTemplate $variables.CertTemplate
    }

    if (-not $codeSigningCert) {
        Exit-WithError "No usable code signing certificate available (request may be pending CA approval). Exiting."
    }

    # Find files to be signed
    $filesToSign = Get-FileToSign -Path $Path

    if (-not $filesToSign) {
        Exit-WithError "No files chosen to sign - exiting"
    }

    # Sign files
    $signResult = Set-FileSignature -FileList $filesToSign -SigningCertificate $codeSigningCert -TimestampServer $variables.timestampServer

    if ($signResult.Failed) {
        Exit-WithError "$($signResult.Failed.Count) of $($signResult.Total) file(s) failed to sign."
    }

    Write-Log "All $($signResult.Total) file(s) signed successfully." -Success
}
catch {
    Exit-WithError "Unhandled error: $($_.Exception.Message)"
}
finally {
    # Runs on every exit path, including Exit-WithError.
    try {
        Invoke-UpdateCheckAndTelemetry
    }
    catch {
        Write-Log -Message "Update check or telemetry error: $($_.Exception.Message)" -Level Debug
    }
}
