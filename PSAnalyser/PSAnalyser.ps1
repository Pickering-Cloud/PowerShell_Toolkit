<#
.SYNOPSIS
    Lints, formats and statically analyses PowerShell scripts for security issues.

.DESCRIPTION
    PSAnalyser is a standalone, dependency-free linter, formatter and static security
    analyser for PowerShell, in the spirit of ruff for Python. It parses each script
    with the built-in PowerShell parser and runs a catalogue of rules against it:

      PSF  formatting (whitespace, indentation, line endings, encoding)
      PSL  lint (syntax errors, aliases, verbs, common mistakes)
      PSS  security (injection, hard-coded secrets, weak crypto, bypasses)
      PSC  compatibility between Windows PowerShell 5.1 and PowerShell 7
      PST  toolkit conformance

    The scripts being analysed are never executed, dot-sourced or imported.

    Findings are results, not errors. A run that completes exits with code 0 whatever
    it finds, unless -FailOnSeverity is used. Rules with a safe fix can be applied
    with -Fix, or by answering the prompt in an interactive session. Every file is
    backed up before it is changed, and a fix that would add parse errors is rolled
    back.

    Toolkit conventions
    - Findings are results, not errors. Only a failed run logs at Error or Critical,
      or exits non-zero.
    - Reports are named "${ScriptName}_${RunStamp}.csv" and ".json" inside $ReportPath
      so retention cleanup only ever touches this tool's own files.
    - Schedule unattended runs with -NonInteractive so no prompt can ever appear.

.PARAMETER Path
    Files or folders to analyse. Defaults to the current directory. Folders are
    searched for .ps1, .psm1 and .psd1 files.

.PARAMETER Recurse
    Searches folders recursively.

.PARAMETER Exclude
    Wildcard patterns for files to skip. Each pattern is matched against the file
    name, the path relative to the scanned folder and the full path.

.PARAMETER ConfigPath
    Configuration file to use. Defaults to .psanalyser.json in the scanned folder,
    or the built-in defaults if there is none.

.PARAMETER Fix
    Applies every safe fix without prompting. With -WhatIf, shows the changes as a
    diff and writes nothing.

.PARAMETER Rules
    Only runs these rule IDs. Wildcards are allowed, for example PSS*.

.PARAMETER ExcludeRules
    Skips these rule IDs. Wildcards are allowed.

.PARAMETER MinimumSeverity
    Only shows, reports and fixes findings at or above this severity: Info, Low,
    Medium or High. Default Info.

.PARAMETER FailOnSeverity
    Exits with code 2 if any finding is at or above this severity, for use in CI.
    Default None, which never fails on findings. This is checked against every
    finding, whatever -MinimumSeverity is set to.

.PARAMETER Report
    Writes reports in these formats: Csv, Json, or both.

    -Rules, -ExcludeRules, -Exclude and -Report also accept comma-separated values in
    a single argument (for example -Report Csv,Json), because "powershell -File"
    passes a comma-separated list as one string.

.PARAMETER BackupPath
    Folder for backups of files changed by fixes. Defaults to a Backups folder in
    the tool's data folder. Each run writes to its own timestamped subfolder.

.PARAMETER ListRules
    Prints the rule catalogue and exits.

.PARAMETER LogPath
    Log file location. Defaults to the value in the CONFIG block.

.PARAMETER LoggingLevel
    Debug, Verbose, Info, Warn, Error, Critical or None (1 to 7, 0 also means None).
    Defaults to the CONFIG block value. -Debug and -Verbose raise it if this is not set.

.PARAMETER ReportPath
    Folder for CSV and JSON reports. Defaults to the value in the CONFIG block.

.PARAMETER RetentionDays
    Reports older than this are removed. 0 disables cleanup.

.PARAMETER DisableUpdateCheck
    Skips the version check.

.PARAMETER DisableTelemetry
    Skips anonymous usage telemetry. The PICKERINGCLOUD_NOTELEMETRY=1 and DO_NOT_TRACK=1
    environment variables do the same.

.EXAMPLE
    .\PSAnalyser.ps1 -Path .\Scripts -Recurse

    Analyses every script under .\Scripts and prints the findings. In an interactive
    session, offers to apply any safe fixes.

.EXAMPLE
    .\PSAnalyser.ps1 -Path .\Deploy.ps1 -Fix -WhatIf

    Shows the safe fixes for one file as a diff, without changing it.

.EXAMPLE
    .\PSAnalyser.ps1 -Path . -Recurse -Rules PSS* -Report Json -FailOnSeverity High

    Runs only the security rules, writes a JSON report and exits with code 2 if any
    High severity finding is present.

.EXAMPLE
    .\PSAnalyser.ps1 -ListRules

    Prints the rule catalogue.

.NOTES
    Name:        PSAnalyser
    Version:     0.1.0
    Author:      Bradley Pickering
    Repository:  Pickering-Cloud/PowerShell_Toolkit

    Exit codes:
      0  The run completed (whatever it found)
      1  The run failed (bad configuration, missing path, rule error, or a fix that
         had to be rolled back)
      2  -FailOnSeverity was used and a finding met the threshold

    Suppress a finding with a comment that gives a reason:
      # psa-ignore PSS001 -- reason      (this line or the next line)
      # psa-disable PSS001 -- reason     (until psa-enable or the end of the file)
      # psa-enable PSS001
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # ---- Script-specific parameters go here (each one ends with a comma) ----
    [Parameter(Position = 0)]
    [string[]]$Path = @('.'),
    [switch]$Recurse,
    [string[]]$Exclude = @(),
    [string]$ConfigPath,
    [switch]$Fix,
    [string[]]$Rules = @(),
    [string[]]$ExcludeRules = @(),
    [ValidateSet('Info', 'Low', 'Medium', 'High')]
    [string]$MinimumSeverity = 'Info',
    [ValidateSet('None', 'Info', 'Low', 'Medium', 'High')]
    [string]$FailOnSeverity = 'None',
    [string[]]$Report = @(),
    [string]$BackupPath,
    [switch]$ListRules,

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
$ScriptName    = 'PSAnalyser'
$ScriptVersion = '1.0.0'

# Toolkit-wide values
$UpdateCheckUrl        = 'https://www.pickering.cloud/tools/versions.json'
$TelemetryUrl          = 'https://www.pickering.cloud/api/telemetry'
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

# The template writes console output with Write-Host and guards its event log cmdlets
# with a Get-Command check, so PSL004 and PSC002 are suppressed for the template only.
# psa-disable PSL004, PSC002 -- template code: Write-Host is its console logger and its event log calls are guarded by Get-Command
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
# psa-enable PSL004, PSC002

# ==============================================================================
# Script body starts here
# ==============================================================================

#region ENGINE-STATE
$script:SeverityRank = @{ 'Info' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3 }
$script:FixTierLabel = @{ 'Safe' = 'fixable'; 'Suggest' = 'suggestion'; 'None' = 'warning' }
$script:SourceExtensions = @('.ps1', '.psm1', '.psd1')
$script:RunFailed = $false
$script:RunningEngine = '7'
if ($PSVersionTable.PSEdition -ne 'Core') {
    $script:RunningEngine = '5.1'
}
$script:ConfigCache = @{}
$script:ApprovedVerbs = $null
$script:ReportColumns = @('RuleId', 'Category', 'Severity', 'FixTier', 'File', 'Line', 'Column', 'Message', 'Snippet', 'Suggestion', 'Cwe', 'AttackId', 'HelpUrl')
#endregion ENGINE-STATE

#region CONSOLE-OUTPUT
function Write-Console {
    <#
    .SYNOPSIS
        Writes a line to the console, optionally in colour.
    .DESCRIPTION
        The console listing of findings and diffs is the tool's user interface, so it
        is written to the host rather than the output stream. Every line that matters
        is also written to the log file by the caller.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Text = '',

        [string]$Colour
    )

    if ($Colour) {
        # psa-ignore PSL004 -- the findings listing is console output by design; the log file receives its own copy.
        Write-Host $Text -ForegroundColor $Colour
    }
    else {
        # psa-ignore PSL004 -- the findings listing is console output by design; the log file receives its own copy.
        Write-Host $Text
    }
}

function Write-AnalyserLine {
    <#
    .SYNOPSIS
        Writes a line to the console and, unless it is empty, to the log file.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Text = '',

        [string]$Colour,

        [ValidateSet('Debug', 'Verbose', 'Info', 'Warn', 'Error', 'Critical')]
        [string]$LogLevel = 'Info'
    )

    Write-Console -Text $Text -Colour $Colour
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        try {
            Write-LogFile -level $LogLevel -message $Text
        }
        catch {
            Write-Console -Text ('[LOGGING FAILURE] {0}' -f $_.Exception.Message) -Colour 'Red'
        }
    }
}
#endregion CONSOLE-OUTPUT

#region CONFIG
function Get-DefaultAnalyserConfig {
    <#
    .SYNOPSIS
        Returns a fresh copy of the built-in configuration.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        source         = '(built-in defaults)'
        targetVersions = @('5.1', '7')
        indent         = @{ style = 'spaces'; size = 4; detect = $false }
        lineEnding     = 'crlf'
        exclude        = @()
        rules          = @{}
        toolkit        = @{ templateVersion = '1.1.1' }
    }
}

function Import-AnalyserConfig {
    <#
    .SYNOPSIS
        Loads the configuration for a scanned folder.
    .DESCRIPTION
        Uses -ConfigPath if it was supplied, otherwise .psanalyser.json in the scanned
        folder, otherwise the built-in defaults. Values in the file are merged over the
        defaults. An invalid file stops the run, since analysing with the wrong settings
        would give misleading results.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $cacheKey = $Root.ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        $cacheKey = '::explicit::'
    }
    if ($script:ConfigCache.ContainsKey($cacheKey)) {
        return $script:ConfigCache[$cacheKey]
    }

    $config = Get-DefaultAnalyserConfig
    $file = $null

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            throw ('Configuration file not found: {0}' -f $ConfigPath)
        }
        $file = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
    }
    else {
        $candidate = Join-Path -Path $Root -ChildPath '.psanalyser.json'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $file = $candidate
        }
    }

    if ($file) {
        try {
            $json = Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw ('Configuration file {0} is not valid JSON: {1}' -f $file, $_.Exception.Message)
        }

        foreach ($prop in $json.PSObject.Properties) {
            switch ($prop.Name) {
                'targetVersions' {
                    $versions = @($prop.Value | ForEach-Object { [string]$_ })
                    foreach ($v in $versions) {
                        if ($v -notin '5.1', '7') {
                            throw ('{0}: targetVersions entries must be "5.1" or "7", not "{1}".' -f $file, $v)
                        }
                    }
                    if ($versions.Count -eq 0) {
                        throw ('{0}: targetVersions must list at least one version.' -f $file)
                    }
                    $config.targetVersions = $versions
                }
                'indent' {
                    foreach ($ip in $prop.Value.PSObject.Properties) {
                        switch ($ip.Name) {
                            'style' {
                                if ([string]$ip.Value -notin 'spaces', 'tabs') {
                                    throw ('{0}: indent.style must be "spaces" or "tabs".' -f $file)
                                }
                                $config.indent.style = [string]$ip.Value
                            }
                            'size' {
                                $size = 0
                                if (-not [int]::TryParse([string]$ip.Value, [ref]$size) -or $size -lt 1 -or $size -gt 16) {
                                    throw ('{0}: indent.size must be a whole number from 1 to 16.' -f $file)
                                }
                                $config.indent.size = $size
                            }
                            'detect' {
                                $config.indent.detect = [bool]$ip.Value
                            }
                            default {
                                Write-Log ('Unknown setting indent.{0} in {1} is ignored.' -f $ip.Name, $file) -Level Warn
                            }
                        }
                    }
                }
                'lineEnding' {
                    $ending = ([string]$prop.Value).ToLowerInvariant()
                    if ($ending -notin 'crlf', 'lf') {
                        throw ('{0}: lineEnding must be "crlf" or "lf".' -f $file)
                    }
                    $config.lineEnding = $ending
                }
                'exclude' {
                    $config.exclude = @($prop.Value | ForEach-Object { [string]$_ })
                }
                'rules' {
                    foreach ($rp in $prop.Value.PSObject.Properties) {
                        $id = $rp.Name.ToUpperInvariant()
                        if (-not (Get-AnalyserRule -Id $id)) {
                            Write-Log ('Unknown rule {0} in {1} is ignored.' -f $id, $file) -Level Warn
                            continue
                        }
                        $setting = @{}
                        foreach ($sp in $rp.Value.PSObject.Properties) {
                            switch ($sp.Name) {
                                'enabled' {
                                    $setting.enabled = [bool]$sp.Value
                                }
                                'severity' {
                                    $sev = [string]$sp.Value
                                    $match = $script:SeverityRank.Keys | Where-Object { $_ -eq $sev } | Select-Object -First 1
                                    if (-not $match) {
                                        throw ('{0}: rules.{1}.severity must be Info, Low, Medium or High.' -f $file, $id)
                                    }
                                    $setting.severity = $match
                                }
                                default {
                                    Write-Log ('Unknown setting rules.{0}.{1} in {2} is ignored.' -f $id, $sp.Name, $file) -Level Warn
                                }
                            }
                        }
                        $config.rules[$id] = $setting
                    }
                }
                'toolkit' {
                    foreach ($tp in $prop.Value.PSObject.Properties) {
                        if ($tp.Name -eq 'templateVersion') {
                            $config.toolkit.templateVersion = [string]$tp.Value
                        }
                        else {
                            Write-Log ('Unknown setting toolkit.{0} in {1} is ignored.' -f $tp.Name, $file) -Level Warn
                        }
                    }
                }
                default {
                    Write-Log ('Unknown setting {0} in {1} is ignored.' -f $prop.Name, $file) -Level Warn
                }
            }
        }
        $config.source = $file
    }

    Write-Log ('Configuration for {0}: {1}' -f $Root, $config.source) -Level Debug
    $script:ConfigCache[$cacheKey] = $config
    return $config
}
#endregion CONFIG

#region FILE-DISCOVERY
function ConvertTo-GlobRegex {
    <#
    .SYNOPSIS
        Converts a glob such as **/vendor/** to an anchored regular expression.
    .DESCRIPTION
        ** matches any number of folders, * matches within one folder name and ?
        matches one character. A pattern with no slash matches at any depth.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Glob
    )

    $pattern = $Glob.Replace('\', '/')
    if ($pattern.IndexOf('/') -lt 0) {
        $pattern = '**/' + $pattern
    }

    $sb = New-Object -TypeName System.Text.StringBuilder
    $i = 0
    while ($i -lt $pattern.Length) {
        $c = $pattern[$i]
        if ($c -eq '*') {
            if ($i + 1 -lt $pattern.Length -and $pattern[$i + 1] -eq '*') {
                if ($i + 2 -lt $pattern.Length -and $pattern[$i + 2] -eq '/') {
                    [void]$sb.Append('(?:.*/)?')
                    $i += 3
                    continue
                }
                [void]$sb.Append('.*')
                $i += 2
                continue
            }
            [void]$sb.Append('[^/]*')
        }
        elseif ($c -eq '?') {
            [void]$sb.Append('[^/]')
        }
        else {
            [void]$sb.Append([regex]::Escape([string]$c))
        }
        $i++
    }
    return '^' + $sb.ToString() + '$'
}

function Test-AnalyserExcluded {
    <#
    .SYNOPSIS
        Returns $true if a file matches the config exclude globs or -Exclude wildcards.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FullName,

        [Parameter(Mandatory = $true)]
        [string]$Relative,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $rel = $Relative.Replace('\', '/')
    foreach ($glob in $Config.exclude) {
        if ($rel -match (ConvertTo-GlobRegex -Glob $glob)) {
            return $true
        }
    }

    $name = [System.IO.Path]::GetFileName($FullName)
    foreach ($wildcard in $Exclude) {
        if ($name -like $wildcard -or $Relative -like $wildcard -or $rel -like $wildcard -or $FullName -like $wildcard) {
            return $true
        }
    }
    return $false
}

function Get-AnalyserTarget {
    <#
    .SYNOPSIS
        Resolves -Path into the list of script files to analyse.
    .DESCRIPTION
        Each entry carries its scanned root, its path relative to that root and the
        configuration for that root. A path that does not exist is logged as an
        Error and marks the run as failed, but the other paths are still analysed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputPath
    )

    $seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $targets = New-Object -TypeName 'System.Collections.Generic.List[object]'

    foreach ($item in $InputPath) {
        $resolved = @(Resolve-Path -Path $item -ErrorAction SilentlyContinue)
        if ($resolved.Count -eq 0) {
            Write-Log ('Path not found: {0}' -f $item) -Level Error
            $script:RunFailed = $true
            continue
        }

        foreach ($r in $resolved) {
            $full = $r.ProviderPath
            if (Test-Path -LiteralPath $full -PathType Container) {
                $root = $full
                $files = @(Get-ChildItem -LiteralPath $full -File -Recurse:$Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Extension -in $script:SourceExtensions -and $_.FullName -notmatch '[\\/]\.git[\\/]' })
            }
            else {
                $root = Split-Path -Path $full -Parent
                $fileItem = Get-Item -LiteralPath $full
                if ($fileItem.Extension -notin $script:SourceExtensions) {
                    Write-Log ('Skipping {0}: not a .ps1, .psm1 or .psd1 file.' -f $full) -Level Warn
                    continue
                }
                $files = @($fileItem)
            }

            $config = Import-AnalyserConfig -Root $root
            foreach ($f in $files) {
                $relative = $f.FullName
                if ($f.FullName.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $relative = $f.FullName.Substring($root.Length).TrimStart('\', '/')
                }
                if (Test-AnalyserExcluded -FullName $f.FullName -Relative $relative -Config $config) {
                    Write-Log ('Excluded: {0}' -f $f.FullName) -Level Debug
                    continue
                }
                if ($seen.Add($f.FullName)) {
                    $targets.Add([pscustomobject]@{
                            FullName = $f.FullName
                            Root     = $root
                            Relative = $relative
                            Config   = $config
                        })
                }
            }
        }
    }
    return $targets.ToArray()
}

function Get-AnalyserDisplayPath {
    <#
    .SYNOPSIS
        Returns a path relative to the current location where possible, for display.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FullName
    )

    $here = (Get-Location).ProviderPath.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($FullName.StartsWith($here, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $FullName.Substring($here.Length)
    }
    return $FullName
}
#endregion FILE-DISCOVERY

#region SOURCE-IO
function Read-SourceFile {
    <#
    .SYNOPSIS
        Reads a file as bytes and decodes it, recording the encoding.
    .DESCRIPTION
        Checks for a byte order mark first, then tries strict UTF-8, then falls back to
        Windows-1252 (which is how Windows PowerShell 5.1 reads a BOM-less file that is
        not valid UTF-8). The encoding is kept so a fixed file is written back the same
        way.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $name = 'utf-8'
    $text = ''

    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $name = 'utf-8-bom'
        $text = (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false).GetString($bytes, 3, $bytes.Length - 3)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $name = 'utf-16le'
        $text = (New-Object -TypeName System.Text.UnicodeEncoding -ArgumentList $false, $false).GetString($bytes, 2, $bytes.Length - 2)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $name = 'utf-16be'
        $text = (New-Object -TypeName System.Text.UnicodeEncoding -ArgumentList $true, $false).GetString($bytes, 2, $bytes.Length - 2)
    }
    else {
        try {
            $strict = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false, $true
            $text = $strict.GetString($bytes)
        }
        catch {
            $name = 'windows-1252'
            $text = [System.Text.Encoding]::GetEncoding(1252).GetString($bytes)
            Write-Log ('{0} is not valid UTF-8 and has no byte order mark, so it was read as Windows-1252.' -f $FilePath) -Level Debug
        }
    }

    return [pscustomobject]@{
        Bytes        = $bytes
        EncodingName = $name
        Text         = $text
    }
}

function ConvertTo-SourceByte {
    <#
    .SYNOPSIS
        Encodes text back to bytes in the named encoding, including any byte order mark.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$EncodingName
    )

    $preamble = [byte[]]@()
    switch ($EncodingName) {
        'utf-8-bom' {
            $preamble = [byte[]](0xEF, 0xBB, 0xBF)
            $body = (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false).GetBytes($Text)
        }
        'utf-16le' {
            $preamble = [byte[]](0xFF, 0xFE)
            $body = (New-Object -TypeName System.Text.UnicodeEncoding -ArgumentList $false, $false).GetBytes($Text)
        }
        'utf-16be' {
            $preamble = [byte[]](0xFE, 0xFF)
            $body = (New-Object -TypeName System.Text.UnicodeEncoding -ArgumentList $true, $false).GetBytes($Text)
        }
        'windows-1252' {
            $body = [System.Text.Encoding]::GetEncoding(1252).GetBytes($Text)
        }
        default {
            $body = (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false).GetBytes($Text)
        }
    }

    $result = New-Object -TypeName 'byte[]' -ArgumentList ($preamble.Length + $body.Length)
    [System.Array]::Copy($preamble, 0, $result, 0, $preamble.Length)
    [System.Array]::Copy($body, 0, $result, $preamble.Length, $body.Length)
    return , $result
}
#endregion SOURCE-IO

#region CONTEXT
function Get-AnalyserLineIndex {
    <#
    .SYNOPSIS
        Returns the zero-based line index containing a character offset.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [int[]]$LineStarts,

        [Parameter(Mandatory = $true)]
        [int]$Offset
    )

    $low = 0
    $high = $LineStarts.Length - 1
    while ($low -lt $high) {
        $mid = [int][Math]::Floor(($low + $high + 1) / 2)
        if ($LineStarts[$mid] -le $Offset) {
            $low = $mid
        }
        else {
            $high = $mid - 1
        }
    }
    return $low
}

function New-AnalyserContext {
    <#
    .SYNOPSIS
        Parses a file and builds the context object that every rule receives.
    .DESCRIPTION
        Holds the text, AST, tokens, parse errors, configuration and target versions,
        plus precomputed indexes (line starts, AST nodes by type, commands, multi-line
        string spans) so that each rule does not have to walk the tree again.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Target,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Source
    )

    $text = $Source.Text
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$parseErrors)

    $breaks = [regex]::Matches($text, "`r`n|`n|`r")
    $starts = New-Object -TypeName 'System.Collections.Generic.List[int]'
    $starts.Add(0)
    foreach ($b in $breaks) {
        $starts.Add($b.Index + $b.Length)
    }
    $lines = [regex]::Split($text, "`r`n|`n|`r")

    $byType = @{}
    foreach ($node in $ast.FindAll({ $true }, $true)) {
        $typeName = $node.GetType().Name
        if (-not $byType.ContainsKey($typeName)) {
            $byType[$typeName] = New-Object -TypeName 'System.Collections.Generic.List[object]'
        }
        $byType[$typeName].Add($node)
    }

    $commands = New-Object -TypeName 'System.Collections.Generic.List[object]'
    if ($byType.ContainsKey('CommandAst')) {
        foreach ($cmd in $byType['CommandAst']) {
            $name = $cmd.GetCommandName()
            $lower = ''
            if ($name) {
                $lower = $name.ToLowerInvariant()
            }
            $commands.Add([pscustomobject]@{ Ast = $cmd; Name = $name; NameLower = $lower })
        }
    }

    $definedFunctions = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    if ($byType.ContainsKey('FunctionDefinitionAst')) {
        foreach ($fn in $byType['FunctionDefinitionAst']) {
            [void]$definedFunctions.Add(($fn.Name -replace '^\w+:', ''))
        }
    }
    $definedAliases = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $commands) {
        if ($c.NameLower -in 'set-alias', 'new-alias', 'sal', 'nal') {
            $nameArg = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'Name'
            if (-not $nameArg) {
                $nameArg = Get-CommandPositionalArgument -CommandAst $c.Ast -Index 0
            }
            if ($nameArg -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                [void]$definedAliases.Add($nameArg.Value)
            }
        }
    }
    if ($byType.ContainsKey('AttributeAst')) {
        foreach ($attr in $byType['AttributeAst']) {
            if ($attr.TypeName.Name -eq 'Alias') {
                foreach ($arg in $attr.PositionalArguments) {
                    if ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                        [void]$definedAliases.Add($arg.Value)
                    }
                }
            }
        }
    }

    $stringSpans = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($t in $tokens) {
        if ([string]$t.Kind -in 'StringLiteral', 'StringExpandable', 'HereStringLiteral', 'HereStringExpandable') {
            if ($t.Extent.StartLineNumber -ne $t.Extent.EndLineNumber) {
                $stringSpans.Add([pscustomobject]@{ Start = $t.Extent.StartOffset; End = $t.Extent.EndOffset })
            }
        }
    }

    $config = $Target.Config
    return [pscustomobject]@{
        Path             = $Target.FullName
        DisplayPath      = Get-AnalyserDisplayPath -FullName $Target.FullName
        Text             = $text
        EncodingName     = $Source.EncodingName
        Ast              = $ast
        Tokens           = $tokens
        ParseErrors      = @($parseErrors)
        Config           = $config
        TargetVersions   = $config.targetVersions
        Targets51        = ($config.targetVersions -contains '5.1')
        Targets7         = ($config.targetVersions -contains '7')
        RunningEngine    = $script:RunningEngine
        LineBreaks       = $breaks
        LineStarts       = [int[]]$starts.ToArray()
        Lines            = $lines
        NodesByType      = $byType
        Commands         = $commands.ToArray()
        DefinedFunctions = $definedFunctions
        DefinedAliases   = $definedAliases
        StringSpans      = $stringSpans.ToArray()
        Suppressions     = $null
        CurrentRule      = $null
        SecretValues     = @()
    }
}

function Get-AnalyserNode {
    <#
    .SYNOPSIS
        Returns every AST node of the named type in the file being analysed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$TypeName
    )

    if ($Context.NodesByType.ContainsKey($TypeName)) {
        return $Context.NodesByType[$TypeName].ToArray()
    }
    return @()
}

function Get-AnalyserCommand {
    <#
    .SYNOPSIS
        Returns the commands in the file whose name is one of the given names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [string[]]$Name
    )

    $wanted = @($Name | ForEach-Object { $_.ToLowerInvariant() })
    return @($Context.Commands | Where-Object { $_.NameLower -and $wanted -contains $_.NameLower })
}

function Test-AnalyserInString {
    <#
    .SYNOPSIS
        Returns $true if an offset falls inside a string that spans several lines.
    .DESCRIPTION
        Used by the formatting rules so they never change whitespace that is part of
        a here-string or other multi-line string value.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [int]$Offset
    )

    foreach ($span in $Context.StringSpans) {
        if ($Offset -gt $span.Start -and $Offset -lt $span.End) {
            return $true
        }
    }
    return $false
}
#endregion CONTEXT

#region AST-HELPERS
function Get-CommandArgumentAst {
    <#
    .SYNOPSIS
        Returns the argument given to a named parameter of a command, or $null.
    .DESCRIPTION
        Accepts abbreviated parameter names, as PowerShell does. Returns the parameter
        itself for a switch with no argument.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.CommandAst]$CommandAst,

        [Parameter(Mandatory = $true)]
        [string[]]$ParameterName,

        [int]$MinimumPrefix = 1
    )

    $elements = $CommandAst.CommandElements
    for ($i = 1; $i -lt $elements.Count; $i++) {
        $el = $elements[$i]
        if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
            $typed = $el.ParameterName
            foreach ($full in $ParameterName) {
                if ($typed.Length -ge $MinimumPrefix -and $full.StartsWith($typed, [System.StringComparison]::OrdinalIgnoreCase)) {
                    if ($el.Argument) {
                        return $el.Argument
                    }
                    if ($i + 1 -lt $elements.Count -and -not ($elements[$i + 1] -is [System.Management.Automation.Language.CommandParameterAst])) {
                        return $elements[$i + 1]
                    }
                    return $el
                }
            }
        }
    }
    return $null
}

function Get-CommandPositionalArgument {
    <#
    .SYNOPSIS
        Returns the nth positional argument of a command, or $null.
    .DESCRIPTION
        An element directly after a parameter name is treated as that parameter's
        value. This is a heuristic, since switch parameters cannot be told apart from
        other parameters without loading the command.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.CommandAst]$CommandAst,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    $elements = $CommandAst.CommandElements
    $position = 0
    for ($i = 1; $i -lt $elements.Count; $i++) {
        $el = $elements[$i]
        if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
            if (-not $el.Argument -and $i + 1 -lt $elements.Count -and -not ($elements[$i + 1] -is [System.Management.Automation.Language.CommandParameterAst])) {
                $i++
            }
            continue
        }
        if ($position -eq $Index) {
            return $el
        }
        $position++
    }
    return $null
}

function Get-AnalyserStringValue {
    <#
    .SYNOPSIS
        Returns the constant string value of an expression, or $null if it is not one.
    .DESCRIPTION
        Unwraps statements, pipelines and command expressions. An expandable string only
        counts as constant if it contains no variables or subexpressions.
    #>
    [CmdletBinding()]
    param(
        $Ast
    )

    $node = $Ast
    while ($node) {
        if ($node -is [System.Management.Automation.Language.PipelineAst]) {
            if ($node.PipelineElements.Count -ne 1) {
                return $null
            }
            $node = $node.PipelineElements[0]
            continue
        }
        if ($node -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $node = $node.Expression
            continue
        }
        if ($node -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            return [pscustomobject]@{ Ast = $node; Value = $node.Value }
        }
        if ($node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
            if ($node.NestedExpressions.Count -eq 0) {
                return [pscustomobject]@{ Ast = $node; Value = $node.Value }
            }
            return $null
        }
        return $null
    }
    return $null
}

function Test-BenignExpression {
    <#
    .SYNOPSIS
        Returns $true for variables that are not attacker-controlled, such as $env:
        values and $PSScriptRoot.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        $Ast
    )

    if ($Ast -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $path = $Ast.VariablePath
        if ($path.IsDriveQualified -and $path.DriveName -eq 'env') {
            return $true
        }
        if ($path.UserPath -in 'PSScriptRoot', 'PSHOME', 'PSCommandPath', 'true', 'false', 'null') {
            return $true
        }
    }
    return $false
}

function Test-DynamicStringAst {
    <#
    .SYNOPSIS
        Returns $true if an expression builds a string from variables, by
        interpolation, concatenation or the format operator.
    .DESCRIPTION
        Used by the injection rules. Interpolating only benign variables (see
        Test-BenignExpression) does not count.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        $Ast
    )

    if ($null -eq $Ast) {
        return $false
    }
    if ($Ast -is [System.Management.Automation.Language.PipelineAst] -and $Ast.PipelineElements.Count -eq 1) {
        return (Test-DynamicStringAst -Ast $Ast.PipelineElements[0])
    }
    if ($Ast -is [System.Management.Automation.Language.CommandExpressionAst]) {
        return (Test-DynamicStringAst -Ast $Ast.Expression)
    }
    if ($Ast -is [System.Management.Automation.Language.ParenExpressionAst]) {
        return (Test-DynamicStringAst -Ast $Ast.Pipeline)
    }
    if ($Ast -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
        foreach ($nested in $Ast.NestedExpressions) {
            if (-not (Test-BenignExpression -Ast $nested)) {
                return $true
            }
        }
        return $false
    }
    if ($Ast -is [System.Management.Automation.Language.BinaryExpressionAst]) {
        $operator = [string]$Ast.Operator
        if ($operator -eq 'Plus' -or $operator -eq 'Format') {
            $operands = @($Ast.Left, $Ast.Right)
            $hasString = $false
            $hasVariable = $false
            foreach ($operand in $operands) {
                if ($operand -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $operand -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                    $hasString = $true
                }
                if (Test-DynamicStringAst -Ast $operand) {
                    return $true
                }
                if (-not ($operand -is [System.Management.Automation.Language.ConstantExpressionAst]) -and -not (Test-BenignExpression -Ast $operand)) {
                    if (-not ($operand -is [System.Management.Automation.Language.ExpandableStringExpressionAst])) {
                        $hasVariable = $true
                    }
                }
            }
            return ($hasString -and $hasVariable)
        }
        return $false
    }
    if ($Ast -is [System.Management.Automation.Language.ArrayLiteralAst]) {
        foreach ($element in $Ast.Elements) {
            if (Test-DynamicStringAst -Ast $element) {
                return $true
            }
        }
    }
    return $false
}

function Get-ShannonEntropy {
    <#
    .SYNOPSIS
        Returns the Shannon entropy of a string in bits per character.
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $counts = @{}
    foreach ($ch in $Text.ToCharArray()) {
        $key = [int]$ch
        if ($counts.ContainsKey($key)) {
            $counts[$key]++
        }
        else {
            $counts[$key] = 1
        }
    }
    $entropy = 0.0
    foreach ($n in $counts.Values) {
        $p = $n / $Text.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return $entropy
}

function Get-StringNode {
    <#
    .SYNOPSIS
        Returns every string constant and expandable string in the file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $result = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($typeName in 'StringConstantExpressionAst', 'ExpandableStringExpressionAst') {
        foreach ($node in (Get-AnalyserNode -Context $Context -TypeName $typeName)) {
            # Skip bare words such as command names and parameter values.
            if ($node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and [string]$node.StringConstantType -eq 'BareWord') {
                continue
            }
            # Strings nested inside an expandable string are covered by their parent.
            if ($node.Parent -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
                continue
            }
            $result.Add($node)
        }
    }
    return $result.ToArray()
}
#endregion AST-HELPERS

#region FINDINGS
function Protect-SnippetText {
    <#
    .SYNOPSIS
        Masks every quoted string in a line of code.
    .DESCRIPTION
        Used for findings from sensitive rules so that a secret value is never shown,
        logged or written to a report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string]$Text
    )

    $masked = $Text -replace "'[^']*'", "'****'"
    $masked = $masked -replace '"[^"]*"', '"****"'
    return (Protect-LogText -Text $masked)
}

function Get-MaskedLine {
    <#
    .SYNOPSIS
        Returns the line containing an offset with a span of it replaced by ****.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [int]$StartOffset,

        [Parameter(Mandatory = $true)]
        [int]$Length
    )

    $index = Get-AnalyserLineIndex -LineStarts $Context.LineStarts -Offset $StartOffset
    $line = $Context.Lines[$index]
    $lineStart = $Context.LineStarts[$index]
    $from = $StartOffset - $lineStart
    $to = [Math]::Min($from + $Length, $line.Length)
    if ($from -lt 0 -or $from -gt $line.Length) {
        return '****'
    }
    $masked = $line.Substring(0, $from) + '****' + $line.Substring($to)
    return (Protect-SnippetText -Text $masked.Trim())
}

function New-AnalyserFinding {
    <#
    .SYNOPSIS
        Creates a finding for the rule currently running against a file.
    .DESCRIPTION
        Fills in the line, column and snippet from the offset. The snippet is masked
        for sensitive rules. Severity, fix tier, CWE and ATT&CK ID default to the
        rule's values but can be set per finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [int]$StartOffset,

        [int]$Length = 0,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Suggestion = '',

        [string]$Severity,

        [string]$FixTier,

        [string]$Cwe,

        [string]$AttackId,

        [string]$Snippet,

        [hashtable]$Data = @{}
    )

    $rule = $Context.CurrentRule
    $index = Get-AnalyserLineIndex -LineStarts $Context.LineStarts -Offset $StartOffset
    $column = $StartOffset - $Context.LineStarts[$index] + 1

    if (-not $PSBoundParameters.ContainsKey('Snippet')) {
        $Snippet = $Context.Lines[$index].Trim()
        if ($rule.Sensitive) {
            $Snippet = Protect-SnippetText -Text $Snippet
        }
    }
    if ($Snippet.Length -gt 160) {
        $Snippet = $Snippet.Substring(0, 157) + '...'
    }
    if (-not $Severity) {
        $Severity = $rule.Severity
    }
    if (-not $FixTier) {
        $FixTier = $rule.FixTier
    }
    if (-not $PSBoundParameters.ContainsKey('Cwe')) {
        $Cwe = $rule.Cwe
    }
    if (-not $PSBoundParameters.ContainsKey('AttackId')) {
        $AttackId = $rule.AttackId
    }

    return [pscustomobject][ordered]@{
        RuleId      = $rule.Id
        Category    = $rule.Category
        Severity    = $Severity
        FixTier     = $FixTier
        File        = $Context.Path
        Line        = $index + 1
        Column      = $column
        StartOffset = $StartOffset
        Length      = $Length
        Message     = $Message
        Snippet     = $Snippet
        Suggestion  = $Suggestion
        Cwe         = $Cwe
        AttackId    = $AttackId
        HelpUrl     = $rule.HelpUrl
        Data        = $Data
    }
}

function New-AnalyserEdit {
    <#
    .SYNOPSIS
        Creates an edit: replace Length characters at StartOffset with ReplacementText.
    .DESCRIPTION
        -AddBom marks an encoding change instead of a text change (used by PSF005).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [int]$StartOffset = 0,

        [int]$Length = 0,

        [AllowEmptyString()]
        [string]$ReplacementText = '',

        [switch]$AddBom
    )

    return [pscustomobject]@{
        StartOffset     = $StartOffset
        Length          = $Length
        ReplacementText = $ReplacementText
        RuleId          = ''
        AddBom          = [bool]$AddBom
    }
}
#endregion FINDINGS

#region SUPPRESSIONS
function Get-AnalyserSuppression {
    <#
    .SYNOPSIS
        Reads psa-ignore, psa-disable and psa-enable comments from a file.
    .DESCRIPTION
        psa-ignore applies to its own line and the next line. psa-disable applies until
        a matching psa-enable or the end of the file. Several IDs can be given,
        separated by commas or spaces. A suppression must give a reason after "--";
        one without a reason is not applied and is reported by PSL007.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    if ($Context.Suppressions) {
        return $Context.Suppressions
    }

    $lineMap = @{}
    $regions = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $problems = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $open = @{}

    foreach ($token in $Context.Tokens) {
        if ([string]$token.Kind -ne 'Comment') {
            continue
        }
        $m = [regex]::Match($token.Text, '^#\s*psa-(ignore|disable|enable)\b(.*)$')
        if (-not $m.Success) {
            continue
        }
        $verb = $m.Groups[1].Value.ToLowerInvariant()
        $rest = $m.Groups[2].Value
        $reason = ''
        $separator = $rest.IndexOf('--')
        if ($separator -ge 0) {
            $reason = $rest.Substring($separator + 2).Trim()
            $rest = $rest.Substring(0, $separator)
        }
        $ids = @($rest -split '[\s,]+' | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() })
        $line = $token.Extent.StartLineNumber

        if ($ids.Count -eq 0) {
            $problems.Add([pscustomobject]@{ Token = $token; Message = ('psa-{0} names no rule IDs.' -f $verb) })
            continue
        }
        if ($verb -ne 'enable' -and [string]::IsNullOrWhiteSpace($reason)) {
            $problems.Add([pscustomobject]@{ Token = $token; Message = ('psa-{0} {1} gives no reason, so it is not applied. Add " -- reason" after the rule IDs.' -f $verb, ($ids -join ', ')) })
            continue
        }

        foreach ($id in $ids) {
            switch ($verb) {
                'ignore' {
                    foreach ($l in $line, ($line + 1)) {
                        if (-not $lineMap.ContainsKey($l)) {
                            $lineMap[$l] = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
                        }
                        [void]$lineMap[$l].Add($id)
                    }
                }
                'disable' {
                    if (-not $open.ContainsKey($id)) {
                        $open[$id] = $line
                    }
                }
                'enable' {
                    if ($open.ContainsKey($id)) {
                        $regions.Add([pscustomobject]@{ Id = $id; Start = $open[$id]; End = $line })
                        $open.Remove($id)
                    }
                }
            }
        }
    }
    foreach ($id in @($open.Keys)) {
        $regions.Add([pscustomobject]@{ Id = $id; Start = $open[$id]; End = [int]::MaxValue })
    }

    $Context.Suppressions = [pscustomobject]@{
        Lines    = $lineMap
        Regions  = $regions.ToArray()
        Problems = $problems.ToArray()
    }
    return $Context.Suppressions
}

function Test-AnalyserSuppressed {
    <#
    .SYNOPSIS
        Returns $true if a finding is covered by a suppression comment.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Suppressions,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Finding
    )

    if ($Suppressions.Lines.ContainsKey($Finding.Line) -and $Suppressions.Lines[$Finding.Line].Contains($Finding.RuleId)) {
        return $true
    }
    foreach ($region in $Suppressions.Regions) {
        if ($region.Id -eq $Finding.RuleId -and $Finding.Line -ge $region.Start -and $Finding.Line -le $region.End) {
            return $true
        }
    }
    return $false
}
#endregion SUPPRESSIONS

#region RULE-RUNNER
function New-AnalyserRule {
    <#
    .SYNOPSIS
        Creates a rule object for the catalogue.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^PS[FLSCT]\d{3}$')]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Formatting', 'Lint', 'Security', 'Compatibility', 'Toolkit')]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Low', 'Medium', 'High')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [string]$Cwe = '',

        [string]$AttackId = '',

        [string]$HelpUrl = '',

        [Parameter(Mandatory = $true)]
        [ValidateSet('Safe', 'Suggest', 'None')]
        [string]$FixTier,

        [switch]$Sensitive,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Check,

        [scriptblock]$Fix
    )

    if ($FixTier -eq 'Safe' -and -not $Fix) {
        throw ('Rule {0} has the Safe fix tier but no Fix script block.' -f $Id)
    }
    if (-not $HelpUrl) {
        $firstCwe = [regex]::Match($Cwe, 'CWE-(\d+)')
        if ($firstCwe.Success) {
            $HelpUrl = 'https://cwe.mitre.org/data/definitions/{0}.html' -f $firstCwe.Groups[1].Value
        }
        else {
            $HelpUrl = 'https://github.com/Pickering-Cloud/PowerShell_Toolkit/blob/main/PSAnalyser/README.md#rules'
        }
    }

    return [pscustomobject]@{
        Id          = $Id
        Category    = $Category
        Severity    = $Severity
        Title       = $Title
        Description = $Description
        Cwe         = $Cwe
        AttackId    = $AttackId
        HelpUrl     = $HelpUrl
        FixTier     = $FixTier
        Sensitive   = [bool]$Sensitive
        Check       = $Check
        Fix         = $Fix
    }
}

function Get-AnalyserRule {
    <#
    .SYNOPSIS
        Returns the rule with the given ID, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    foreach ($rule in $script:AnalyserRules) {
        if ($rule.Id -eq $Id) {
            return $rule
        }
    }
    return $null
}

function Test-AnalyserRuleSelected {
    <#
    .SYNOPSIS
        Returns $true if a rule should run, given the config, -Rules and -ExcludeRules.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Rule,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    if ($Config.rules.ContainsKey($Rule.Id) -and $Config.rules[$Rule.Id].ContainsKey('enabled') -and -not $Config.rules[$Rule.Id].enabled) {
        return $false
    }
    if ($Rules.Count -gt 0) {
        $included = $false
        foreach ($pattern in $Rules) {
            if ($Rule.Id -like $pattern) {
                $included = $true
            }
        }
        if (-not $included) {
            return $false
        }
    }
    foreach ($pattern in $ExcludeRules) {
        if ($Rule.Id -like $pattern) {
            return $false
        }
    }
    return $true
}

function Invoke-AnalyserFile {
    <#
    .SYNOPSIS
        Reads, parses and runs every selected rule against one file.
    .DESCRIPTION
        Returns the context and the findings after severity overrides and suppressions
        have been applied. A rule that throws is a tool fault: it is logged as an Error,
        the run is marked as failed, and the other rules still run.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Target
    )

    $source = Read-SourceFile -FilePath $Target.FullName
    $context = New-AnalyserContext -Target $Target -Source $source
    $findings = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $maskOnly = New-Object -TypeName 'System.Collections.Generic.List[object]'

    foreach ($rule in $script:AnalyserRules) {
        # Sensitive rules always run, even when deselected, so that secrets are still
        # masked in snippets and diffs. Their findings are then used for masking only.
        $selected = Test-AnalyserRuleSelected -Rule $rule -Config $context.Config
        if (-not $selected -and -not $rule.Sensitive) {
            continue
        }
        $context.CurrentRule = $rule
        try {
            $ruleFindings = @(& $rule.Check $context)
        }
        catch {
            Write-Log ('Rule {0} failed on {1}: {2} ({3})' -f $rule.Id, $context.Path, $_.Exception.Message, $_.InvocationInfo.PositionMessage) -Level Error
            $script:RunFailed = $true
            continue
        }

        $override = $null
        if ($context.Config.rules.ContainsKey($rule.Id) -and $context.Config.rules[$rule.Id].ContainsKey('severity')) {
            $override = $context.Config.rules[$rule.Id].severity
        }
        foreach ($finding in $ruleFindings) {
            if ($null -eq $finding) {
                continue
            }
            if (-not $selected) {
                $maskOnly.Add($finding)
                continue
            }
            if ($override) {
                $finding.Severity = $override
            }
            $findings.Add($finding)
        }
    }
    $context.CurrentRule = $null

    # Any finding on a line that holds a secret gets a masked snippet, whichever rule
    # raised it, so the value never reaches the console, log or reports.
    $secretLines = @{}
    $secretValues = New-Object -TypeName 'System.Collections.Generic.List[string]'
    foreach ($f in @($findings.ToArray()) + @($maskOnly.ToArray())) {
        $rule = Get-AnalyserRule -Id $f.RuleId
        if ($rule -and $rule.Sensitive) {
            $secretLines[$f.Line] = $true
            if ($f.Length -ge 4 -and $f.StartOffset + $f.Length -le $context.Text.Length) {
                $secretValues.Add($context.Text.Substring($f.StartOffset, $f.Length))
            }
        }
    }
    foreach ($f in $findings) {
        if ($secretLines.ContainsKey($f.Line)) {
            $rule = Get-AnalyserRule -Id $f.RuleId
            if (-not $rule.Sensitive) {
                $f.Snippet = Protect-SnippetText -Text $context.Lines[$f.Line - 1].Trim()
            }
        }
    }
    $context.SecretValues = $secretValues.ToArray()

    $suppressions = Get-AnalyserSuppression -Context $context
    $kept = @($findings | Where-Object { -not (Test-AnalyserSuppressed -Suppressions $suppressions -Finding $_) } |
            Sort-Object -Property Line, Column, RuleId)

    return [pscustomobject]@{
        Target   = $Target
        Context  = $context
        Findings = $kept
    }
}

function Select-AnalyserVisible {
    <#
    .SYNOPSIS
        Returns the findings at or above -MinimumSeverity.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Finding = @()
    )

    $threshold = $script:SeverityRank[$MinimumSeverity]
    return @($Finding | Where-Object { $null -ne $_ -and $script:SeverityRank[$_.Severity] -ge $threshold })
}
#endregion RULE-RUNNER

#region FIX-ENGINE
function Get-AnalyserEdit {
    <#
    .SYNOPSIS
        Asks each rule for the edits that fix its safe findings in one file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result
    )

    $edits = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($finding in (Select-AnalyserVisible -Finding $Result.Findings)) {
        if ($finding.FixTier -ne 'Safe') {
            continue
        }
        $rule = Get-AnalyserRule -Id $finding.RuleId
        if (-not $rule -or -not $rule.Fix) {
            continue
        }
        try {
            foreach ($edit in @(& $rule.Fix $Result.Context $finding)) {
                if ($null -ne $edit) {
                    $edit.RuleId = $rule.Id
                    $edits.Add($edit)
                }
            }
        }
        catch {
            Write-Log ('Fix for {0} failed on {1}: {2}' -f $rule.Id, $Result.Context.Path, $_.Exception.Message) -Level Error
            $script:RunFailed = $true
        }
    }
    return $edits.ToArray()
}

function Select-AnalyserEdit {
    <#
    .SYNOPSIS
        Removes duplicate and overlapping edits, keeping the earliest of each overlap.
    .DESCRIPTION
        Overlapping edits are rejected and logged at Debug. Running the tool again
        applies them once the earlier edit has been made.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Edit = @(),

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $accepted = New-Object -TypeName 'System.Collections.Generic.List[object]'
    $keys = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
    $lastEnd = -1
    $textEdits = @($Edit | Where-Object { -not $_.AddBom } | Sort-Object -Property StartOffset, Length)
    foreach ($e in $textEdits) {
        $key = '{0}|{1}|{2}' -f $e.StartOffset, $e.Length, $e.ReplacementText
        if (-not $keys.Add($key)) {
            continue
        }
        if ($e.StartOffset -lt $lastEnd) {
            Write-Log ('Rejected overlapping {0} edit at offset {1} in {2}; run the tool again to apply it.' -f $e.RuleId, $e.StartOffset, $FilePath) -Level Debug
            continue
        }
        $accepted.Add($e)
        $lastEnd = [Math]::Max($lastEnd, $e.StartOffset + $e.Length)
    }
    $bom = @($Edit | Where-Object { $_.AddBom } | Select-Object -First 1)
    foreach ($b in $bom) {
        $accepted.Add($b)
    }
    return $accepted.ToArray()
}

function Get-EditedText {
    <#
    .SYNOPSIS
        Applies text edits from the end of the text backwards and returns the result.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [AllowEmptyCollection()]
        [object[]]$Edit = @()
    )

    $sb = New-Object -TypeName System.Text.StringBuilder -ArgumentList $Text
    foreach ($e in @($Edit | Where-Object { -not $_.AddBom } | Sort-Object -Property StartOffset -Descending)) {
        [void]$sb.Remove($e.StartOffset, $e.Length)
        [void]$sb.Insert($e.StartOffset, $e.ReplacementText)
    }
    return $sb.ToString()
}

function Get-AnalyserBackupFile {
    <#
    .SYNOPSIS
        Returns the backup path for a file, mirroring its full path so names cannot
        collide.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FullName
    )

    $root = $BackupPath
    if ([string]::IsNullOrWhiteSpace($root)) {
        $root = Join-Path -Path $DefaultDataRoot -ChildPath 'Backups'
    }
    $root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($root)

    $relative = $FullName
    if ($relative.StartsWith('\\')) {
        $relative = 'UNC\' + $relative.Substring(2)
    }
    $relative = $relative.Replace(':', '')
    return (Join-Path -Path (Join-Path -Path $root -ChildPath $RunStamp) -ChildPath $relative)
}

function Invoke-AnalyserFix {
    <#
    .SYNOPSIS
        Applies the safe fixes for one file.
    .DESCRIPTION
        Merges the edits, checks that the result parses with no more errors than the
        original, backs the original up, writes the new file atomically (temporary file
        then replace) and confirms the bytes on disk. If anything goes wrong after the
        write, the original is restored from the backup and an Error is logged. Returns
        the number of edits applied.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result,

        [AllowEmptyCollection()]
        [object[]]$Edit = @()
    )

    $context = $Result.Context
    if ($Edit.Count -eq 0) {
        return 0
    }

    $newText = Get-EditedText -Text $context.Text -Edit $Edit
    $encoding = $context.EncodingName
    if (@($Edit | Where-Object { $_.AddBom }).Count -gt 0) {
        $encoding = 'utf-8-bom'
    }
    if ($newText -ceq $context.Text -and $encoding -eq $context.EncodingName) {
        return 0
    }

    $tokens = $null
    $errorsAfter = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($newText, [ref]$tokens, [ref]$errorsAfter)
    if (@($errorsAfter).Count -gt $context.ParseErrors.Count) {
        Write-Log ('Fixes for {0} were not applied: they would add parse errors ({1} before, {2} after). Please report this as a PSAnalyser bug.' -f $context.Path, $context.ParseErrors.Count, @($errorsAfter).Count) -Level Error
        $script:RunFailed = $true
        return 0
    }

    if (-not $PSCmdlet.ShouldProcess($context.Path, ('Apply {0} safe fix(es)' -f $Edit.Count))) {
        return 0
    }

    $bytes = ConvertTo-SourceByte -Text $newText -EncodingName $encoding
    $backup = Get-AnalyserBackupFile -FullName $context.Path
    $temp = '{0}.psa-{1}.tmp' -f $context.Path, ([guid]::NewGuid().ToString('N'))

    try {
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Path $backup -Parent))
        [System.IO.File]::Copy($context.Path, $backup, $true)
    }
    catch {
        Write-Log ('Fixes for {0} were not applied: the backup could not be written to {1}: {2}' -f $context.Path, $backup, $_.Exception.Message) -Level Error
        $script:RunFailed = $true
        return 0
    }

    try {
        [System.IO.File]::WriteAllBytes($temp, $bytes)
        # [NullString]::Value, because PowerShell would pass $null as an empty string.
        [System.IO.File]::Replace($temp, $context.Path, [NullString]::Value)

        $written = [System.IO.File]::ReadAllBytes($context.Path)
        $same = ($written.Length -eq $bytes.Length)
        if ($same) {
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                if ($written[$i] -ne $bytes[$i]) {
                    $same = $false
                    break
                }
            }
        }
        if (-not $same) {
            throw 'the file on disk does not match what was written'
        }
    }
    catch {
        $reason = $_.Exception.Message
        try {
            [System.IO.File]::Copy($backup, $context.Path, $true)
            Write-Log ('Fixes for {0} failed and the original was restored from {1}: {2}' -f $context.Path, $backup, $reason) -Level Error
        }
        catch {
            Write-Log ('Fixes for {0} failed and the original could not be restored. A copy is at {1}: {2}' -f $context.Path, $backup, $reason) -Level Critical
        }
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue -WhatIf:$false
        }
        $script:RunFailed = $true
        return 0
    }

    Write-Log ('Applied {0} fix(es) to {1}. Backup: {2}' -f $Edit.Count, $context.Path, $backup)
    return $Edit.Count
}
#endregion FIX-ENGINE

#region DIFF
function Split-TextLine {
    <#
    .SYNOPSIS
        Splits text into lines, dropping the empty entry after a final line break.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyString()]
        [string]$Text
    )

    if ($Text.Length -eq 0) {
        return , @()
    }
    $parts = [regex]::Split($Text, "`r`n|`n|`r")
    if ($Text.EndsWith("`n") -or $Text.EndsWith("`r")) {
        $parts = $parts[0..($parts.Length - 2)]
    }
    return , @($parts)
}

function Get-AnalyserDiff {
    <#
    .SYNOPSIS
        Returns a unified-style diff of the edits for one file.
    .DESCRIPTION
        Built directly from the edits rather than by comparing whole files, so it is
        exact and fast. Changes that only alter line endings or the byte order mark are
        summarised in a note instead of being shown line by line.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Result,

        [AllowEmptyCollection()]
        [object[]]$Edit = @()
    )

    $context = $Result.Context
    $text = $context.Text
    $starts = $context.LineStarts
    $lines = $context.Lines
    $contextLines = 2
    $output = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $notes = New-Object -TypeName 'System.Collections.Generic.List[string]'

    $textEdits = @($Edit | Where-Object { -not $_.AddBom } | Sort-Object -Property StartOffset)
    $groups = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($e in $textEdits) {
        $first = Get-AnalyserLineIndex -LineStarts $starts -Offset $e.StartOffset
        $last = $first
        if ($e.Length -gt 0) {
            $last = Get-AnalyserLineIndex -LineStarts $starts -Offset ($e.StartOffset + $e.Length - 1)
        }
        if ($groups.Count -gt 0 -and $first -le $groups[$groups.Count - 1].Last + (2 * $contextLines) + 1) {
            $g = $groups[$groups.Count - 1]
            $g.Last = [Math]::Max($g.Last, $last)
            $g.Edits.Add($e)
        }
        else {
            $list = New-Object -TypeName 'System.Collections.Generic.List[object]'
            $list.Add($e)
            $groups.Add([pscustomobject]@{ First = $first; Last = $last; Edits = $list })
        }
    }

    $delta = 0
    $lineEndingOnly = 0
    foreach ($g in $groups) {
        $segStart = $starts[$g.First]
        $segEnd = $text.Length
        if ($g.Last + 1 -lt $starts.Length) {
            $segEnd = $starts[$g.Last + 1]
        }
        $oldSegment = $text.Substring($segStart, $segEnd - $segStart)
        $shifted = @($g.Edits | ForEach-Object {
                [pscustomobject]@{ StartOffset = $_.StartOffset - $segStart; Length = $_.Length; ReplacementText = $_.ReplacementText; AddBom = $false }
            })
        $newSegment = Get-EditedText -Text $oldSegment -Edit $shifted

        if ($oldSegment.Replace("`r", '') -ceq $newSegment.Replace("`r", '')) {
            $lineEndingOnly += [Math]::Max(1, $g.Edits.Count)
            continue
        }

        $oldLines = Split-TextLine -Text $oldSegment
        $newLines = Split-TextLine -Text $newSegment
        $before = [Math]::Max(0, $g.First - $contextLines)
        $afterEnd = [Math]::Min($lines.Length - 1, $g.Last + $contextLines)
        if ($afterEnd -eq $lines.Length - 1 -and $lines[$afterEnd] -eq '' -and $text.Length -gt 0) {
            $afterEnd--
        }
        $leading = $g.First - $before
        $trailing = [Math]::Max(0, $afterEnd - $g.Last)
        $oldCount = $leading + $oldLines.Count + $trailing
        $newCount = $leading + $newLines.Count + $trailing
        $output.Add(('@@ -{0},{1} +{2},{3} @@' -f ($before + 1), $oldCount, ($before + 1 + $delta), $newCount))
        for ($i = $before; $i -lt $g.First; $i++) {
            $output.Add(' ' + $lines[$i])
        }
        foreach ($l in $oldLines) {
            $output.Add('-' + $l)
        }
        if (-not ($oldSegment.EndsWith("`n") -or $oldSegment.EndsWith("`r"))) {
            $output.Add('\ No newline at end of file')
        }
        foreach ($l in $newLines) {
            $output.Add('+' + $l)
        }
        if ($newSegment.Length -gt 0 -and -not ($newSegment.EndsWith("`n") -or $newSegment.EndsWith("`r"))) {
            $output.Add('\ No newline at end of file')
        }
        for ($i = $g.Last + 1; $i -le $afterEnd; $i++) {
            $output.Add(' ' + $lines[$i])
        }
        $delta += $newLines.Count - $oldLines.Count
    }

    $lineEndingEdits = @($Edit | Where-Object { $_.RuleId -eq 'PSF004' }).Count
    if ($lineEndingEdits -gt 0) {
        $notes.Add(('(line endings normalised to {0} in {1} place(s))' -f $context.Config.lineEnding.ToUpperInvariant(), $lineEndingEdits))
    }
    elseif ($lineEndingOnly -gt 0) {
        $notes.Add(('({0} change(s) affect line endings only)' -f $lineEndingOnly))
    }
    if (@($Edit | Where-Object { $_.AddBom }).Count -gt 0) {
        $notes.Add('(encoding: saved as UTF-8 with a byte order mark)')
    }
    if ($output.Count -eq 0 -and $notes.Count -eq 0) {
        return , @()
    }

    $header = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $header.Add(('--- a/{0}' -f $context.DisplayPath.Replace('\', '/')))
    $header.Add(('+++ b/{0}' -f $context.DisplayPath.Replace('\', '/')))
    foreach ($n in $notes) {
        $header.Add($n)
    }

    # Mask secret values so a diff never prints them.
    $masked = foreach ($line in $output) {
        $safe = $line
        foreach ($secret in $context.SecretValues) {
            $safe = $safe.Replace($secret, '****')
        }
        Protect-LogText -Text $safe
    }
    return , @($header.ToArray() + @($masked))
}

function Show-AnalyserDiff {
    <#
    .SYNOPSIS
        Prints the diff of every pending fix, in colour.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Plan
    )

    foreach ($item in $Plan) {
        $diff = Get-AnalyserDiff -Result $item.Result -Edit $item.Edits
        foreach ($line in $diff) {
            $colour = $null
            if ($line.StartsWith('+++') -or $line.StartsWith('---')) {
                $colour = 'White'
            }
            elseif ($line.StartsWith('@@')) {
                $colour = 'Cyan'
            }
            elseif ($line.StartsWith('+')) {
                $colour = 'Green'
            }
            elseif ($line.StartsWith('-')) {
                $colour = 'Red'
            }
            elseif ($line.StartsWith('(')) {
                $colour = 'DarkGray'
            }
            Write-AnalyserLine -Text $line -Colour $colour -LogLevel Debug
        }
        Write-Console
    }
}
#endregion DIFF

#region REPORTING
function Get-AnalyserSummaryText {
    <#
    .SYNOPSIS
        Returns a one-line summary of findings by fix tier.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()]
        [object[]]$Finding = @()
    )

    $total = @($Finding).Count
    if ($total -eq 0) {
        return 'No findings.'
    }
    $safe = @($Finding | Where-Object { $_.FixTier -eq 'Safe' }).Count
    $suggest = @($Finding | Where-Object { $_.FixTier -eq 'Suggest' }).Count
    $warn = @($Finding | Where-Object { $_.FixTier -eq 'None' }).Count

    $parts = New-Object -TypeName 'System.Collections.Generic.List[string]'
    if ($safe -gt 0) {
        $parts.Add(('{0} safe fix{1} available' -f $safe, $(if ($safe -eq 1) { '' } else { 'es' })))
    }
    if ($suggest -gt 0) {
        $parts.Add(('{0} suggestion{1}' -f $suggest, $(if ($suggest -eq 1) { '' } else { 's' })))
    }
    if ($warn -gt 0) {
        $parts.Add(('{0} warning{1}' -f $warn, $(if ($warn -eq 1) { '' } else { 's' })))
    }
    return ('{0} finding{1}: {2}' -f $total, $(if ($total -eq 1) { '' } else { 's' }), ($parts -join ', '))
}

function Show-AnalyserFinding {
    <#
    .SYNOPSIS
        Prints findings grouped by file, to the console and the log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Result
    )

    $colours = @{ 'High' = 'Red'; 'Medium' = 'Yellow'; 'Low' = 'Cyan'; 'Info' = 'Gray' }
    foreach ($r in $Result) {
        $visible = @(Select-AnalyserVisible -Finding $r.Findings)
        if ($visible.Count -eq 0) {
            continue
        }
        Write-AnalyserLine -Text ('{0} ({1})' -f $r.Context.DisplayPath, (Get-AnalyserSummaryText -Finding $visible)) -Colour 'White'
        foreach ($f in $visible) {
            $line = '  {0,5}:{1,-4} {2}  {3,-6}  {4,-10}  {5}' -f $f.Line, $f.Column, $f.RuleId, $f.Severity, $script:FixTierLabel[$f.FixTier], $f.Message
            Write-AnalyserLine -Text $line -Colour $colours[$f.Severity]
            if ($f.Snippet) {
                Write-AnalyserLine -Text ('               > {0}' -f $f.Snippet) -Colour 'DarkGray'
            }
            if ($f.Suggestion) {
                Write-AnalyserLine -Text ('               Suggestion: {0}' -f $f.Suggestion) -Colour 'DarkGray'
            }
        }
        Write-Console
    }
}

function Export-AnalyserReport {
    <#
    .SYNOPSIS
        Writes the CSV and JSON reports requested with -Report.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Result
    )

    $findings = @($Result | ForEach-Object { Select-AnalyserVisible -Finding $_.Findings })
    $rows = @($findings | Select-Object -Property $script:ReportColumns)
    Initialize-OutputFolder

    if ($Report -contains 'Csv') {
        $csvPath = Join-Path -Path $ReportPath -ChildPath ('{0}_{1}.csv' -f $ScriptName, $RunStamp)
        if ($PSCmdlet.ShouldProcess($csvPath, 'Write CSV report')) {
            if ($rows.Count -gt 0) {
                $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false
            }
            else {
                $header = ($script:ReportColumns | ForEach-Object { '"{0}"' -f $_ }) -join ','
                [System.IO.File]::WriteAllText($csvPath, $header + "`r`n", (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true))
            }
            Write-Log ('CSV report written: {0}' -f $csvPath)
        }
    }

    if ($Report -contains 'Json') {
        $jsonPath = Join-Path -Path $ReportPath -ChildPath ('{0}_{1}.json' -f $ScriptName, $RunStamp)
        if ($PSCmdlet.ShouldProcess($jsonPath, 'Write JSON report')) {
            $bySeverity = [ordered]@{}
            foreach ($s in 'High', 'Medium', 'Low', 'Info') {
                $bySeverity[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count
            }
            $byTier = [ordered]@{}
            foreach ($t in 'Safe', 'Suggest', 'None') {
                $byTier[$t] = @($findings | Where-Object { $_.FixTier -eq $t }).Count
            }
            $document = [ordered]@{
                tool         = $ScriptName
                version      = $ScriptVersion
                runStamp     = $RunStamp
                engine       = $script:RunningEngine
                filesScanned = @($Result).Count
                summary      = [ordered]@{
                    total      = $findings.Count
                    bySeverity = $bySeverity
                    byFixTier  = $byTier
                }
                findings     = $rows
            }
            $json = $document | ConvertTo-Json -Depth 6
            [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
            Write-Log ('JSON report written: {0}' -f $jsonPath)
        }
    }

    Remove-ExpiredOutput -Folder $ReportPath -OlderThanDays $RetentionDays
}

function Show-RuleCatalogue {
    <#
    .SYNOPSIS
        Prints the rule catalogue for -ListRules.
    #>
    [CmdletBinding()]
    param()

    $rows = $script:AnalyserRules | ForEach-Object {
        [pscustomobject]@{
            Id       = $_.Id
            Category = $_.Category
            Severity = $_.Severity
            FixTier  = $_.FixTier
            CWE      = $_.Cwe
            Title    = $_.Title
        }
    }
    Write-Output ($rows | Format-Table -AutoSize | Out-String -Width 4096).TrimEnd()
}
#endregion REPORTING

#region DATA-TABLES
# Built-in aliases that resolve to the same cmdlet on Windows PowerShell 5.1 and
# PowerShell 7. Generated from Get-Alias on both engines; only these are expanded
# automatically by PSL001.
$script:BuiltInAliasTable = @{
    '?'       = 'Where-Object'
    '%'       = 'ForEach-Object'
    'ac'      = 'Add-Content'
    'cat'     = 'Get-Content'
    'cd'      = 'Set-Location'
    'chdir'   = 'Set-Location'
    'clc'     = 'Clear-Content'
    'clhy'    = 'Clear-History'
    'cli'     = 'Clear-Item'
    'clp'     = 'Clear-ItemProperty'
    'clv'     = 'Clear-Variable'
    'cnsn'    = 'Connect-PSSession'
    'compare' = 'Compare-Object'
    'copy'    = 'Copy-Item'
    'cp'      = 'Copy-Item'
    'cpi'     = 'Copy-Item'
    'cpp'     = 'Copy-ItemProperty'
    'cvpa'    = 'Convert-Path'
    'dbp'     = 'Disable-PSBreakpoint'
    'del'     = 'Remove-Item'
    'diff'    = 'Compare-Object'
    'dir'     = 'Get-ChildItem'
    'dnsn'    = 'Disconnect-PSSession'
    'ebp'     = 'Enable-PSBreakpoint'
    'echo'    = 'Write-Output'
    'epal'    = 'Export-Alias'
    'epcsv'   = 'Export-Csv'
    'erase'   = 'Remove-Item'
    'etsn'    = 'Enter-PSSession'
    'exsn'    = 'Exit-PSSession'
    'fc'      = 'Format-Custom'
    'fl'      = 'Format-List'
    'foreach' = 'ForEach-Object'
    'ft'      = 'Format-Table'
    'fw'      = 'Format-Wide'
    'gal'     = 'Get-Alias'
    'gbp'     = 'Get-PSBreakpoint'
    'gc'      = 'Get-Content'
    'gcb'     = 'Get-Clipboard'
    'gci'     = 'Get-ChildItem'
    'gcm'     = 'Get-Command'
    'gcs'     = 'Get-PSCallStack'
    'gdr'     = 'Get-PSDrive'
    'ghy'     = 'Get-History'
    'gi'      = 'Get-Item'
    'gin'     = 'Get-ComputerInfo'
    'gjb'     = 'Get-Job'
    'gl'      = 'Get-Location'
    'gm'      = 'Get-Member'
    'gmo'     = 'Get-Module'
    'gp'      = 'Get-ItemProperty'
    'gps'     = 'Get-Process'
    'gpv'     = 'Get-ItemPropertyValue'
    'group'   = 'Group-Object'
    'gsn'     = 'Get-PSSession'
    'gsv'     = 'Get-Service'
    'gtz'     = 'Get-TimeZone'
    'gu'      = 'Get-Unique'
    'gv'      = 'Get-Variable'
    'h'       = 'Get-History'
    'history' = 'Get-History'
    'icm'     = 'Invoke-Command'
    'iex'     = 'Invoke-Expression'
    'ihy'     = 'Invoke-History'
    'ii'      = 'Invoke-Item'
    'ipal'    = 'Import-Alias'
    'ipcsv'   = 'Import-Csv'
    'ipmo'    = 'Import-Module'
    'irm'     = 'Invoke-RestMethod'
    'iwr'     = 'Invoke-WebRequest'
    'kill'    = 'Stop-Process'
    'ls'      = 'Get-ChildItem'
    'measure' = 'Measure-Object'
    'mi'      = 'Move-Item'
    'mount'   = 'New-PSDrive'
    'move'    = 'Move-Item'
    'mp'      = 'Move-ItemProperty'
    'mv'      = 'Move-Item'
    'nal'     = 'New-Alias'
    'ndr'     = 'New-PSDrive'
    'ni'      = 'New-Item'
    'nmo'     = 'New-Module'
    'nsn'     = 'New-PSSession'
    'nv'      = 'New-Variable'
    'ogv'     = 'Out-GridView'
    'oh'      = 'Out-Host'
    'popd'    = 'Pop-Location'
    'ps'      = 'Get-Process'
    'pushd'   = 'Push-Location'
    'pwd'     = 'Get-Location'
    'r'       = 'Invoke-History'
    'rbp'     = 'Remove-PSBreakpoint'
    'rcjb'    = 'Receive-Job'
    'rcsn'    = 'Receive-PSSession'
    'rd'      = 'Remove-Item'
    'rdr'     = 'Remove-PSDrive'
    'ren'     = 'Rename-Item'
    'ri'      = 'Remove-Item'
    'rjb'     = 'Remove-Job'
    'rm'      = 'Remove-Item'
    'rmdir'   = 'Remove-Item'
    'rmo'     = 'Remove-Module'
    'rni'     = 'Rename-Item'
    'rnp'     = 'Rename-ItemProperty'
    'rp'      = 'Remove-ItemProperty'
    'rsn'     = 'Remove-PSSession'
    'rv'      = 'Remove-Variable'
    'rvpa'    = 'Resolve-Path'
    'sajb'    = 'Start-Job'
    'sal'     = 'Set-Alias'
    'saps'    = 'Start-Process'
    'sasv'    = 'Start-Service'
    'sbp'     = 'Set-PSBreakpoint'
    'scb'     = 'Set-Clipboard'
    'select'  = 'Select-Object'
    'set'     = 'Set-Variable'
    'shcm'    = 'Show-Command'
    'si'      = 'Set-Item'
    'sl'      = 'Set-Location'
    'sleep'   = 'Start-Sleep'
    'sls'     = 'Select-String'
    'sort'    = 'Sort-Object'
    'sp'      = 'Set-ItemProperty'
    'spjb'    = 'Stop-Job'
    'spps'    = 'Stop-Process'
    'spsv'    = 'Stop-Service'
    'start'   = 'Start-Process'
    'stz'     = 'Set-TimeZone'
    'sv'      = 'Set-Variable'
    'tee'     = 'Tee-Object'
    'type'    = 'Get-Content'
    'where'   = 'Where-Object'
    'wjb'     = 'Wait-Job'
    'write'   = 'Write-Output'
}

# Aliases that run a native executable on PowerShell 7 but a cmdlet on 5.1, so
# expanding them could change behaviour. PSL001 warns about these but never fixes them.
$script:AmbiguousAliasTable = @{
    'sc'   = 'Set-Content on Windows PowerShell 5.1, but sc.exe (the Service Control tool) on PowerShell 7'
    'curl' = 'Invoke-WebRequest on Windows PowerShell 5.1, but the native curl.exe on PowerShell 7'
    'wget' = 'Invoke-WebRequest on Windows PowerShell 5.1, but a native wget executable (if installed) on PowerShell 7'
}

# Approved verbs on Windows PowerShell 5.1, used if Get-Verb is unavailable.
$script:FallbackVerbList = @(
    'Add', 'Approve', 'Assert', 'Backup', 'Block', 'Checkpoint', 'Clear', 'Close',
    'Compare', 'Complete', 'Compress', 'Confirm', 'Connect', 'Convert', 'ConvertFrom', 'ConvertTo',
    'Copy', 'Debug', 'Deny', 'Disable', 'Disconnect', 'Dismount', 'Edit', 'Enable',
    'Enter', 'Exit', 'Expand', 'Export', 'Find', 'Format', 'Get', 'Grant',
    'Group', 'Hide', 'Import', 'Initialize', 'Install', 'Invoke', 'Join', 'Limit',
    'Lock', 'Measure', 'Merge', 'Mount', 'Move', 'New', 'Open', 'Optimize',
    'Out', 'Ping', 'Pop', 'Protect', 'Publish', 'Push', 'Read', 'Receive',
    'Redo', 'Register', 'Remove', 'Rename', 'Repair', 'Request', 'Reset', 'Resize',
    'Resolve', 'Restart', 'Restore', 'Resume', 'Revoke', 'Save', 'Search', 'Select',
    'Send', 'Set', 'Show', 'Skip', 'Split', 'Start', 'Step', 'Stop',
    'Submit', 'Suspend', 'Switch', 'Sync', 'Test', 'Trace', 'Unblock', 'Undo',
    'Uninstall', 'Unlock', 'Unprotect', 'Unpublish', 'Unregister', 'Update', 'Use', 'Wait',
    'Watch', 'Write'
)

# Common unapproved verbs and the approved verb to use instead.
$script:VerbSuggestionTable = @{
    'delete'    = 'Remove'
    'create'    = 'New'
    'make'      = 'New'
    'generate'  = 'New'
    'check'     = 'Test'
    'validate'  = 'Test'
    'verify'    = 'Test'
    'fetch'     = 'Get'
    'find'      = 'Get'
    'retrieve'  = 'Get'
    'load'      = 'Import'
    'kill'      = 'Stop'
    'run'       = 'Invoke'
    'execute'   = 'Invoke'
    'configure' = 'Set'
    'change'    = 'Set'
    'display'   = 'Show'
    'print'     = 'Write'
    'calculate' = 'Measure'
}

# Cmdlets and parameters that need PowerShell 7 (PSC001).
$script:SevenOnlyCommandTable = @{
    'join-string'          = 'Join-String'
    'get-error'            = 'Get-Error'
    'test-json'            = 'Test-Json'
    'convertfrom-markdown' = 'ConvertFrom-Markdown'
    'show-markdown'        = 'Show-Markdown'
    'get-markdownoption'   = 'Get-MarkdownOption'
    'set-markdownoption'   = 'Set-MarkdownOption'
    'get-uptime'           = 'Get-Uptime'
    'remove-alias'         = 'Remove-Alias'
    'remove-service'       = 'Remove-Service'
}
$script:SevenOnlyParameterTable = @(
    @{ Commands = @('foreach-object', '%', 'foreach'); Parameters = @('Parallel'); MinimumPrefix = 2 }
    @{ Commands = @('convertfrom-securestring'); Parameters = @('AsPlainText'); MinimumPrefix = 2 }
    @{ Commands = @('get-content', 'set-content', 'add-content', 'gc', 'ac', 'cat', 'type'); Parameters = @('AsByteStream'); MinimumPrefix = 3 }
    @{ Commands = @('invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm'); Parameters = @('SkipCertificateCheck', 'SslProtocol', 'Authentication', 'Token', 'StatusCodeVariable', 'ResponseHeadersVariable', 'SkipHttpErrorCheck', 'MaximumRetryCount', 'RetryIntervalSec', 'Resume'); MinimumPrefix = 4 }
    @{ Commands = @('test-connection'); Parameters = @('TargetName'); MinimumPrefix = 2 }
)

# Cmdlets that do not exist on PowerShell 7 (PSC002), with what to use instead.
$script:MissingOnSevenTable = @{
    'get-wmiobject'        = 'Get-CimInstance'
    'gwmi'                 = 'Get-CimInstance'
    'set-wmiinstance'      = 'Set-CimInstance'
    'swmi'                 = 'Set-CimInstance'
    'invoke-wmimethod'     = 'Invoke-CimMethod'
    'iwmi'                 = 'Invoke-CimMethod'
    'remove-wmiobject'     = 'Remove-CimInstance'
    'rwmi'                 = 'Remove-CimInstance'
    'register-wmievent'    = 'Register-CimIndicationEvent'
    'get-eventlog'         = 'Get-WinEvent'
    'new-eventlog'         = '[System.Diagnostics.EventLog]::CreateEventSource()'
    'write-eventlog'       = '[System.Diagnostics.EventLog]::WriteEntry() or New-WinEvent'
    'remove-eventlog'      = '[System.Diagnostics.EventLog]::Delete() or DeleteEventSource()'
    'clear-eventlog'       = 'wevtutil.exe clear-log, or [System.Diagnostics.EventLog]::Clear()'
    'limit-eventlog'       = 'wevtutil.exe set-log'
    'show-eventlog'        = 'eventvwr.exe'
    'new-webserviceproxy'  = 'Invoke-RestMethod, or a generated client'
    'add-pssnapin'         = 'modules (Import-Module)'
    'get-pssnapin'         = 'Get-Module'
    'remove-pssnapin'      = 'Remove-Module'
    'export-console'       = 'a profile script'
    'start-transaction'    = 'an explicit rollback strategy (transactions were removed)'
    'complete-transaction' = 'an explicit rollback strategy (transactions were removed)'
    'undo-transaction'     = 'an explicit rollback strategy (transactions were removed)'
    'use-transaction'      = 'an explicit rollback strategy (transactions were removed)'
    'get-transaction'      = 'an explicit rollback strategy (transactions were removed)'
    'out-printer'          = 'Out-File, then print the file'
    'get-controlpanelitem' = 'control.exe'
    'show-controlpanelitem' = 'control.exe'
    'convertfrom-string'   = 'ConvertFrom-StringData or regular expressions'
}

# Variable, key and parameter names that suggest a secret (PSS003, PSS004). "pwd" is
# deliberately absent: $PWD is the automatic current-location variable.
$script:SensitiveNamePattern = '(?i)(password|passwd|secret|apikey|api_key|accesskey|access_key|accesstoken|access_token|authtoken|^token$|connectionstring|privatekey)'

# Values that are obviously placeholders rather than real secrets.
$script:PlaceholderValuePattern = '(?i)^(\*+|x+|<[^>]*>|\{[^}]*\}|\$\{[^}]*\}|change_?me|placeholder|todo|tbd|replace_?me|your[_ -].*|example.*|dummy|test|none|null|password|secret)$'

# Download commands and members for PSS002. Written with character classes so the
# patterns themselves never match the text they are looking for.
$script:DownloadCommandNames = @('invoke-webrequest', 'invoke-restmethod', 'iwr', 'irm', 'curl', 'wget', 'start-bitstransfer')
$script:DownloadExecutePatterns = @(
    '(?is)\b(?:i[e]x|invoke-e[x]pression)\b.{0,200}?\b(?:i[w]r|i[r]m|invoke-w[e]brequest|invoke-r[e]stmethod|downloads[t]ring|downloadd[a]ta)\b'
    '(?is)\b(?:i[w]r|i[r]m|invoke-w[e]brequest|invoke-r[e]stmethod|downloads[t]ring)\b.{0,200}?\|\s*(?:i[e]x|invoke-e[x]pression)\b'
)
#endregion DATA-TABLES

#region RULES
function Get-ApprovedVerbSet {
    <#
    .SYNOPSIS
        Returns the approved verbs, from Get-Verb or the embedded fallback list.
    #>
    [CmdletBinding()]
    param()

    if ($null -eq $script:ApprovedVerbs) {
        $set = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
        try {
            foreach ($v in (Get-Verb -ErrorAction Stop)) {
                [void]$set.Add($v.Verb)
            }
        }
        catch {
            Write-Log ('Get-Verb failed, using the embedded verb list: {0}' -f $_.Exception.Message) -Level Debug
        }
        if ($set.Count -eq 0) {
            foreach ($v in $script:FallbackVerbList) {
                [void]$set.Add($v)
            }
        }
        $script:ApprovedVerbs = $set
    }
    return , $script:ApprovedVerbs
}

function Test-SevenOnlySyntaxError {
    <#
    .SYNOPSIS
        Returns $true if a parse error on Windows PowerShell 5.1 is caused by
        PowerShell 7 syntax (??, ??=, ternary, &&, ||, ?. or ?[]).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $ParseError
    )

    if ($ParseError.ErrorId -notin 'UnexpectedToken', 'InvalidEndOfLine') {
        return $false
    }
    return ($ParseError.Extent.Text -match '^(\?\?=?|\?|&&|\|\||\?\.\S*|\?\[.*)$')
}

function Get-StringExtentMatch {
    <#
    .SYNOPSIS
        Runs a regular expression over every string in the file and returns each match
        with its offset in the file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    $result = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($node in (Get-StringNode -Context $Context)) {
        foreach ($m in [regex]::Matches($node.Extent.Text, $Pattern)) {
            $result.Add([pscustomobject]@{ Node = $node; Offset = $node.Extent.StartOffset + $m.Index; Length = $m.Length; Match = $m })
        }
    }
    return $result.ToArray()
}

$script:AnalyserRules = New-Object -TypeName 'System.Collections.Generic.List[object]'

# ---- Formatting -------------------------------------------------------------

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSF001' -Category 'Formatting' -Severity 'Info' -FixTier 'Safe' `
            -Title 'Trailing whitespace' `
            -Description 'Spaces or tabs at the end of a line. Whitespace inside multi-line strings is left alone.' `
            -Check {
            param($Context)
            for ($i = 0; $i -lt $Context.Lines.Length; $i++) {
                $m = [regex]::Match($Context.Lines[$i], '[ \t]+$')
                if (-not $m.Success) {
                    continue
                }
                $offset = $Context.LineStarts[$i] + $m.Index
                if (Test-AnalyserInString -Context $Context -Offset $offset) {
                    continue
                }
                New-AnalyserFinding -Context $Context -StartOffset $offset -Length $m.Length -Message 'Trailing whitespace.' -Suggestion 'Remove the spaces or tabs at the end of the line.'
            }
        } `
            -Fix {
            param($Context, $Finding)
            New-AnalyserEdit -StartOffset $Finding.StartOffset -Length $Finding.Length -ReplacementText ''
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSF002' -Category 'Formatting' -Severity 'Info' -FixTier 'Safe' `
            -Title 'Indentation style' `
            -Description 'Indentation uses tabs where the configuration says spaces, or the other way round. With indent.detect, the dominant style of each file is used instead.' `
            -Check {
            param($Context)
            $style = $Context.Config.indent.style
            $size = $Context.Config.indent.size
            if ($Context.Config.indent.detect) {
                $tabs = 0
                $spaces = 0
                for ($i = 0; $i -lt $Context.Lines.Length; $i++) {
                    if (Test-AnalyserInString -Context $Context -Offset $Context.LineStarts[$i]) {
                        continue
                    }
                    if ($Context.Lines[$i] -match '^\t+\S') {
                        $tabs++
                    }
                    elseif ($Context.Lines[$i] -match '^ +\S') {
                        $spaces++
                    }
                }
                if ($tabs -gt $spaces) {
                    $style = 'tabs'
                }
                elseif ($spaces -gt $tabs) {
                    $style = 'spaces'
                }
            }

            for ($i = 0; $i -lt $Context.Lines.Length; $i++) {
                $m = [regex]::Match($Context.Lines[$i], '^([ \t]+)\S')
                if (-not $m.Success) {
                    continue
                }
                $leading = $m.Groups[1].Value
                if (($style -eq 'spaces' -and $leading.IndexOf("`t") -lt 0) -or ($style -eq 'tabs' -and $leading.IndexOf(' ') -lt 0)) {
                    continue
                }
                $offset = $Context.LineStarts[$i]
                if (Test-AnalyserInString -Context $Context -Offset $offset) {
                    continue
                }

                $width = 0
                foreach ($ch in $leading.ToCharArray()) {
                    if ($ch -eq "`t") {
                        $width += $size - ($width % $size)
                    }
                    else {
                        $width++
                    }
                }
                if ($style -eq 'spaces') {
                    $replacement = ' ' * $width
                    $message = 'Indentation uses tabs; this project indents with {0} spaces.' -f $size
                }
                else {
                    $replacement = ("`t" * [Math]::Floor($width / $size)) + (' ' * ($width % $size))
                    $message = 'Indentation uses spaces; this project indents with tabs.'
                }
                if ($replacement -ceq $leading) {
                    continue
                }
                New-AnalyserFinding -Context $Context -StartOffset $offset -Length $leading.Length -Message $message -Suggestion 'Re-indent the line.' -Data @{ Replacement = $replacement }
            }
        } `
            -Fix {
            param($Context, $Finding)
            New-AnalyserEdit -StartOffset $Finding.StartOffset -Length $Finding.Length -ReplacementText $Finding.Data.Replacement
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSF003' -Category 'Formatting' -Severity 'Info' -FixTier 'Safe' `
            -Title 'Missing final newline' `
            -Description 'The file does not end with a line break.' `
            -Check {
            param($Context)
            $text = $Context.Text
            if ($text.Length -gt 0 -and -not ($text.EndsWith("`n") -or $text.EndsWith("`r"))) {
                New-AnalyserFinding -Context $Context -StartOffset $text.Length -Message 'The file does not end with a line break.' -Suggestion 'Add a line break at the end of the file.'
            }
        } `
            -Fix {
            param($Context, $Finding)
            $newline = "`r`n"
            if ($Context.Config.lineEnding -eq 'lf') {
                $newline = "`n"
            }
            New-AnalyserEdit -StartOffset $Finding.StartOffset -Length 0 -ReplacementText $newline
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSF004' -Category 'Formatting' -Severity 'Info' -FixTier 'Safe' `
            -Title 'Line endings' `
            -Description 'Line endings are mixed or do not match the configured style (CRLF by default). Reported once per file.' `
            -Check {
            param($Context)
            $target = "`r`n"
            $label = 'CRLF'
            if ($Context.Config.lineEnding -eq 'lf') {
                $target = "`n"
                $label = 'LF'
            }
            $wrong = New-Object -TypeName 'System.Collections.Generic.List[object]'
            $kinds = @{}
            foreach ($b in $Context.LineBreaks) {
                if ($b.Value -cne $target) {
                    $wrong.Add([pscustomobject]@{ Index = $b.Index; Length = $b.Length })
                    $kind = 'LF'
                    if ($b.Value -eq "`r") {
                        $kind = 'CR'
                    }
                    elseif ($b.Value -eq "`r`n") {
                        $kind = 'CRLF'
                    }
                    $kinds[$kind] = $true
                }
            }
            if ($wrong.Count -gt 0) {
                $message = '{0} of {1} line ending(s) are {2}; this project uses {3}.' -f $wrong.Count, $Context.LineBreaks.Count, (($kinds.Keys | Sort-Object) -join ' and '), $label
                New-AnalyserFinding -Context $Context -StartOffset $wrong[0].Index -Length $wrong[0].Length -Message $message -Suggestion ('Convert every line ending to {0}.' -f $label) -Data @{ Breaks = $wrong.ToArray(); Target = $target }
            }
        } `
            -Fix {
            param($Context, $Finding)
            foreach ($b in $Finding.Data.Breaks) {
                New-AnalyserEdit -StartOffset $b.Index -Length $b.Length -ReplacementText $Finding.Data.Target
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSF005' -Category 'Formatting' -Severity 'Medium' -FixTier 'Safe' `
            -Title 'Non-ASCII characters without a UTF-8 BOM' `
            -Description 'Windows PowerShell 5.1 reads a file with no byte order mark as ANSI (Windows-1252), so non-ASCII characters in a BOM-less UTF-8 file are misread. Only checked when 5.1 is a target version.' `
            -Check {
            param($Context)
            if (-not $Context.Targets51 -or $Context.EncodingName -notin 'utf-8', 'windows-1252') {
                return
            }
            $m = [regex]::Match($Context.Text, '[^\x00-\x7F]')
            if (-not $m.Success) {
                return
            }
            if ($Context.EncodingName -eq 'windows-1252') {
                $message = 'The file is not valid UTF-8 and has no byte order mark, so it was read as Windows-1252. It contains non-ASCII characters.'
            }
            else {
                $message = 'The file contains non-ASCII characters but has no UTF-8 byte order mark. Windows PowerShell 5.1 will read it as Windows-1252 and misread them.'
            }
            New-AnalyserFinding -Context $Context -StartOffset $m.Index -Length 1 -Message $message -Suggestion 'Save the file as UTF-8 with a byte order mark, or replace the characters with ASCII.'
        } `
            -Fix {
            param($Context, $Finding)
            New-AnalyserEdit -AddBom
        }))

# ---- Lint -------------------------------------------------------------------

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL000' -Category 'Lint' -Severity 'High' -FixTier 'None' `
            -Title 'Syntax error' `
            -Description 'The parser reported an error. Under Windows PowerShell 5.1, errors caused by PowerShell 7 syntax are relabelled, and reported as PSC001 when 5.1 is a target version.' `
            -Check {
            param($Context)
            foreach ($e in $Context.ParseErrors) {
                if ($Context.RunningEngine -eq '5.1' -and (Test-SevenOnlySyntaxError -ParseError $e)) {
                    if ($Context.Targets51) {
                        continue
                    }
                    New-AnalyserFinding -Context $Context -StartOffset $e.Extent.StartOffset -Length ($e.Extent.EndOffset - $e.Extent.StartOffset) -Severity 'Info' `
                        -Message ("Syntax not supported on the running engine (Windows PowerShell 5.1): '{0}'. Run PSAnalyser under PowerShell 7 to analyse this file fully." -f $e.Extent.Text)
                    continue
                }
                New-AnalyserFinding -Context $Context -StartOffset $e.Extent.StartOffset -Length ($e.Extent.EndOffset - $e.Extent.StartOffset) -Message ('Syntax error: {0}' -f $e.Message)
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL001' -Category 'Lint' -Severity 'Low' -FixTier 'Safe' `
            -Title 'Alias used in a script' `
            -Description 'Aliases make scripts harder to read and can differ between machines. Built-in aliases that mean the same cmdlet on 5.1 and 7 are expanded automatically; aliases that mean a native program on 7 (sc, curl, wget) are reported without a fix.' `
            -Check {
            param($Context)
            foreach ($c in $Context.Commands) {
                $first = $c.Ast.CommandElements[0]
                if (-not ($first -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or [string]$first.StringConstantType -ne 'BareWord') {
                    continue
                }
                $name = $first.Value.ToLowerInvariant()
                if ($Context.DefinedFunctions.Contains($name) -or $Context.DefinedAliases.Contains($name)) {
                    continue
                }
                $length = $first.Extent.EndOffset - $first.Extent.StartOffset
                if ($script:AmbiguousAliasTable.ContainsKey($name)) {
                    New-AnalyserFinding -Context $Context -StartOffset $first.Extent.StartOffset -Length $length -FixTier 'None' `
                        -Message ("'{0}' is {1}." -f $first.Value, $script:AmbiguousAliasTable[$name]) `
                        -Suggestion 'Use the full cmdlet name, or the .exe name if you mean the native program.'
                }
                elseif ($script:BuiltInAliasTable.ContainsKey($name)) {
                    $full = $script:BuiltInAliasTable[$name]
                    New-AnalyserFinding -Context $Context -StartOffset $first.Extent.StartOffset -Length $length `
                        -Message ("Alias '{0}' used; the command is {1}." -f $first.Value, $full) -Suggestion ("Use '{0}'." -f $full) -Data @{ Replacement = $full }
                }
            }
        } `
            -Fix {
            param($Context, $Finding)
            New-AnalyserEdit -StartOffset $Finding.StartOffset -Length $Finding.Length -ReplacementText $Finding.Data.Replacement
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL002' -Category 'Lint' -Severity 'Low' -FixTier 'Suggest' `
            -Title 'Unapproved verb in a function name' `
            -Description 'Function names should use an approved verb (see Get-Verb). Never renamed automatically, since callers would break.' `
            -Check {
            param($Context)
            $approved = Get-ApprovedVerbSet
            foreach ($fn in (Get-AnalyserNode -Context $Context -TypeName 'FunctionDefinitionAst')) {
                $name = $fn.Name -replace '^\w+:', ''
                $m = [regex]::Match($name, '^([A-Za-z]+)-\S')
                if (-not $m.Success) {
                    continue
                }
                $verb = $m.Groups[1].Value
                if ($approved.Contains($verb)) {
                    continue
                }
                $offset = $fn.Extent.StartOffset
                $nameMatch = [regex]::Match($fn.Extent.Text, '^\s*(?:function|filter|workflow)\s+(?:\w+:)?([^\s{(]+)', 'IgnoreCase')
                if ($nameMatch.Success) {
                    $offset += $nameMatch.Groups[1].Index
                }
                $better = $script:VerbSuggestionTable[$verb.ToLowerInvariant()]
                if ($better -and $approved.Contains($better)) {
                    $suggestion = "Rename it to '{0}-{1}' ({0} is the approved verb for this). Update every caller." -f $better, $name.Substring($verb.Length + 1)
                }
                else {
                    $suggestion = 'Run Get-Verb and choose an approved verb. Update every caller.'
                }
                New-AnalyserFinding -Context $Context -StartOffset $offset -Length $name.Length -Message ("Function '{0}' uses the unapproved verb '{1}'." -f $name, $verb) -Suggestion $suggestion
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL003' -Category 'Lint' -Severity 'Medium' -FixTier 'Safe' `
            -Title '$null on the right of a comparison' `
            -Description 'When the left side is a collection, -eq and -ne filter it instead of testing for null, so "$x -eq $null" can give the wrong answer. Put $null on the left.' `
            -Check {
            param($Context)
            foreach ($b in (Get-AnalyserNode -Context $Context -TypeName 'BinaryExpressionAst')) {
                if ([string]$b.Operator -notin 'Ieq', 'Ine', 'Ceq', 'Cne') {
                    continue
                }
                $right = $b.Right
                $left = $b.Left
                if (-not ($right -is [System.Management.Automation.Language.VariableExpressionAst]) -or $right.VariablePath.UserPath -ne 'null') {
                    continue
                }
                if ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.VariablePath.UserPath -eq 'null') {
                    continue
                }
                New-AnalyserFinding -Context $Context -StartOffset $b.Extent.StartOffset -Length ($b.Extent.EndOffset - $b.Extent.StartOffset) `
                    -Message '$null is on the right of the comparison.' -Suggestion 'Put $null on the left, for example "$null -eq $x".' `
                    -Data @{ LeftStart = $left.Extent.StartOffset; LeftEnd = $left.Extent.EndOffset; RightStart = $right.Extent.StartOffset; RightEnd = $right.Extent.EndOffset }
            }
        } `
            -Fix {
            param($Context, $Finding)
            $d = $Finding.Data
            $text = $Context.Text
            $leftText = $text.Substring($d.LeftStart, $d.LeftEnd - $d.LeftStart)
            $middle = $text.Substring($d.LeftEnd, $d.RightStart - $d.LeftEnd)
            $rightText = $text.Substring($d.RightStart, $d.RightEnd - $d.RightStart)
            New-AnalyserEdit -StartOffset $d.LeftStart -Length ($d.RightEnd - $d.LeftStart) -ReplacementText ($rightText + $middle + $leftText)
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL004' -Category 'Lint' -Severity 'Info' -FixTier 'Suggest' `
            -Title 'Write-Host used' `
            -Description 'Write-Host writes only to the console. Its output cannot be captured, redirected or suppressed on Windows PowerShell 5.1.' `
            -Check {
            param($Context)
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Write-Host')) {
                $first = $c.Ast.CommandElements[0]
                New-AnalyserFinding -Context $Context -StartOffset $first.Extent.StartOffset -Length ($first.Extent.EndOffset - $first.Extent.StartOffset) `
                    -Message 'Write-Host used.' -Suggestion 'Use Write-Output for data, or Write-Verbose or Write-Information for messages.'
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL005' -Category 'Lint' -Severity 'Low' -FixTier 'None' -Cwe 'CWE-390' `
            -Title 'Empty catch block' `
            -Description 'An empty catch block silently swallows errors, hiding failures.' `
            -Check {
            param($Context)
            foreach ($c in (Get-AnalyserNode -Context $Context -TypeName 'CatchClauseAst')) {
                if ($c.Body.Statements.Count -eq 0) {
                    New-AnalyserFinding -Context $Context -StartOffset $c.Extent.StartOffset -Length 5 -Message 'Empty catch block: errors are silently ignored.' `
                        -Suggestion 'Log the error, rethrow it, or handle it. If ignoring it is deliberate, suppress this with a reason.'
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL006' -Category 'Lint' -Severity 'Info' -FixTier 'Safe' `
            -Title 'Redundant trailing semicolon' `
            -Description 'A semicolon at the end of a line does nothing in PowerShell.' `
            -Check {
            param($Context)
            $tokens = $Context.Tokens
            $forHeaders = @(Get-AnalyserNode -Context $Context -TypeName 'ForStatementAst' | ForEach-Object {
                    [pscustomobject]@{ Start = $_.Extent.StartOffset; End = $_.Body.Extent.StartOffset }
                })
            for ($i = 0; $i -lt $tokens.Count; $i++) {
                if ([string]$tokens[$i].Kind -ne 'Semi') {
                    continue
                }
                $j = $i + 1
                while ($j -lt $tokens.Count -and [string]$tokens[$j].Kind -eq 'Comment') {
                    $j++
                }
                if ($j -lt $tokens.Count -and [string]$tokens[$j].Kind -notin 'NewLine', 'EndOfInput') {
                    continue
                }
                $semi = $tokens[$i].Extent.StartOffset
                $inFor = $false
                foreach ($h in $forHeaders) {
                    if ($semi -gt $h.Start -and $semi -lt $h.End) {
                        $inFor = $true
                    }
                }
                if ($inFor) {
                    continue
                }
                $start = $semi
                while ($start -gt 0 -and ($Context.Text[$start - 1] -eq ' ' -or $Context.Text[$start - 1] -eq "`t")) {
                    $start--
                }
                New-AnalyserFinding -Context $Context -StartOffset $semi -Length 1 -Message 'Redundant semicolon at the end of the line.' -Suggestion 'Remove the semicolon.' `
                    -Data @{ RemoveStart = $start; RemoveEnd = $semi + 1 }
            }
        } `
            -Fix {
            param($Context, $Finding)
            New-AnalyserEdit -StartOffset $Finding.Data.RemoveStart -Length ($Finding.Data.RemoveEnd - $Finding.Data.RemoveStart) -ReplacementText ''
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSL007' -Category 'Lint' -Severity 'Low' -FixTier 'None' `
            -Title 'Suppression without a reason' `
            -Description 'A psa-ignore or psa-disable comment must give a reason after "--". One without a reason is not applied.' `
            -Check {
            param($Context)
            $suppressions = Get-AnalyserSuppression -Context $Context
            foreach ($p in $suppressions.Problems) {
                New-AnalyserFinding -Context $Context -StartOffset $p.Token.Extent.StartOffset -Length ($p.Token.Extent.EndOffset - $p.Token.Extent.StartOffset) `
                    -Message $p.Message -Suggestion 'Write the reason after the rule IDs, for example: # psa-ignore PSL004 -- console output by design'
            }
        }))

# ---- Security ---------------------------------------------------------------

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS001' -Category 'Security' -Severity 'Medium' -FixTier 'Suggest' -Cwe 'CWE-95' `
            -Title 'Invoke-Expression used' `
            -Description 'Invoke-Expression runs a string as code. If any part of the string comes from input, an attacker can run their own code.' `
            -Check {
            param($Context)
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Invoke-Expression', 'iex')) {
                $first = $c.Ast.CommandElements[0]
                New-AnalyserFinding -Context $Context -StartOffset $first.Extent.StartOffset -Length ($first.Extent.EndOffset - $first.Extent.StartOffset) `
                    -Message ("{0} runs a string as code." -f $c.Name) -Suggestion 'Call the command directly, or use the call operator (&) with a script block or command name.'
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS002' -Category 'Security' -Severity 'High' -FixTier 'None' -Cwe 'CWE-494' -AttackId 'T1105' `
            -Title 'Download and execute' `
            -Description 'Code is downloaded and run in one step (for example by piping Invoke-WebRequest output into Invoke-Expression), with no integrity check, so whoever controls the server or the network controls what runs.' `
            -Check {
            param($Context)
            $isDownload = {
                param($Node)
                if ($Node -is [System.Management.Automation.Language.CommandAst]) {
                    $n = $Node.GetCommandName()
                    if ($n -and $script:DownloadCommandNames -contains $n.ToLowerInvariant()) {
                        return $true
                    }
                }
                if ($Node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $Node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    if ($Node.Member.Value -in 'DownloadString', 'DownloadData', 'GetStringAsync') {
                        return $true
                    }
                }
                return $false
            }
            $flagged = New-Object -TypeName 'System.Collections.Generic.HashSet[int]'
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Invoke-Expression', 'iex')) {
                $hit = $false
                $pipeline = $c.Ast.Parent
                if ($pipeline -is [System.Management.Automation.Language.PipelineAst]) {
                    foreach ($element in $pipeline.PipelineElements) {
                        if ($element -eq $c.Ast) {
                            break
                        }
                        if (@($element.FindAll($isDownload, $true)).Count -gt 0) {
                            $hit = $true
                        }
                    }
                }
                for ($i = 1; $i -lt $c.Ast.CommandElements.Count -and -not $hit; $i++) {
                    if (@($c.Ast.CommandElements[$i].FindAll($isDownload, $true)).Count -gt 0) {
                        $hit = $true
                    }
                }
                if ($hit -and $flagged.Add($c.Ast.Extent.StartOffset)) {
                    New-AnalyserFinding -Context $Context -StartOffset $c.Ast.Extent.StartOffset -Length ($c.Ast.Extent.EndOffset - $c.Ast.Extent.StartOffset) `
                        -Message 'Downloaded content is run directly with Invoke-Expression.' -Suggestion 'Download to a file, verify its signature or hash, then run it.'
                }
            }
            foreach ($member in (Get-AnalyserNode -Context $Context -TypeName 'InvokeMemberExpressionAst')) {
                if ($member.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and $member.Expression.TypeName.Name -eq 'scriptblock' -and
                    $member.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $member.Member.Value -eq 'Create') {
                    if (@($member.FindAll($isDownload, $true)).Count -gt 0 -and $flagged.Add($member.Extent.StartOffset)) {
                        New-AnalyserFinding -Context $Context -StartOffset $member.Extent.StartOffset -Length ($member.Extent.EndOffset - $member.Extent.StartOffset) `
                            -Message 'Downloaded content is turned into a script block.' -Suggestion 'Download to a file, verify its signature or hash, then run it.'
                    }
                }
            }
            foreach ($pattern in $script:DownloadExecutePatterns) {
                foreach ($m in (Get-StringExtentMatch -Context $Context -Pattern $pattern)) {
                    if ($flagged.Add($m.Offset)) {
                        New-AnalyserFinding -Context $Context -StartOffset $m.Offset -Length $m.Length `
                            -Message 'A string contains a download-and-execute command.' -Suggestion 'Download to a file, verify its signature or hash, then run it.'
                    }
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS003' -Category 'Security' -Severity 'Medium' -FixTier 'Suggest' -Cwe 'CWE-312' -Sensitive `
            -Title 'Plaintext password handling' `
            -Description 'A secret is handled as plain text: ConvertTo-SecureString -AsPlainText, ConvertFrom-SecureString -AsPlainText, or a [string] parameter named like a password.' `
            -Check {
            param($Context)
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'ConvertTo-SecureString', 'ConvertFrom-SecureString')) {
                $param = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'AsPlainText' -MinimumPrefix 3
                if ($param) {
                    New-AnalyserFinding -Context $Context -StartOffset $c.Ast.Extent.StartOffset -Length ($c.Ast.Extent.EndOffset - $c.Ast.Extent.StartOffset) `
                        -Message ('{0} -AsPlainText handles the secret as plain text.' -f $c.Name) -Suggestion 'Use Read-Host -AsSecureString, Get-Credential or a secret store, and keep the value as a SecureString.'
                }
            }
            foreach ($p in (Get-AnalyserNode -Context $Context -TypeName 'ParameterAst')) {
                $name = $p.Name.VariablePath.UserPath
                if ($name -notmatch $script:SensitiveNamePattern) {
                    continue
                }
                $isString = $false
                foreach ($attr in $p.Attributes) {
                    if ($attr -is [System.Management.Automation.Language.TypeConstraintAst] -and $attr.TypeName.FullName -match '^(System\.)?String$') {
                        $isString = $true
                    }
                }
                if ($isString) {
                    New-AnalyserFinding -Context $Context -StartOffset $p.Name.Extent.StartOffset -Length ($p.Name.Extent.EndOffset - $p.Name.Extent.StartOffset) `
                        -Message ("Parameter `${0} looks like a secret but is a plain [string]." -f $name) -Suggestion 'Use [SecureString] or [PSCredential] instead.'
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS004' -Category 'Security' -Severity 'High' -FixTier 'None' -Cwe 'CWE-798' -Sensitive `
            -Title 'Hard-coded secret' `
            -Description 'A password, secret, token or key appears to be written into the script. The value is never shown in findings, logs or reports.' `
            -Check {
            param($Context)
            $flagged = New-Object -TypeName 'System.Collections.Generic.HashSet[int]'
            $report = {
                param($Node, $Label, $Severity)
                if (-not $flagged.Add($Node.Extent.StartOffset)) {
                    return
                }
                $length = $Node.Extent.EndOffset - $Node.Extent.StartOffset
                New-AnalyserFinding -Context $Context -StartOffset $Node.Extent.StartOffset -Length $length -Severity $Severity `
                    -Message ('Possible hard-coded secret: {0}.' -f $Label) -Suggestion 'Load it at run time from a secret store, a protected file or an environment variable, and rotate the exposed value.' `
                    -Snippet (Get-MaskedLine -Context $Context -StartOffset $Node.Extent.StartOffset -Length $length)
            }
            $isRealValue = {
                param($Value)
                return ($Value.Length -ge 4 -and $Value -notmatch $script:PlaceholderValuePattern)
            }

            foreach ($a in (Get-AnalyserNode -Context $Context -TypeName 'AssignmentStatementAst')) {
                $left = $a.Left
                if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) {
                    $left = $left.Child
                }
                $name = $null
                if ($left -is [System.Management.Automation.Language.VariableExpressionAst]) {
                    $name = $left.VariablePath.UserPath
                }
                elseif ($left -is [System.Management.Automation.Language.MemberExpressionAst] -and $left.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $name = $left.Member.Value
                }
                if (-not $name -or $name -notmatch $script:SensitiveNamePattern) {
                    continue
                }
                $value = Get-AnalyserStringValue -Ast $a.Right
                if ($value -and (& $isRealValue $value.Value)) {
                    & $report $value.Ast ("value assigned to '{0}'" -f $name) 'High'
                }
            }
            foreach ($h in (Get-AnalyserNode -Context $Context -TypeName 'HashtableAst')) {
                foreach ($pair in $h.KeyValuePairs) {
                    $key = Get-AnalyserStringValue -Ast $pair.Item1
                    if (-not $key -or $key.Value -notmatch $script:SensitiveNamePattern) {
                        continue
                    }
                    $value = Get-AnalyserStringValue -Ast $pair.Item2
                    if ($value -and (& $isRealValue $value.Value)) {
                        & $report $value.Ast ("value for key '{0}'" -f $key.Value) 'High'
                    }
                }
            }
            foreach ($p in (Get-AnalyserNode -Context $Context -TypeName 'ParameterAst')) {
                $name = $p.Name.VariablePath.UserPath
                if ($name -match $script:SensitiveNamePattern -and $p.DefaultValue) {
                    $value = Get-AnalyserStringValue -Ast $p.DefaultValue
                    if ($value -and (& $isRealValue $value.Value)) {
                        & $report $value.Ast ("default value of parameter '{0}'" -f $name) 'High'
                    }
                }
            }
            foreach ($c in $Context.Commands) {
                $elements = $c.Ast.CommandElements
                for ($i = 1; $i -lt $elements.Count; $i++) {
                    $el = $elements[$i]
                    if (-not ($el -is [System.Management.Automation.Language.CommandParameterAst]) -or $el.ParameterName -notmatch $script:SensitiveNamePattern) {
                        continue
                    }
                    $argument = $el.Argument
                    if (-not $argument -and $i + 1 -lt $elements.Count) {
                        $argument = $elements[$i + 1]
                    }
                    $value = Get-AnalyserStringValue -Ast $argument
                    if ($value -and [string]$value.Ast.StringConstantType -ne 'BareWord' -and (& $isRealValue $value.Value)) {
                        & $report $value.Ast ("argument to -{0}" -f $el.ParameterName) 'High'
                    }
                }
            }

            $tokenPatterns = [ordered]@{
                'a bearer token'           = '(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*'
                'a GitHub token'           = '\bgh[pousr]_[A-Za-z0-9]{36,}'
                'a Slack token'            = '\bxox[baprs]-[A-Za-z0-9-]{10,}'
                'an AWS access key ID'     = '\bAKIA[0-9A-Z]{16}\b'
                'a private key'            = '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
            }
            foreach ($label in $tokenPatterns.Keys) {
                foreach ($m in (Get-StringExtentMatch -Context $Context -Pattern $tokenPatterns[$label])) {
                    if ($flagged.Add($m.Node.Extent.StartOffset)) {
                        New-AnalyserFinding -Context $Context -StartOffset $m.Offset -Length $m.Length -Severity 'High' `
                            -Message ('Possible hard-coded secret: {0}.' -f $label) -Suggestion 'Load it at run time from a secret store and rotate the exposed value.' `
                            -Snippet (Get-MaskedLine -Context $Context -StartOffset $m.Offset -Length $m.Length)
                    }
                }
            }

            foreach ($node in (Get-StringNode -Context $Context)) {
                $value = Get-AnalyserStringValue -Ast $node
                if (-not $value) {
                    continue
                }
                $v = $value.Value
                if ($v.Length -lt 32 -or $v.Length -gt 512 -or $v -notmatch '^[A-Za-z0-9+/=_\-]+$') {
                    continue
                }
                if ($v -cnotmatch '[a-z]' -or $v -cnotmatch '[A-Z]' -or $v -notmatch '[0-9]') {
                    continue
                }
                if ((Get-ShannonEntropy -Text $v) -ge 4.3) {
                    & $report $node 'a long random-looking string (high entropy)' 'Medium'
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS005' -Category 'Security' -Severity 'High' -FixTier 'None' -Cwe 'CWE-295' `
            -Title 'Certificate validation bypass' `
            -Description 'TLS certificate checking is turned off, so any server, including an attacker in the middle, is trusted.' `
            -Check {
            param($Context)
            foreach ($a in (Get-AnalyserNode -Context $Context -TypeName 'AssignmentStatementAst')) {
                $left = $a.Left
                if ($left -is [System.Management.Automation.Language.MemberExpressionAst] -and $left.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $left.Member.Value -in 'ServerCertificateValidationCallback', 'ServerCertificateCustomValidationCallback') {
                    if ($a.Right.Extent.Text -match '(?i)\$true|DangerousAcceptAnyServerCertificateValidator') {
                        New-AnalyserFinding -Context $Context -StartOffset $a.Extent.StartOffset -Length ($a.Extent.EndOffset - $a.Extent.StartOffset) `
                            -Message ('{0} is set to accept every certificate.' -f $left.Member.Value) -Suggestion 'Remove the callback, or validate the certificate (for example pin its thumbprint).'
                    }
                }
            }
            foreach ($p in (Get-AnalyserNode -Context $Context -TypeName 'CommandParameterAst')) {
                if ($p.ParameterName.Length -ge 5 -and 'SkipCertificateCheck'.StartsWith($p.ParameterName, [System.StringComparison]::OrdinalIgnoreCase)) {
                    New-AnalyserFinding -Context $Context -StartOffset $p.Extent.StartOffset -Length ($p.Extent.EndOffset - $p.Extent.StartOffset) `
                        -Message '-SkipCertificateCheck turns off certificate validation.' -Suggestion 'Fix the certificate trust instead, for example by installing the issuing CA.'
                }
            }
            # Character classes stop these patterns matching their own text.
            foreach ($pattern in '(?is)ICertificateP[o]licy.{0,400}?return\s+true', '(?i)TrustAllC[e]rtsPolicy') {
                foreach ($m in (Get-StringExtentMatch -Context $Context -Pattern $pattern)) {
                    New-AnalyserFinding -Context $Context -StartOffset $m.Offset -Length $m.Length `
                        -Message 'Embedded code defines a certificate policy that trusts every certificate.' -Suggestion 'Remove the policy and fix the certificate trust instead.'
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS006' -Category 'Security' -Severity 'Medium' -FixTier 'Suggest' -Cwe 'CWE-327, CWE-319' `
            -Title 'Weak or legacy TLS, or cleartext HTTP' `
            -Description 'SSL 2.0, SSL 3.0, TLS 1.0 or TLS 1.1 is enabled (CWE-327), or a web request is sent over plain http:// (CWE-319).' `
            -Check {
            param($Context)
            $weak = '(?i)^(ssl2|ssl3|tls|tls11)$'
            foreach ($m in (Get-AnalyserNode -Context $Context -TypeName 'MemberExpressionAst')) {
                if ($m.Static -and $m.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and $m.Expression.TypeName.Name -match '(?i)(SecurityProtocolType|SslProtocols)$' -and
                    $m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $m.Member.Value -match $weak) {
                    New-AnalyserFinding -Context $Context -StartOffset $m.Extent.StartOffset -Length ($m.Extent.EndOffset - $m.Extent.StartOffset) -Cwe 'CWE-327' `
                        -Message ('{0} is a weak or legacy protocol.' -f $m.Member.Value) -Suggestion 'Use Tls12 or Tls13, or SystemDefault to let the operating system choose.'
                }
            }
            foreach ($a in (Get-AnalyserNode -Context $Context -TypeName 'AssignmentStatementAst')) {
                if ($a.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and $a.Left.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $a.Left.Member.Value -eq 'SecurityProtocol') {
                    $value = Get-AnalyserStringValue -Ast $a.Right
                    if ($value -and $value.Value -match '(?i)\b(ssl2|ssl3|tls|tls11)\b') {
                        New-AnalyserFinding -Context $Context -StartOffset $value.Ast.Extent.StartOffset -Length ($value.Ast.Extent.EndOffset - $value.Ast.Extent.StartOffset) -Cwe 'CWE-327' `
                            -Message 'SecurityProtocol includes a weak or legacy protocol.' -Suggestion 'Use Tls12 or Tls13, or SystemDefault to let the operating system choose.'
                    }
                }
            }
            foreach ($c in $Context.Commands) {
                $protocol = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'SslProtocol' -MinimumPrefix 4
                if ($protocol -and -not ($protocol -is [System.Management.Automation.Language.CommandParameterAst])) {
                    if ($protocol.Extent.Text -match '(?i)\b(ssl2|ssl3|tls|tls11)\b') {
                        New-AnalyserFinding -Context $Context -StartOffset $protocol.Extent.StartOffset -Length ($protocol.Extent.EndOffset - $protocol.Extent.StartOffset) -Cwe 'CWE-327' `
                            -Message '-SslProtocol allows a weak or legacy protocol.' -Suggestion 'Use Tls12 or Tls13.'
                    }
                }
            }
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm')) {
                $uri = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'Uri'
                if (-not $uri) {
                    $uri = Get-CommandPositionalArgument -CommandAst $c.Ast -Index 0
                }
                $value = Get-AnalyserStringValue -Ast $uri
                if ($value -and $value.Value -match '^(?i)http://' -and $value.Value -notmatch '^(?i)http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)') {
                    New-AnalyserFinding -Context $Context -StartOffset $value.Ast.Extent.StartOffset -Length ($value.Ast.Extent.EndOffset - $value.Ast.Extent.StartOffset) -Severity 'Low' -Cwe 'CWE-319' `
                        -Message 'Web request over cleartext HTTP.' -Suggestion 'Use https:// so the request and response are encrypted.'
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS007' -Category 'Security' -Severity 'Low' -FixTier 'Suggest' -Cwe 'CWE-328' `
            -Title 'Weak hash algorithm' `
            -Description 'MD5 or SHA1 is used. Both are broken for security purposes, though still acceptable for non-security checksums.' `
            -Check {
            param($Context)
            $weakType = '(?i)(^|\.)(MD5|SHA1|MD5CryptoServiceProvider|SHA1CryptoServiceProvider|SHA1Managed|MD5Cng|SHA1Cng|HMACMD5|HMACSHA1)$'
            $suggestion = 'Use SHA256 or stronger. If this is only a non-security checksum, suppress this finding with a reason.'
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Get-FileHash')) {
                $algorithm = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'Algorithm'
                $value = Get-AnalyserStringValue -Ast $algorithm
                if ($value -and $value.Value -match '(?i)^(MD5|SHA1)$') {
                    New-AnalyserFinding -Context $Context -StartOffset $algorithm.Extent.StartOffset -Length ($algorithm.Extent.EndOffset - $algorithm.Extent.StartOffset) `
                        -Message ('Get-FileHash uses {0}.' -f $value.Value) -Suggestion $suggestion
                }
            }
            foreach ($typeName in 'TypeExpressionAst', 'TypeConstraintAst') {
                foreach ($t in (Get-AnalyserNode -Context $Context -TypeName $typeName)) {
                    if ($t.TypeName.FullName -match $weakType) {
                        New-AnalyserFinding -Context $Context -StartOffset $t.Extent.StartOffset -Length ($t.Extent.EndOffset - $t.Extent.StartOffset) `
                            -Message ('{0} is a weak hash algorithm.' -f $t.TypeName.Name) -Suggestion $suggestion
                    }
                }
            }
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'New-Object')) {
                $typeArg = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'TypeName'
                if (-not $typeArg) {
                    $typeArg = Get-CommandPositionalArgument -CommandAst $c.Ast -Index 0
                }
                $value = Get-AnalyserStringValue -Ast $typeArg
                if ($value -and $value.Value -match $weakType) {
                    New-AnalyserFinding -Context $Context -StartOffset $typeArg.Extent.StartOffset -Length ($typeArg.Extent.EndOffset - $typeArg.Extent.StartOffset) `
                        -Message ('{0} is a weak hash algorithm.' -f $value.Value) -Suggestion $suggestion
                }
            }
            foreach ($m in (Get-AnalyserNode -Context $Context -TypeName 'InvokeMemberExpressionAst')) {
                if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $m.Member.Value -in 'Create', 'CreateFromName' -and $m.Arguments.Count -gt 0) {
                    $value = Get-AnalyserStringValue -Ast $m.Arguments[0]
                    if ($value -and $value.Value -match '(?i)^(System\.Security\.Cryptography\.)?(MD5|SHA1)$') {
                        New-AnalyserFinding -Context $Context -StartOffset $m.Extent.StartOffset -Length ($m.Extent.EndOffset - $m.Extent.StartOffset) `
                            -Message ('{0} is a weak hash algorithm.' -f $value.Value) -Suggestion $suggestion
                    }
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS008' -Category 'Security' -Severity 'Medium' -FixTier 'Suggest' -Cwe 'CWE-78' `
            -Title 'Possible command injection' `
            -Description 'A command line is built by interpolating or concatenating variables and then run with Start-Process, cmd /c, powershell -Command, or the call operator. Interpolating only $env: variables or $PSScriptRoot does not count.' `
            -Check {
            param($Context)
            $suggestion = 'Pass arguments as an array of separate values, and validate any input that reaches a command line.'
            foreach ($c in $Context.Commands) {
                $elements = $c.Ast.CommandElements
                $name = $c.NameLower
                $hit = $null
                if ($name -in 'start-process', 'saps', 'start') {
                    for ($i = 1; $i -lt $elements.Count; $i++) {
                        $el = $elements[$i]
                        if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                            $el = $el.Argument
                        }
                        if (Test-DynamicStringAst -Ast $el) {
                            $hit = 'Start-Process is given a command line built from variables.'
                        }
                    }
                }
                elseif ($name -in 'cmd', 'cmd.exe') {
                    $afterSwitch = $false
                    for ($i = 1; $i -lt $elements.Count; $i++) {
                        if ($elements[$i].Extent.Text -match '^(?i)/[ck]$') {
                            $afterSwitch = $true
                        }
                        elseif ($afterSwitch -and (Test-DynamicStringAst -Ast $elements[$i])) {
                            $hit = 'cmd /c is given a command line built from variables.'
                        }
                    }
                }
                elseif ($name -in 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe') {
                    $command = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'Command' -MinimumPrefix 1
                    if ($command -and (Test-DynamicStringAst -Ast $command)) {
                        $hit = 'powershell -Command is given a command built from variables.'
                    }
                }
                if (-not $hit -and [string]$c.Ast.InvocationOperator -in 'Ampersand', 'Dot' -and (Test-DynamicStringAst -Ast $elements[0])) {
                    $hit = 'The call operator runs a command name built from variables.'
                }
                if ($hit) {
                    New-AnalyserFinding -Context $Context -StartOffset $c.Ast.Extent.StartOffset -Length ($c.Ast.Extent.EndOffset - $c.Ast.Extent.StartOffset) -Message $hit -Suggestion $suggestion
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS009' -Category 'Security' -Severity 'High' -FixTier 'Suggest' -Cwe 'CWE-89' `
            -Title 'Possible SQL injection' `
            -Description 'A SQL query is built by interpolating or concatenating variables, for Invoke-Sqlcmd or a SqlCommand.' `
            -Check {
            param($Context)
            $suggestion = 'Use a parameterised query: -Variable with Invoke-Sqlcmd, or SqlParameter objects with SqlCommand.'
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Invoke-Sqlcmd')) {
                $query = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'Query'
                if (-not $query) {
                    $query = Get-CommandPositionalArgument -CommandAst $c.Ast -Index 0
                }
                if (Test-DynamicStringAst -Ast $query) {
                    New-AnalyserFinding -Context $Context -StartOffset $query.Extent.StartOffset -Length ($query.Extent.EndOffset - $query.Extent.StartOffset) `
                        -Message 'Invoke-Sqlcmd is given a query built from variables.' -Suggestion $suggestion
                }
            }
            foreach ($a in (Get-AnalyserNode -Context $Context -TypeName 'AssignmentStatementAst')) {
                if ($a.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and $a.Left.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $a.Left.Member.Value -eq 'CommandText' -and (Test-DynamicStringAst -Ast $a.Right)) {
                    New-AnalyserFinding -Context $Context -StartOffset $a.Right.Extent.StartOffset -Length ($a.Right.Extent.EndOffset - $a.Right.Extent.StartOffset) `
                        -Message 'CommandText is set to a query built from variables.' -Suggestion $suggestion
                }
            }
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'New-Object')) {
                $typeArg = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'TypeName'
                if (-not $typeArg) {
                    $typeArg = Get-CommandPositionalArgument -CommandAst $c.Ast -Index 0
                }
                $typeValue = Get-AnalyserStringValue -Ast $typeArg
                if (-not $typeValue -or $typeValue.Value -notmatch '(?i)SqlCommand$') {
                    continue
                }
                $arguments = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'ArgumentList'
                if (-not $arguments) {
                    $arguments = Get-CommandPositionalArgument -CommandAst $c.Ast -Index 1
                }
                if ($arguments -and (Test-DynamicStringAst -Ast $arguments)) {
                    New-AnalyserFinding -Context $Context -StartOffset $arguments.Extent.StartOffset -Length ($arguments.Extent.EndOffset - $arguments.Extent.StartOffset) `
                        -Message 'A SqlCommand is created with a query built from variables.' -Suggestion $suggestion
                }
            }
            foreach ($m in (Get-AnalyserNode -Context $Context -TypeName 'InvokeMemberExpressionAst')) {
                if ($m.Static -and $m.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and $m.Expression.TypeName.Name -match '(?i)SqlCommand$' -and
                    $m.Member.Value -eq 'new' -and $m.Arguments.Count -gt 0 -and (Test-DynamicStringAst -Ast $m.Arguments[0])) {
                    New-AnalyserFinding -Context $Context -StartOffset $m.Extent.StartOffset -Length ($m.Extent.EndOffset - $m.Extent.StartOffset) `
                        -Message 'A SqlCommand is created with a query built from variables.' -Suggestion $suggestion
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSS010' -Category 'Security' -Severity 'Medium' -FixTier 'Suggest' -Cwe 'CWE-693' `
            -Title 'Security control bypass' `
            -Description 'Execution policy is bypassed (ATT&CK T1059.001), an encoded command is used (T1027), or Microsoft Defender exclusions or protections are changed (T1562.001).' `
            -Check {
            param($Context)
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe')) {
                foreach ($el in $c.Ast.CommandElements) {
                    if (-not ($el -is [System.Management.Automation.Language.CommandParameterAst])) {
                        continue
                    }
                    $typed = $el.ParameterName.ToLowerInvariant()
                    if ($typed -eq 'ep' -or ($typed.Length -ge 2 -and 'executionpolicy'.StartsWith($typed))) {
                        $value = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName $el.ParameterName
                        if ($value -and $value.Extent.Text -match '(?i)^["'']?(bypass|unrestricted)["'']?$') {
                            New-AnalyserFinding -Context $Context -StartOffset $el.Extent.StartOffset -Length ($value.Extent.EndOffset - $el.Extent.StartOffset) -AttackId 'T1059.001' `
                                -Message ('PowerShell is started with the execution policy set to {0}.' -f $value.Extent.Text.Trim('"', "'")) -Suggestion 'Sign the script, or use RemoteSigned or AllSigned.'
                        }
                    }
                    elseif ($typed -in 'e', 'ec' -or ($typed.Length -ge 2 -and 'encodedcommand'.StartsWith($typed))) {
                        New-AnalyserFinding -Context $Context -StartOffset $el.Extent.StartOffset -Length ($el.Extent.EndOffset - $el.Extent.StartOffset) -Severity 'High' -AttackId 'T1027' `
                            -Message 'PowerShell is started with an encoded command, which hides what it runs.' -Suggestion 'Run a script file instead, so the code can be reviewed and signed.'
                    }
                }
            }
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Set-ExecutionPolicy')) {
                $value = Get-CommandArgumentAst -CommandAst $c.Ast -ParameterName 'ExecutionPolicy'
                if (-not $value) {
                    $value = Get-CommandPositionalArgument -CommandAst $c.Ast -Index 0
                }
                if ($value -and $value.Extent.Text -match '(?i)^["'']?(bypass|unrestricted)["'']?$') {
                    New-AnalyserFinding -Context $Context -StartOffset $c.Ast.Extent.StartOffset -Length ($c.Ast.Extent.EndOffset - $c.Ast.Extent.StartOffset) -AttackId 'T1059.001' `
                        -Message ('The execution policy is set to {0}.' -f $value.Extent.Text.Trim('"', "'")) -Suggestion 'Use RemoteSigned or AllSigned, and sign your scripts.'
                }
            }
            foreach ($c in (Get-AnalyserCommand -Context $Context -Name 'Add-MpPreference', 'Set-MpPreference')) {
                foreach ($el in $c.Ast.CommandElements) {
                    if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $el.ParameterName -match '(?i)^(Exclusion|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|DisableBlockAtFirstSeen)') {
                        New-AnalyserFinding -Context $Context -StartOffset $c.Ast.Extent.StartOffset -Length ($c.Ast.Extent.EndOffset - $c.Ast.Extent.StartOffset) -Severity 'High' -AttackId 'T1562.001' `
                            -Message ('{0} -{1} weakens Microsoft Defender.' -f $c.Name, $el.ParameterName) -Suggestion 'Manage Defender exclusions centrally (Intune or Group Policy) and keep them as narrow as possible.'
                        break
                    }
                }
            }
            $stringPatterns = @(
                @{ Pattern = '(?i)(?:^|[\s"''])-(?:ep|ex|exec|executionpolicy)\s+["'']?(?:bypass|unrestricted)\b'; AttackId = 'T1059.001'; Severity = 'Medium'; Message = 'A command line in a string sets the execution policy to Bypass or Unrestricted.' }
                @{ Pattern = '(?i)(?:powershell|pwsh)(?:\.exe)?["'']?\s+(?:-\S+\s+)*-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{16,}'; AttackId = 'T1027'; Severity = 'High'; Message = 'A command line in a string starts PowerShell with an encoded command.' }
            )
            foreach ($sp in $stringPatterns) {
                foreach ($m in (Get-StringExtentMatch -Context $Context -Pattern $sp.Pattern)) {
                    New-AnalyserFinding -Context $Context -StartOffset $m.Offset -Length $m.Length -Severity $sp.Severity -AttackId $sp.AttackId -Message $sp.Message `
                        -Suggestion 'Run a signed script file instead.'
                }
            }
        }))

# ---- Compatibility ----------------------------------------------------------

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSC001' -Category 'Compatibility' -Severity 'High' -FixTier 'None' `
            -Title 'Not available on Windows PowerShell 5.1' `
            -Description 'Syntax, cmdlets or parameters that need PowerShell 7 (??, ??=, ternary, &&, ||, ?., ?[], ForEach-Object -Parallel and others). Only checked when 5.1 is a target version. Under 5.1 itself, the syntax cannot be parsed, so it is found from the parse errors instead.' `
            -Check {
            param($Context)
            if (-not $Context.Targets51) {
                return
            }
            $suggestion = 'Rewrite it for Windows PowerShell 5.1, or remove 5.1 from targetVersions if the script only needs to run on PowerShell 7.'
            if ($Context.RunningEngine -eq '5.1') {
                foreach ($e in $Context.ParseErrors) {
                    if (Test-SevenOnlySyntaxError -ParseError $e) {
                        New-AnalyserFinding -Context $Context -StartOffset $e.Extent.StartOffset -Length ($e.Extent.EndOffset - $e.Extent.StartOffset) `
                            -Message ("'{0}' is PowerShell 7 syntax and is a parse error on Windows PowerShell 5.1." -f $e.Extent.Text) -Suggestion $suggestion
                    }
                }
            }
            else {
                foreach ($n in (Get-AnalyserNode -Context $Context -TypeName 'TernaryExpressionAst')) {
                    New-AnalyserFinding -Context $Context -StartOffset $n.Extent.StartOffset -Length ($n.Extent.EndOffset - $n.Extent.StartOffset) -Message 'The ternary operator (? :) needs PowerShell 7.' -Suggestion $suggestion
                }
                foreach ($n in (Get-AnalyserNode -Context $Context -TypeName 'PipelineChainAst')) {
                    New-AnalyserFinding -Context $Context -StartOffset $n.Extent.StartOffset -Length ($n.Extent.EndOffset - $n.Extent.StartOffset) -Message ("The pipeline chain operator '{0}' needs PowerShell 7." -f $(if ([string]$n.Operator -eq 'AndAnd') { '&&' } else { '||' })) -Suggestion $suggestion
                }
                foreach ($n in (Get-AnalyserNode -Context $Context -TypeName 'BinaryExpressionAst')) {
                    if ([string]$n.Operator -eq 'QuestionQuestion') {
                        New-AnalyserFinding -Context $Context -StartOffset $n.Extent.StartOffset -Length ($n.Extent.EndOffset - $n.Extent.StartOffset) -Message "The null-coalescing operator '??' needs PowerShell 7." -Suggestion $suggestion
                    }
                }
                foreach ($n in (Get-AnalyserNode -Context $Context -TypeName 'AssignmentStatementAst')) {
                    if ([string]$n.Operator -eq 'QuestionQuestionEquals') {
                        New-AnalyserFinding -Context $Context -StartOffset $n.Extent.StartOffset -Length ($n.Extent.EndOffset - $n.Extent.StartOffset) -Message "The null-coalescing assignment operator '??=' needs PowerShell 7." -Suggestion $suggestion
                    }
                }
                foreach ($typeName in 'MemberExpressionAst', 'InvokeMemberExpressionAst', 'IndexExpressionAst') {
                    foreach ($n in (Get-AnalyserNode -Context $Context -TypeName $typeName)) {
                        $prop = $n.PSObject.Properties['NullConditional']
                        if ($prop -and $prop.Value) {
                            New-AnalyserFinding -Context $Context -StartOffset $n.Extent.StartOffset -Length ($n.Extent.EndOffset - $n.Extent.StartOffset) -Message "The null-conditional operator ('?.' or '?[]') needs PowerShell 7." -Suggestion $suggestion
                        }
                    }
                }
            }
            foreach ($c in $Context.Commands) {
                if (-not $c.NameLower) {
                    continue
                }
                if ($script:SevenOnlyCommandTable.ContainsKey($c.NameLower)) {
                    $first = $c.Ast.CommandElements[0]
                    New-AnalyserFinding -Context $Context -StartOffset $first.Extent.StartOffset -Length ($first.Extent.EndOffset - $first.Extent.StartOffset) `
                        -Message ('{0} needs PowerShell 7.' -f $script:SevenOnlyCommandTable[$c.NameLower]) -Suggestion $suggestion
                }
                foreach ($entry in $script:SevenOnlyParameterTable) {
                    if ($entry.Commands -notcontains $c.NameLower) {
                        continue
                    }
                    foreach ($el in $c.Ast.CommandElements) {
                        if (-not ($el -is [System.Management.Automation.Language.CommandParameterAst])) {
                            continue
                        }
                        foreach ($full in $entry.Parameters) {
                            if ($el.ParameterName.Length -ge $entry.MinimumPrefix -and $full.StartsWith($el.ParameterName, [System.StringComparison]::OrdinalIgnoreCase)) {
                                New-AnalyserFinding -Context $Context -StartOffset $el.Extent.StartOffset -Length ($el.Extent.EndOffset - $el.Extent.StartOffset) `
                                    -Message ('{0} -{1} needs PowerShell 7.' -f $c.Name, $full) -Suggestion $suggestion
                            }
                        }
                    }
                }
            }
        }))

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PSC002' -Category 'Compatibility' -Severity 'Medium' -FixTier 'Suggest' `
            -Title 'Not available on PowerShell 7' `
            -Description 'Cmdlets that were removed in PowerShell 7, such as the WMI and classic event log cmdlets. Only checked when 7 is a target version.' `
            -Check {
            param($Context)
            if (-not $Context.Targets7) {
                return
            }
            foreach ($c in $Context.Commands) {
                if ($c.NameLower -and $script:MissingOnSevenTable.ContainsKey($c.NameLower)) {
                    $first = $c.Ast.CommandElements[0]
                    New-AnalyserFinding -Context $Context -StartOffset $first.Extent.StartOffset -Length ($first.Extent.EndOffset - $first.Extent.StartOffset) `
                        -Message ('{0} does not exist on PowerShell 7.' -f $c.Name) -Suggestion ('Use {0}. If the call is guarded so it only runs on 5.1, suppress this finding with a reason.' -f $script:MissingOnSevenTable[$c.NameLower])
                }
            }
        }))

# ---- Toolkit conformance ----------------------------------------------------

$script:AnalyserRules.Add((New-AnalyserRule -Id 'PST001' -Category 'Toolkit' -Severity 'Medium' -FixTier 'None' `
            -Title 'Toolkit template region' `
            -Description 'For toolkit scripts (those with a PC-CONFIG or PC-TEMPLATE region), the PC-TEMPLATE region must be present, well formed, and at the canonical version set in toolkit.templateVersion.' `
            -Check {
            param($Context)
            $text = $Context.Text
            $configMarker = [regex]::Match($text, '(?m)^#region PC-CONFIG\s*$')
            $start = [regex]::Match($text, '(?m)^#region PC-TEMPLATE(?: v(\S+))?[ \t]*\r?$')
            if (-not $configMarker.Success -and -not $start.Success) {
                return
            }
            $suggestion = 'Re-sync the PC-TEMPLATE region from the canonical template.'
            if (-not $start.Success) {
                New-AnalyserFinding -Context $Context -StartOffset $configMarker.Index -Length $configMarker.Length -Message 'This toolkit script has no PC-TEMPLATE region.' -Suggestion $suggestion
                return
            }
            $version = $start.Groups[1].Value
            $canonical = $Context.Config.toolkit.templateVersion
            if (-not $version) {
                New-AnalyserFinding -Context $Context -StartOffset $start.Index -Length $start.Length -Message 'The PC-TEMPLATE region marker has no version.' -Suggestion $suggestion
                return
            }
            $end = [regex]::Match($text, '(?m)^#endregion PC-TEMPLATE(?: v(\S+))?[ \t]*\r?$')
            if (-not $end.Success) {
                New-AnalyserFinding -Context $Context -StartOffset $start.Index -Length $start.Length -Message 'The PC-TEMPLATE region has no #endregion marker.' -Suggestion $suggestion
            }
            elseif ($end.Groups[1].Value -ne $version) {
                New-AnalyserFinding -Context $Context -StartOffset $end.Index -Length $end.Length -Message ('The PC-TEMPLATE region starts at v{0} but ends at v{1}.' -f $version, $end.Groups[1].Value) -Suggestion $suggestion
            }
            $variable = [regex]::Match($text, "(?m)^\`$TemplateVersion\s*=\s*'([^']*)'")
            if ($variable.Success -and $variable.Groups[1].Value -ne $version) {
                New-AnalyserFinding -Context $Context -StartOffset $variable.Index -Length $variable.Length -Message ('$TemplateVersion is {0} but the region marker says v{1}.' -f $variable.Groups[1].Value, $version) -Suggestion $suggestion
            }
            if ($canonical -and $version -ne $canonical) {
                New-AnalyserFinding -Context $Context -StartOffset $start.Index -Length $start.Length -Message ('The PC-TEMPLATE region is v{0}; the canonical version is v{1}.' -f $version, $canonical) -Suggestion $suggestion
            }
        }))
#endregion RULES

#region MAIN
function Invoke-AnalyserScan {
    <#
    .SYNOPSIS
        Analyses every target file and returns one result per file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Target
    )

    $results = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($t in $Target) {
        try {
            $results.Add((Invoke-AnalyserFile -Target $t))
        }
        catch {
            Write-Log ('Could not analyse {0}: {1}' -f $t.FullName, $_.Exception.Message) -Level Error
            $script:RunFailed = $true
        }
    }
    return $results.ToArray()
}

function Get-AnalyserFixPlan {
    <#
    .SYNOPSIS
        Returns, for each file with safe fixes, the merged list of edits to apply.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Result
    )

    $plan = New-Object -TypeName 'System.Collections.Generic.List[object]'
    foreach ($r in $Result) {
        # @() matters on 5.1, where a single [pscustomobject] has no Count property.
        $edits = @(Select-AnalyserEdit -Edit (Get-AnalyserEdit -Result $r) -FilePath $r.Context.Path)
        if ($edits.Count -gt 0) {
            $plan.Add([pscustomobject]@{ Result = $r; Edits = $edits })
        }
    }
    return $plan.ToArray()
}

function Split-ListParameter {
    <#
    .SYNOPSIS
        Splits comma-separated entries in a list parameter.
    .DESCRIPTION
        "powershell -File script.ps1 -Rules A,B" passes "A,B" as one string, unlike
        -Command, so list parameters are split on commas here.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowEmptyCollection()]
        [string[]]$Value = @()
    )

    return , @($Value | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$exitCode = 0
try {
    $Rules = Split-ListParameter -Value $Rules
    $ExcludeRules = Split-ListParameter -Value $ExcludeRules
    $Exclude = Split-ListParameter -Value $Exclude
    $Report = Split-ListParameter -Value $Report
    foreach ($format in $Report) {
        if ($format -notin 'Csv', 'Json') {
            throw ('-Report accepts Csv and Json, not "{0}".' -f $format)
        }
    }

    if ($ListRules) {
        Show-RuleCatalogue
    }
    else {
        $targets = @(Get-AnalyserTarget -InputPath $Path)
        Write-AnalyserLine -Text ('{0} {1}: analysing {2} file(s) on PowerShell {3}' -f $ScriptName, $ScriptVersion, $targets.Count, $script:RunningEngine) -Colour 'White'
        Write-Console

        $results = @(Invoke-AnalyserScan -Target $targets)
        Show-AnalyserFinding -Result $results
        $visible = @($results | ForEach-Object { Select-AnalyserVisible -Finding $_.Findings })
        Write-AnalyserLine -Text (Get-AnalyserSummaryText -Finding $visible) -Colour 'White'

        $plan = @(Get-AnalyserFixPlan -Result $results)
        $safeCount = @($visible | Where-Object { $_.FixTier -eq 'Safe' }).Count
        $applyFixes = $false

        if ($plan.Count -gt 0) {
            if ($Fix) {
                $applyFixes = $true
                Write-LogFile -level Info -message ('-Fix was supplied: applying {0} safe fix(es).' -f $safeCount)
            }
            elseif ($WhatIfPreference) {
                Write-AnalyserLine -Text 'Safe fixes are available. Use -Fix with -WhatIf to see them as a diff.'
            }
            elseif ($script:RunMode -eq 'interactive') {
                $decided = $false
                while (-not $decided) {
                    $answer = Read-Host ('Apply {0} safe fix(es) now? (y/N/d=show diff)' -f $safeCount)
                    $answer = ([string]$answer).Trim().ToLowerInvariant()
                    if ($answer -eq 'd') {
                        Show-AnalyserDiff -Plan $plan
                    }
                    else {
                        $decided = $true
                        $applyFixes = ($answer -in 'y', 'yes')
                    }
                }
                Write-LogFile -level Info -message ('Prompt answered: safe fixes {0}.' -f $(if ($applyFixes) { 'accepted' } else { 'declined' }))
            }
            else {
                Write-AnalyserLine -Text 'Unattended run: safe fixes are reported but not applied. Use -Fix to apply them.'
            }
        }

        if ($applyFixes) {
            if ($WhatIfPreference) {
                Write-Console
                Show-AnalyserDiff -Plan $plan
                Write-AnalyserLine -Text ('WhatIf: {0} safe fix(es) in {1} file(s) shown above; nothing was written.' -f $safeCount, $plan.Count) -Colour 'White'
            }
            else {
                $applied = 0
                $filesChanged = 0
                foreach ($item in $plan) {
                    $count = Invoke-AnalyserFix -Result $item.Result -Edit $item.Edits
                    if ($count -gt 0) {
                        $applied += $count
                        $filesChanged++
                    }
                }
                Write-Console
                Write-AnalyserLine -Text ('Applied {0} edit(s) to {1} file(s).' -f $applied, $filesChanged) -Colour 'Green'

                if ($filesChanged -gt 0) {
                    $results = @(Invoke-AnalyserScan -Target $targets)
                    $visible = @($results | ForEach-Object { Select-AnalyserVisible -Finding $_.Findings })
                    if ($visible.Count -gt 0) {
                        Write-AnalyserLine -Text 'Remaining findings after fixes:' -Colour 'White'
                        Write-Console
                        Show-AnalyserFinding -Result $results
                    }
                    Write-AnalyserLine -Text ('After fixes: {0}' -f (Get-AnalyserSummaryText -Finding $visible)) -Colour 'White'
                }
            }
        }

        if ($Report.Count -gt 0) {
            Export-AnalyserReport -Result $results
        }

        if ($FailOnSeverity -ne 'None') {
            $threshold = $script:SeverityRank[$FailOnSeverity]
            $failing = @($results | ForEach-Object { $_.Findings } | Where-Object { $null -ne $_ -and $script:SeverityRank[$_.Severity] -ge $threshold })
            if ($failing.Count -gt 0) {
                Write-Log ('{0} finding(s) at or above {1} severity: exiting with code 2 (-FailOnSeverity).' -f $failing.Count, $FailOnSeverity)
                $exitCode = 2
            }
        }
    }
}
catch {
    Write-Log ('{0} failed: {1}' -f $ScriptName, $_.Exception.Message) -Level Error
    Write-Log ('Location: {0}' -f $_.InvocationInfo.PositionMessage) -Level Debug
    $exitCode = 1
}
finally {
    try {
        Invoke-UpdateCheckAndTelemetry
    }
    catch {
        Write-Log ('Update check or telemetry error: {0}' -f $_.Exception.Message) -Level Debug
    }
}

# A failed run takes precedence over -FailOnSeverity, since its results are incomplete.
if ($script:RunFailed) {
    $exitCode = 1
}
Write-Log ('{0} finished with exit code {1}.' -f $ScriptName, $exitCode) -Level Debug
exit $exitCode
#endregion MAIN
