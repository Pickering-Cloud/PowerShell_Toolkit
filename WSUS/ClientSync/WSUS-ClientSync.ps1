<#
    .SYNOPSIS
        Forces a Windows client to check in against its configured WSUS server,
        collecting diagnostic information and optionally remediating common
        synchronisation and installation errors automatically.

    .DESCRIPTION
        Collects the currently configured WSUS server/status server from Group
        Policy, verifies name resolution, network reachability, and (if HTTPS)
        certificate trust. Checks for a pending reboot, low disk space, and
        disabled prerequisite services. Attempts synchronisation against WSUS,
        retrying up to a configured number of times. Reviews update history for
        errors that occurred during this run and, if -AutomaticallyRemediate is
        set, attempts known fixes for recognised error codes before retrying
        synchronisation once more.

        Designed to run unattended, including via PowerShell remoting across
        many machines simultaneously, and via Scheduled Task. No interactive
        prompts. Writes an HTML report and CSV export per run, in addition to
        the log file and Application event log entries.

    .PARAMETER AutomaticallyRemediate
        If set, attempts to automatically fix recognised issues (disabled
        services, corrupted component store, stale caches, etc.) rather than
        only reporting them. Some detected issues (policy-managed settings)
        are never auto-remediated regardless of this switch, since doing so
        would override a deliberate administrative decision.

    .PARAMETER OutputRoot
        Deprecated, kept so existing scheduled tasks keep working. When
        supplied, the log is written to <OutputRoot>\Logs\WSUSClientSync\ClientSync.log
        and reports to <OutputRoot>\Reports\WSUSClientSync, unless -LogPath or
        -ReportPath is also supplied.

    .PARAMETER LogPath
        Log file location. Defaults to
        C:\ProgramData\PickeringCloud\ClientSync\Logs\ClientSync.log. The file is
        appended to across runs and rotated at 10 MB. -CustomLogPath is
        accepted as an alias for compatibility with earlier versions.

    .PARAMETER LoggingLevel
        Debug, Verbose, Info, Warn, Error, Critical or None (1 to 7, 0 also
        means None). Defaults to Info. -Debug and -Verbose raise it if this is
        not set.

    .PARAMETER ReportPath
        Folder for the HTML report and CSV exports. Defaults to
        C:\ProgramData\PickeringCloud\ClientSync\Reports.

    .PARAMETER RetentionDays
        Reports older than this many days are removed. Default 30. 0 disables
        cleanup. Only this tool's own reports are removed. -LogRetentionDays is
        accepted as an alias for compatibility with earlier versions.

    .PARAMETER DisableUpdateCheck
        Skips the check for a newer version. No network request is made for
        this purpose.

    .PARAMETER DisableTelemetry
        Stops anonymous usage telemetry being sent. The update check still runs
        unless -DisableUpdateCheck is also used. The PICKERINGCLOUD_NOTELEMETRY=1
        and DO_NOT_TRACK=1 environment variables do the same.

    .EXAMPLE
        .\WSUS-ClientSync.ps1

        Runs diagnostics and a sync attempt, reporting any issues found without
        changing anything.

    .EXAMPLE
        .\WSUS-ClientSync.ps1 -AutomaticallyRemediate -LogPath D:\Logs\wsus.log

        Runs diagnostics, attempts automatic remediation of recognised issues,
        and retries synchronisation once afterward.

    .OUTPUTS
        None. Writes progress and results to the configured log file, the
        Application event log (source: "WSUS Client Sync Script"), and an
        HTML report + CSV export under -ReportPath. See the project README for
        the full event ID map.

    .NOTES
        Author: Bradley Pickering
        Version: 1.2.0
        GitHub: https://github.com/Pickering-Cloud
        Requires: No special module dependencies beyond built-in Windows
        Update Agent COM APIs.
        Update check and telemetry: when the script finishes it reads a static
        version file from pickering.cloud and tells you if a newer version
        exists. It never downloads or installs anything. Unless disabled, it
        also sends anonymous usage data (tool, version, OS, PowerShell version,
        timezone, run mode). No server names, machine names, update or error
        details are sent. See TELEMETRY.md in the repository root for the full
        list. Neither feature prompts in a remote or unattended session.
#>

##################################################
# Script Parameters
##################################################

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    # ---- Script-specific parameters go here (each one ends with a comma) ----
    [switch]$AutomaticallyRemediate,
    [string]$OutputRoot,

    # ---- Standard toolkit parameters (do not remove) ----
    [Alias('CustomLogPath')]
    [string]$LogPath,
    [string]$LoggingLevel,
    [string]$ReportPath,
    [Alias('LogRetentionDays')]
    [ValidateRange(0, 3650)]
    [int]$RetentionDays,
    [switch]$DisableUpdateCheck,
    [switch]$DisableTelemetry
)

#region PC-CONFIG

# Per-tool values
$ScriptName    = 'ClientSync'   # Must match the key in versions.json
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
$EventLogSource = 'WSUS Client Sync Script'   # (tool override) Unchanged from 1.x so existing event log monitoring still matches.
#endregion PC-CONFIG

# Deprecated -OutputRoot: keep the pre-1.2.0 layout for anyone still passing it.
if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
    if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path -Path $OutputRoot -ChildPath ('Logs\WSUSClientSync\{0}.log' -f $ScriptName) }
    if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = Join-Path -Path $OutputRoot -ChildPath 'Reports\WSUSClientSync' }
}

# Runs through PowerShell remoting are never interactive, even if the session looks it.
if ($PSSenderInfo) {
    $script:RunMode = 'unattended'
}

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

##################################################
# Variables
##################################################
$Script:startTime = Get-Date
[string]$Script:reportBaseName = '{0}_{1}' -f $ScriptName, $RunStamp
[int]$Script:minimumRequiredGB = 10
$Script:syncAttempts = 3
$Script:updateErrors = @()
$Script:serviceStates = @()
$Script:actionsTaken = @()
$Script:sfcAlreadyRun = $false
$Script:dismAlreadyRun = $false
$Script:sdFolderResetAlreadyRun = $false
$Script:bitsQueueResetAlreadyRun = $false
$Script:bitsQueueFileResetAlreadyRun = $false

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

# The main body runs inside try/finally so the update check and telemetry run on every
# exit path, including Exit-WithError.
try {
    Initialize-OutputFolder

    ########## Collate Existing Configuration ##########

    Write-Log -Level DEBUG -Message "Beginning configuration collection"

    # WSUS server info
    [System.Uri]$initialWUServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUServer
    [System.Uri]$initialWUStatusServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUStatusServer
    Write-Log -Level DEBUG -Message "Pre-gpupdate WUServer=$initialWUServer; WUStatusServer=$initialWUStatusServer"

    Write-Log -Level DEBUG -Message "Forcing Group Policy update"
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Force Group Policy update (gpupdate /force)')) {
        $groupPolicyResult = gpupdate /force /target:computer 2>&1
        Write-Log -Level DEBUG -Message "gpupdate output: $($groupPolicyResult -join ' | ')"
        if ($groupPolicyResult -match 'failed|error') {
            Write-Log -Level WARN -Message "gpupdate output suggests a possible failure, review debug log output above."
        }
    }

    [System.Uri]$WUServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUServer
    [System.Uri]$WUStatusServer = (Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -ErrorAction SilentlyContinue).WUStatusServer
    Write-Log -Level DEBUG -Message "Post-gpupdate WUServer=$WUServer; WUStatusServer=$WUStatusServer"

    if ($initialWUServer -ne $WUServer) {
        Write-Log -Level INFO -Message "Group Policy update amended configured WSUS server"
    }
    if ($initialWUStatusServer -ne $WUStatusServer) {
        Write-Log -Level INFO -Message "Group Policy update amended configured WSUS Status server"
    }

    if ($null -eq $WUServer) {
        Exit-WithError -EventId 1002 -Message "No WSUS server configured - please review Group Policy/Registry configuration"
    }
    if ($null -eq $WUStatusServer) {
        Exit-WithError -EventId 1003 -Message "No WSUS Status server configured - please review Group Policy/Registry configuration"
    }

    Write-Log -Level DEBUG -Message "Configured WSUS server is $WUServer. Configured WSUS Status server is $WUStatusServer"

        ########## Test Configurations ##########

    Write-Log -Level DEBUG -Message "Beginning configuration testing"

    # Attempt to resolve DNS name
    Write-Log -Level DEBUG -Message "Attempting to resolve DNS name"
    $parsedIP = $null
    if ([System.Net.IPAddress]::TryParse($WUServer.Host, [ref]$parsedIP)) {
        Write-Log -Level INFO -Message "WSUS server is configured as an IP address"
    }
    else {
        try {
            $dnsCheck = Resolve-DnsName -Name $WUServer.Host -ErrorAction Stop
            Write-Log -Level DEBUG -Message "DNS resolution succeeded"
            Write-Log -Level DEBUG -Message "DNS resolution result: $($dnsCheck | Out-String)"
        }
        catch {
            Exit-WithError -EventId 1004 -Message "Unable to resolve DNS name for WSUS server: $($WUServer.Host). $($_.Exception.Message)"
        }
    }

    # Test network connectivity
    Write-Log -Level DEBUG -Message "Testing network connections"
    $pingCheck = Test-Connection -ComputerName $WUServer.Host -Quiet -ErrorAction SilentlyContinue
    $portCheck = Test-NetConnection -ComputerName $WUServer.Host -Port $WUServer.Port -InformationLevel Quiet -ErrorAction SilentlyContinue
    Write-Log -Level DEBUG -Message "pingCheck=$pingCheck; portCheck=$portCheck"

    if (-not $portCheck) {
        Exit-WithError -EventId 1005 -Message "Unable to reach WSUS server on port $($WUServer.Port)."
    }
    if (-not $pingCheck) {
        Write-Log -Level WARN -Message "ICMP ping to WSUS server failed, this may be normal if ICMP is blocked by firewall policy."
    }

        # Check IIS certificate is trusted
        $certTrustResult = [PSCustomObject]@{
            IsTrusted   = $true
            Subject     = $null
            Issuer      = $null
            Thumbprint  = $null
            NotAfter    = $null
            ChainStatus = @()
        }

    if ($WUServer.Scheme -eq 'https') {
        Write-Log -Level DEBUG -Message "Checking for certificate trust"
        $tcpClient = $null
        $sslStream = $null
        $Script:capturedCert = $null

            try {
                $tcpClient = [System.Net.Sockets.TcpClient]::new()
                $tcpClient.Connect($WUServer.Host, $WUServer.Port)

                $validationCallback = {
                    param($senderObj, $certificate, $chain, $sslPolicyErrors)
                    $script:capturedCert = $certificate
                    return $true
                }

                $sslStream = [System.Net.Security.SslStream]::new(
                    $tcpClient.GetStream(),
                    $false,
                    $validationCallback
                )

                $sslStream.AuthenticateAsClient($WUServer.Host)

                if (-not $script:capturedCert) {
                    throw "No certificate was presented by $($WUServer.Host):$($WUServer.Port)."
                }

                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($script:capturedCert)

                $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $chain.ChainPolicy.RevocationMode = 'NoCheck'
                $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

                $isValid = $chain.Build($cert)

            $certTrustResult = [PSCustomObject]@{
                IsTrusted   = $isValid
                Subject     = $cert.Subject
                Issuer      = $cert.Issuer
                Thumbprint  = $cert.Thumbprint
                NotAfter    = $cert.NotAfter
                ChainStatus = $chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }
            }
        }
        catch {
            $certTrustResult = [PSCustomObject]@{
                IsTrusted   = $false
                Subject     = $null
                Issuer      = $null
                Thumbprint  = $null
                NotAfter    = $null
                ChainStatus = @("Connection or handshake failed: $($_.Exception.Message)")
            }
        }
        finally {
            if ($sslStream) { $sslStream.Dispose() }
            if ($tcpClient) { $tcpClient.Dispose() }
        }
    }
    else {
        Write-Log -Level DEBUG -Message "WUServer $WUServer is not using HTTPS, skipping certificate trust check."
    }

    if ($certTrustResult.IsTrusted) {
        Write-Log -Level DEBUG -Message "WSUS server certificate trust check passed (or not applicable)."
    }
    else {
        Write-Log -Level ERROR -Message "WSUS server certificate is not trusted. Issuer: $($certTrustResult.Issuer). Detail: $($certTrustResult.ChainStatus -join ' | ')"
        Send-LogEvent -EventId 1006 -EntryType Warning -Message "WSUS server certificate is not trusted. Issuer: $($certTrustResult.Issuer)"
    }

    # Check for pending reboot
    Write-Log -Level DEBUG -Message "Testing if machine is in pending reboot state"
    $rebootPending = $false
    $rebootReasons = @()

        if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $rebootPending = $true
            $rebootReasons += "Component Based Servicing"
        }

        if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $rebootPending = $true
            $rebootReasons += "Windows Update"
        }

        $pfro = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pfro) {
            $rebootPending = $true
            $rebootReasons += "Pending File Rename Operations"
        }

        $activeName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue).ComputerName
        $pendingName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue).ComputerName
        if ($activeName -and $pendingName -and $activeName -ne $pendingName) {
            $rebootPending = $true
            $rebootReasons += "Pending computer rename"
        }

        if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "JoinDomain" -ErrorAction SilentlyContinue) {
            $rebootPending = $true
            $rebootReasons += "Pending domain join"
        }
        if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Name "AvoidSpnSet" -ErrorAction SilentlyContinue) {
            $rebootPending = $true
            $rebootReasons += "Pending domain rename"
        }

        $ccmClientSDK = Get-CimInstance -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_ClientUtilities -ErrorAction SilentlyContinue
        if ($ccmClientSDK) {
            $ccmResult = Invoke-CimMethod -Namespace "ROOT\ccm\ClientSDK" -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction SilentlyContinue
            if ($ccmResult -and ($ccmResult.RebootPending -or $ccmResult.IsHardRebootPending)) {
                $rebootPending = $true
                $rebootReasons += "SCCM client"
            }
        }

    if ($rebootPending) {
        Write-Log -Level WARN -Message "Reboot pending: $($rebootReasons -join ', ')"
    }
    else {
        Write-Log -Level DEBUG -Message "No reboot pending."
    }

    # Check for available space on system drive
    Write-Log -Level DEBUG -Message "Checking available space on system drive"
    $systemDrive = $env:SystemDrive.TrimEnd(':')
    $totalSpaceGB = $null
    $freeSpaceGB = $null

    try {
        $diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive`:'" -ErrorAction Stop
        $totalSpaceGB = [math]::Round($diskInfo.Size / 1GB, 2)
        $freeSpaceGB = [math]::Round($diskInfo.FreeSpace / 1GB, 2)
        Write-Log -Level DEBUG -Message "Raw disk info: Size=$($diskInfo.Size) FreeSpace=$($diskInfo.FreeSpace)"

        if ($freeSpaceGB -lt $Script:minimumRequiredGB) {
            Write-Log -Level WARN -Message "Low disk space on $systemDrive`: $freeSpaceGB GB free out of $totalSpaceGB GB. Minimum recommended: $Script:minimumRequiredGB GB."
        }
        else {
            Write-Log -Level INFO -Message "$systemDrive`: $freeSpaceGB GB free out of $totalSpaceGB GB."
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to query disk space for $systemDrive`: $($_.Exception.Message)"
    }

        # Service state
        $requiredServices = @(
            "wuauserv",
            "bits",
            "cryptsvc"
        )

    Write-Log -Level DEBUG -Message "Ensuring required services are not disabled"
    foreach ($service in $requiredServices) {
        $svc = Get-Service -Name $service
        Write-Log -Level DEBUG -Message "Service '$service': StartType=$($svc.StartType), Status=$($svc.Status)"

        $Script:serviceStates += [PSCustomObject]@{
            Service   = $service
            StartType = $svc.StartType
            Status    = $svc.Status
        }

        if ($svc.StartType -eq "Disabled") {
            if ($AutomaticallyRemediate) {
                if ($PSCmdlet.ShouldProcess($service, 'Set service startup type to Manual')) {
                    try {
                        Set-Service -Name $service -StartupType Manual -ErrorAction Stop
                        Write-Log -Level WARN -Message "Service '$service' was Disabled, set to Manual."
                        $Script:actionsTaken += "Set service '$service' startup type from Disabled to Manual."
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to change startup type for '$service': $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Log -Level WARN -Message "Service '$service' is Disabled. Run with -AutomaticallyRemediate to fix automatically."
            }
        }
    }

    $wuauservStatus = (Get-Service -Name "wuauserv").Status
    if ($wuauservStatus -ne "Running") {
        if ($AutomaticallyRemediate) {
            if ($PSCmdlet.ShouldProcess("wuauserv", 'Start service')) {
                try {
                    Start-Service -Name "wuauserv" -ErrorAction Stop
                    Write-Log -Level WARN -Message "wuauserv was not running - service started"
                    $Script:actionsTaken += "Started wuauserv service (was not running)."
                }
                catch {
                    Write-Log -Level ERROR -Message "wuauserv was not running - unable to start service: $($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Log -Level WARN -Message "wuauserv is not running. Run with -AutomaticallyRemediate to start it automatically."
        }
    }
    else {
        Write-Log -Level DEBUG -Message "wuauserv is already running."
    }

        ########## Sync Attempt Logic ##########
        function Invoke-SyncAttempt {
            <#
            .SYNOPSIS
                Attempts to trigger a Windows Update synchronisation via all available mechanisms.
            .DESCRIPTION
                Triggers detection/sync via the Windows Update Agent COM API, UsoClient,
                and legacy wuauclt (in that order, each independently wrapped so one
                failing doesn't prevent the others from running), waits, then checks
                whether LastSuccessTime indicates a genuinely recent successful
                detection.
            .OUTPUTS
                System.Boolean. $true if a successful detection was recorded within
                the last 5 minutes, otherwise $false.
            .EXAMPLE
                Invoke-SyncAttempt

                Triggers a synchronisation attempt and returns whether it succeeded.
            #>
            [CmdletBinding(SupportsShouldProcess)]
            param()

        if ($PSCmdlet.ShouldProcess('Windows Update', 'Trigger synchronisation attempt')) {
            if ($autoUpdate) {
                try {
                    $autoUpdate.DetectNow()
                    Write-Log -Level DEBUG -Message "COM API DetectNow triggered."
                }
                catch {
                    Write-Log -Level WARN -Message "COM API DetectNow failed: $($_.Exception.Message)"
                }
            }
            try {
                $usoResult = & "$env:SystemRoot\System32\UsoClient.exe" ScanInstallWait 2>&1
                Write-Log -Level DEBUG -Message "UsoClient ScanInstallWait output: $($usoResult -join ' ')"
            }
            catch {
                Write-Log -Level WARN -Message "UsoClient ScanInstallWait failed: $($_.Exception.Message)"
            }
            try {
                & "$env:SystemRoot\System32\wuauclt.exe" /detectnow /reportnow
                Write-Log -Level DEBUG -Message "wuauclt /detectnow /reportnow invoked."
            }
            catch {
                Write-Log -Level WARN -Message "wuauclt failed: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds 60
            $lastSuccess = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -Name "LastSuccessTime" -ErrorAction SilentlyContinue).LastSuccessTime
            Write-Log -Level DEBUG -Message "LastSuccessTime read as: $lastSuccess"
            return [bool]($lastSuccess -and ((Get-Date) - [DateTime]$lastSuccess).TotalMinutes -le 5)
        }

            return $false
        }

        ########## Attempt Synchronisation ##########
        [int]$syncs = 0
        $syncSucceeded = $false

    try {
        $autoUpdate = New-Object -ComObject "Microsoft.Update.AutoUpdate" -ErrorAction Stop
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to create Microsoft.Update.AutoUpdate COM object: $($_.Exception.Message)"
    }

    do {
        Write-Log -Level DEBUG -Message "Starting sync - attempt $($syncs + 1)"
        $syncSucceeded = Invoke-SyncAttempt
        $syncs += 1
        Write-Log -Level DEBUG -Message "Sync $syncs finished. Success: $syncSucceeded"
    }
    until ($syncSucceeded -or $syncs -ge $Script:syncAttempts)

    if ($syncSucceeded) {
        Write-Log -Level INFO -Message "Sync succeeded after $syncs attempt(s)."
    }
    else {
        Write-Log -Level ERROR -Message "Sync did not succeed after $syncs attempt(s)."
        Send-LogEvent -EventId 1007 -EntryType Error -Message "WSUS sync failed after $syncs attempt(s)."
    }

    ########## Identify Errors ##########
    Write-Log -Level DEBUG -Message "Reviewing update history for errors since $Script:startTime"

    try {
        $updateSession = New-Object -ComObject "Microsoft.Update.Session" -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        Write-Log -Level DEBUG -Message "Total update history entries on this machine: $historyCount"

            if ($historyCount -gt 0) {
                $history = $updateSearcher.QueryHistory(0, $historyCount)

            $Script:updateErrors = $history | Where-Object {
                $_.Date -ge $Script:startTime -and $_.ResultCode -in @(3, 4, 5)
            } | ForEach-Object {
                [PSCustomObject]@{
                    Title      = $_.Title
                    Date       = $_.Date
                    Operation  = switch ($_.Operation) { 1 { "Installation" } 2 { "Uninstallation" } default { "Unknown" } }
                    ResultCode = switch ($_.ResultCode) { 3 { "SucceededWithErrors" } 4 { "Failed" } 5 { "Aborted" } default { "Unknown" } }
                    HResult    = '0x{0:X8}' -f $_.HResult
                }
            }
        }
        else {
            Write-Log -Level DEBUG -Message "No update history entries found on this machine."
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to query update history: $($_.Exception.Message)"
    }

    if ($Script:updateErrors.Count -gt 0) {
        foreach ($err in $Script:updateErrors) {
            Write-Log -Level ERROR -Message "Update error: '$($err.Title)' - $($err.Operation) $($err.ResultCode) ($($err.HResult)) at $($err.Date)"
            Send-LogEvent -EventId 1008 -EntryType Error -Message "Update error: '$($err.Title)' - $($err.ResultCode) ($($err.HResult))"
        }
    }
    else {
        Write-Log -Level INFO -Message "No update install/uninstall errors found since script start ($Script:startTime)."
    }

    ########## Attempt Remediations ##########
    Write-Log -Level DEBUG -Message "Beginning remediation phase (AutomaticallyRemediate=$($AutomaticallyRemediate.IsPresent))"

        # Repair actions - called by multiple repair functions

        function Invoke-SFCScanOnce {
            <#
            .SYNOPSIS
                Runs sfc /scannow once per script execution.
            .DESCRIPTION
                Runs the System File Checker to repair corrupted system files, but only
                once per session, tracked via $Script:sfcAlreadyRun, since this is a
                genuinely expensive operation that multiple Repair-<code> functions may
                otherwise trigger redundantly if the same underlying fix applies to
                several detected error codes.
            .OUTPUTS
                None. Writes sfc's output to the log file as a side effect.
            .EXAMPLE
                Invoke-SFCScanOnce

                Runs sfc /scannow if it hasn't already run this session.
            #>
            [CmdletBinding(SupportsShouldProcess)]
            param()

        if ($Script:sfcAlreadyRun) {
            Write-Log -Level DEBUG -Message "sfc /scannow already run this session, skipping."
            return
        }

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run sfc /scannow')) {
            Write-Log -Level DEBUG -Message "Running sfc /scannow."
            $sfcOutput = sfc /scannow 2>&1
            Write-Log -Level DEBUG -Message "sfc /scannow output: $($sfcOutput -join ' ')"
            $Script:sfcAlreadyRun = $true
            $Script:actionsTaken += "Ran sfc /scannow."
        }
    }

        function Invoke-DISMRestoreHealthOnce {
            <#
            .SYNOPSIS
                Runs DISM /Online /Cleanup-Image /RestoreHealth once per script execution.
            .DESCRIPTION
                Runs DISM's component store repair, but only once per session, tracked
                via $Script:dismAlreadyRun, since this is a genuinely expensive
                operation that multiple Repair-<code> functions may otherwise trigger
                redundantly if the same underlying fix applies to several detected
                error codes.
            .OUTPUTS
                None. Writes DISM's output to the log file as a side effect.
            .EXAMPLE
                Invoke-DISMRestoreHealthOnce

                Runs DISM /Online /Cleanup-Image /RestoreHealth if it hasn't already
                run this session.
            #>
            [CmdletBinding(SupportsShouldProcess)]
            param()

        if ($Script:dismAlreadyRun) {
            Write-Log -Level DEBUG -Message "DISM /RestoreHealth already run this session, skipping."
            return
        }

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Run DISM /Online /Cleanup-Image /RestoreHealth')) {
            Write-Log -Level DEBUG -Message "Running DISM /Online /Cleanup-Image /RestoreHealth."
            $dismOutput = DISM /Online /Cleanup-Image /RestoreHealth 2>&1
            Write-Log -Level DEBUG -Message "DISM output: $($dismOutput -join ' ')"
            $Script:dismAlreadyRun = $true
            $Script:actionsTaken += "Ran DISM /Online /Cleanup-Image /RestoreHealth."
        }
    }

        function Invoke-ResetFolderCache {
            <#
            .SYNOPSIS
                Resets the SoftwareDistribution and catroot2 folders, once per script execution.
            .DESCRIPTION
                Stops wuauserv, bits, and cryptsvc, renames SoftwareDistribution and
                catroot2 to .old backups (clearing any existing backup from a previous
                run first), then restarts the services regardless of whether the
                rename succeeded, via a finally block, so a failed reset never leaves
                Windows Update services stopped. Only runs once per session, tracked
                via $Script:sdFolderResetAlreadyRun.
            .OUTPUTS
                None. Renames folders on disk and logs the outcome of each step.
            .EXAMPLE
                Invoke-ResetFolderCache

                Resets the SoftwareDistribution and catroot2 folders if this hasn't
                already run this session.
            #>
            [CmdletBinding(SupportsShouldProcess)]
            param()

        if ($Script:sdFolderResetAlreadyRun) {
            Write-Log -Level DEBUG -Message "SoftwareDistribution/catroot2 reset already run this session, skipping."
            return
        }

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Reset SoftwareDistribution and catroot2 folders')) {
            Write-Log -Level INFO -Message "Resetting SoftwareDistribution and catroot2 folders."
            $sdServices = @("wuauserv", "bits", "cryptsvc")
            $foldersToReset = @(
                @{ Path = "$env:SystemRoot\SoftwareDistribution"; BackupName = "SoftwareDistribution.old" },
                @{ Path = "$env:SystemRoot\System32\catroot2"; BackupName = "catroot2.old" }
            )
            try {
                foreach ($service in $sdServices) {
                    try {
                        Stop-Service -Name $service -Force -ErrorAction Stop
                        Write-Log -Level DEBUG -Message "Stopped service '$service'."
                    }
                    catch {
                        Write-Log -Level WARN -Message "Failed to stop service '$service': $($_.Exception.Message)"
                    }
                }
                foreach ($folder in $foldersToReset) {
                    $backupPath = Join-Path -Path (Split-Path -Path $folder.Path -Parent) -ChildPath $folder.BackupName
                    if (Test-Path -Path $backupPath) {
                        Write-Log -Level DEBUG -Message "Removing existing backup at '$backupPath' from a previous run."
                        Remove-Item -Path $backupPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    if (Test-Path -Path $folder.Path) {
                        try {
                            Rename-Item -Path $folder.Path -NewName $folder.BackupName -ErrorAction Stop
                            Write-Log -Level INFO -Message "Renamed '$($folder.Path)' to '$($folder.BackupName)'."
                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to rename '$($folder.Path)': $($_.Exception.Message)"
                        }
                    }
                    else {
                        Write-Log -Level WARN -Message "Folder not found at '$($folder.Path)', nothing to rename."
                    }
                }
            }
            finally {
                foreach ($service in $sdServices) {
                    try {
                        Start-Service -Name $service -ErrorAction Stop
                        Write-Log -Level DEBUG -Message "Started service '$service'."
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Failed to restart service '$service': $($_.Exception.Message). This service may need manual attention."
                        Send-LogEvent -EventId 1015 -EntryType Error -Message "Failed to restart service '$service' after remediation. Manual attention required."
                    }
                }
            }
            $Script:sdFolderResetAlreadyRun = $true
            $Script:actionsTaken += "Reset SoftwareDistribution and catroot2 folders."
        }
    }

        function Invoke-BitsQueueReset {
            <#
            .SYNOPSIS
                Removes stuck or errored jobs from the BITS transfer queue, once per script execution.
            .DESCRIPTION
                Queries all BITS transfer jobs (all users, requires elevation) and
                removes any in an Error, TransientError, or Suspended state. If the
                query itself fails (the API doesn't respond), escalates to the more
                invasive Invoke-BitsQueueFileReset. Only runs once per session, tracked
                via $Script:bitsQueueResetAlreadyRun.
            .OUTPUTS
                None. Removes problem BITS jobs and logs the outcome.
            .EXAMPLE
                Invoke-BitsQueueReset

                Checks the BITS transfer queue and removes any problem jobs, if this
                hasn't already run this session.
            #>
            [CmdletBinding(SupportsShouldProcess)]
            param()

        if ($Script:bitsQueueResetAlreadyRun) {
            Write-Log -Level DEBUG -Message "BITS queue reset already run this session, skipping."
            return
        }

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Check and reset BITS transfer queue')) {
            Write-Log -Level INFO -Message "Checking BITS transfer queue for stuck or errored jobs."
            try {
                $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction Stop
                $problemJobs = $bitsJobs | Where-Object { $_.JobState -in @('Error', 'TransientError', 'Suspended') }
                if ($problemJobs) {
                    foreach ($job in $problemJobs) {
                        Write-Log -Level WARN -Message "Removing BITS job '$($job.DisplayName)' (State: $($job.JobState))."
                        try {
                            Remove-BitsTransfer -BitsJob $job -ErrorAction Stop
                            $Script:actionsTaken += "Removed BITS job '$($job.DisplayName)' (State: $($job.JobState))."
                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to remove BITS job '$($job.DisplayName)': $($_.Exception.Message)"
                        }
                    }
                }
                else {
                    Write-Log -Level DEBUG -Message "No problem BITS jobs found in queue."
                }
            }
            catch {
                Write-Log -Level WARN -Message "Failed to query BITS transfer queue via API: $($_.Exception.Message). Escalating to file-level reset."
                Invoke-BitsQueueFileReset
            }
            $Script:bitsQueueResetAlreadyRun = $true
        }
    }

        function Invoke-BitsQueueFileReset {
            <#
            .SYNOPSIS
                Performs a file-level reset of the BITS transfer queue, once per script execution.
            .DESCRIPTION
                More invasive fallback for when the API-based approach
                (Invoke-BitsQueueReset) can't run at all. Stops the BITS service,
                deletes the queue database files directly, and restarts the service
                regardless of whether the deletion succeeded, via a finally block, so
                a failed reset never leaves BITS stopped. Only runs once per session,
                tracked via $Script:bitsQueueFileResetAlreadyRun.
            .OUTPUTS
                None. Deletes BITS queue files on disk and logs the outcome.
            .EXAMPLE
                Invoke-BitsQueueFileReset

                Performs a file-level BITS queue reset if this hasn't already run
                this session.
            #>
            [CmdletBinding(SupportsShouldProcess)]
            param()

        if ($Script:bitsQueueFileResetAlreadyRun) {
            Write-Log -Level DEBUG -Message "BITS queue file reset already run this session, skipping."
            return
        }

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Perform file-level BITS queue reset')) {
            Write-Log -Level DEBUG -Message "Performing file-level BITS queue reset."
            $downloaderPath = "$env:ProgramData\Microsoft\Network\Downloader"
            try {
                Stop-Service -Name bits -Force -ErrorAction Stop
                Get-ChildItem -Path $downloaderPath -Filter "qmgr*" -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Log -Level WARN -Message "Removing BITS queue file: $($_.Name)"
                    Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Log -Level ERROR -Message "File-level BITS queue reset failed: $($_.Exception.Message)"
            }
            finally {
                try {
                    Start-Service -Name bits -ErrorAction Stop
                }
                catch {
                    Write-Log -Level ERROR -Message "Failed to restart BITS service: $($_.Exception.Message). This service may need manual attention."
                    Send-LogEvent -EventId 1015 -EntryType Error -Message "Failed to restart BITS service after remediation. Manual attention required."
                }
            }
            $Script:bitsQueueFileResetAlreadyRun = $true
            $Script:actionsTaken += "Performed file-level BITS queue reset."
        }
    }

        # Error code repairs

        function Repair-8000FFFF {
            <#
            .SYNOPSIS
                Remediation for error code 0x8000FFFF (generic unexpected error).
            .DESCRIPTION
                Attempts a general component repair by running DISM /RestoreHealth
                followed by sfc /scannow, since 0x8000FFFF (E_UNEXPECTED) is too
                generic to diagnose more specifically. Delegates to the shared,
                idempotent Invoke-DISMRestoreHealthOnce and Invoke-SFCScanOnce
                functions, which handle their own ShouldProcess gating.
            .OUTPUTS
                None. Logs the remediation attempt and delegates to shared repair actions.
            .EXAMPLE
                Repair-8000FFFF

                Attempts a DISM and SFC repair for a generic unexpected error.
            #>
            [CmdletBinding()]
            param()

        Write-Log -Level INFO -Message "Repair-8000FFFF: generic unexpected error, attempting component repair."
        Send-LogEvent -EventId 1009 -EntryType Warning -Message "Repair-8000FFFF invoked: generic unexpected error."
        Invoke-DISMRestoreHealthOnce
        Invoke-SFCScanOnce
    }

        function Repair-800F0831 {
            <#
            .SYNOPSIS
                Remediation for error code 0x800F0831 (component store corruption).
            .DESCRIPTION
                Attempts a component store repair by running DISM /RestoreHealth
                followed by sfc /scannow, per CBS.log indicating WinSxS corruption.
                Delegates to the shared, idempotent Invoke-DISMRestoreHealthOnce and
                Invoke-SFCScanOnce functions, which handle their own ShouldProcess
                gating.
            .OUTPUTS
                None. Logs the remediation attempt and delegates to shared repair actions.
            .EXAMPLE
                Repair-800F0831

                Attempts a DISM and SFC repair for detected component store corruption.
            #>
            [CmdletBinding()]
            param()

        Write-Log -Level INFO -Message "Repair-800F0831: component store corruption detected, attempting repair."
        Send-LogEvent -EventId 1010 -EntryType Warning -Message "Repair-800F0831 invoked: component store corruption."
        Invoke-DISMRestoreHealthOnce
        Invoke-SFCScanOnce
    }

        function Repair-80244022 {
            <#
            .SYNOPSIS
                Remediation for error code 0x80244022 (WSUS server reported overloaded/unavailable).
            .DESCRIPTION
                Resets local caches that can help when the WSUS server itself reports
                being temporarily overloaded (WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL),
                per Microsoft's own guidance for this status code. Delegates to the
                shared, idempotent Invoke-ResetFolderCache and Invoke-BitsQueueReset
                functions, which handle their own ShouldProcess gating.
            .OUTPUTS
                None. Logs the remediation attempt and delegates to shared repair actions.
            .EXAMPLE
                Repair-80244022

                Resets the SoftwareDistribution/catroot2 folders and BITS queue in
                response to a WSUS server overloaded/unavailable error.
            #>
            [CmdletBinding()]
            param()

        Write-Log -Level INFO -Message "Repair-80244022: WSUS server reported overloaded/unavailable, resetting local cache."
        Send-LogEvent -EventId 1011 -EntryType Warning -Message "Repair-80244022 invoked: WSUS server overloaded/unavailable."
        Invoke-ResetFolderCache
        Invoke-BitsQueueReset
    }

        function Repair-80072EE2 {
            <#
            .SYNOPSIS
                Remediation for error code 0x80072EE2 (timeout reaching WSUS server).
            .DESCRIPTION
                This error typically indicates a network, firewall, or WSUS server
                load issue rather than something locally repairable, so no component
                repair is attempted. Clears the local DNS client cache in case of
                stale resolution, then re-checks port connectivity and logs the
                result for investigation.
            .OUTPUTS
                None. Clears the DNS client cache and logs the outcome.
            .EXAMPLE
                Repair-80072EE2

                Clears the DNS cache and re-checks connectivity to the configured
                WSUS server following a timeout error.
            #>
            [CmdletBinding(SupportsShouldProcess)]
            param()

        Write-Log -Level WARN -Message "Repair-80072EE2: timeout reaching WSUS server. This is typically network/firewall/server-load related, not locally repairable."

        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Clear DNS client cache')) {
            Clear-DnsClientCache
            $Script:actionsTaken += "Cleared DNS client cache (in response to 0x80072EE2)."
        }

        $retryPortCheck = Test-NetConnection -ComputerName $WUServer.Host -Port $WUServer.Port -InformationLevel Quiet -ErrorAction SilentlyContinue
        Write-Log -Level INFO -Message "Retry port check result: $retryPortCheck"
        Send-LogEvent -EventId 1012 -EntryType Warning -Message "Timeout reaching WSUS server, may require network/firewall investigation."
    }

        function Repair-80072EE5 {
            <#
            .SYNOPSIS
                Remediation for error code 0x80072EE5 (malformed WSUS URL).
            .DESCRIPTION
                This error typically indicates a trailing slash or other malformation
                in the WUServer registry value, which is a GPO-managed policy setting.
                Deliberately does not modify the value automatically, since doing so
                would override a deliberate administrative decision, logs the issue
                with guidance instead.
            .OUTPUTS
                None. Logs the issue for manual policy correction.
            .EXAMPLE
                Repair-80072EE5

                Logs guidance for correcting a malformed WSUS server URL in Group
                Policy.
            #>
            [CmdletBinding()]
            param()

        Write-Log -Level ERROR -Message "Repair-80072EE5: WUServer URL appears malformed (check for a trailing slash). Current value: $($WUServer.OriginalString). This is a policy-managed setting and will not be modified automatically."
        Send-LogEvent -EventId 1013 -EntryType Error -Message "WSUS server URL is malformed, requires GPO/policy correction."
    }

        function Repair-8024002E {
            <#
            .SYNOPSIS
                Remediation for error code 0x8024002E (Windows Update disabled by policy).
            .DESCRIPTION
                This error indicates Windows Update access has been intentionally
                disabled via Group Policy. Deliberately does not override this
                automatically, since doing so would reverse a deliberate
                administrative decision, logs the issue with guidance instead.
            .OUTPUTS
                None. Logs the issue for manual policy review.
            .EXAMPLE
                Repair-8024002E

                Logs guidance noting that Windows Update access is disabled by policy
                and will not be overridden.
            #>
            [CmdletBinding()]
            param()

        Write-Log -Level ERROR -Message "Repair-8024002E: Windows Update access is disabled by policy on this machine. This will not be overridden automatically."
        Send-LogEvent -EventId 1014 -EntryType Error -Message "Windows Update access disabled by policy on $env:COMPUTERNAME."
    }

    if ($AutomaticallyRemediate) {
        $uniqueErrorCodes = $Script:updateErrors.HResult | Select-Object -Unique
        Write-Log -Level DEBUG -Message "Unique error codes to remediate: $($uniqueErrorCodes -join ', ')"

            foreach ($hexErr in $uniqueErrorCodes) {
                $codeSuffix = $hexErr -replace '^0x', ''
                $repairFunctionName = "Repair-$codeSuffix"

            if (Get-Command -Name $repairFunctionName -ErrorAction SilentlyContinue) {
                try {
                    Write-Log -Level INFO -Message "Calling $repairFunctionName for error code $hexErr."
                    & $repairFunctionName
                    $Script:actionsTaken += "Invoked $repairFunctionName for error code $hexErr."
                }
                catch {
                    Write-Log -Level ERROR -Message "$repairFunctionName threw an error: $($_.Exception.Message)"
                }
            }
            else {
                Write-Log -Level WARN -Message "No remediation function exists for error code $hexErr."
            }
        }
    }

    ########## Reattempt Synchronisation ##########
    if ($AutomaticallyRemediate -and $Script:updateErrors.Count -gt 0 -and -not $syncSucceeded) {
        Write-Log -Level DEBUG -Message "Starting sync attempt after remediations"
        $syncSucceeded = Invoke-SyncAttempt
        $syncs += 1
        Write-Log -Level DEBUG -Message "Sync $syncs finished. Success: $syncSucceeded"

        if ($syncSucceeded) {
            Write-Log -Level INFO -Message "Sync succeeded after remediation (attempt $syncs)."
        }
        else {
            Write-Log -Level ERROR -Message "Sync did not succeed after remediation (attempt $syncs)."
            Send-LogEvent -EventId 1016 -EntryType Error -Message "WSUS sync failed after $syncs attempt(s), including post-remediation retry."
        }
    }

    ##################################################
    # Report generation
    ##################################################

    function Export-AuditCsv {
        <#
        .SYNOPSIS
            Writes the run summary, update errors, and actions taken to CSV files.
        #>
        $summaryPath = Join-Path $ReportPath "$($Script:reportBaseName)_Summary.csv"
        $summary = [PSCustomObject]@{
            RunTime            = $Script:startTime
            WUServer           = $WUServer
            WUStatusServer     = $WUStatusServer
            CertificateTrusted = $certTrustResult.IsTrusted
            RebootPending      = $rebootPending
            RebootReasons      = ($rebootReasons -join '; ')
            FreeSpaceGB        = $freeSpaceGB
            TotalSpaceGB       = $totalSpaceGB
            SyncSucceeded      = $syncSucceeded
            SyncAttempts       = $syncs
            UpdateErrorCount   = $Script:updateErrors.Count
            ActionsTakenCount  = $Script:actionsTaken.Count
        }
        $summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
        Write-Log -Level INFO -Message "Wrote CSV: $summaryPath"

        $errorsPath = Join-Path $ReportPath "$($Script:reportBaseName)_UpdateErrors.csv"
        if ($Script:updateErrors.Count -gt 0) {
            $Script:updateErrors | Export-Csv -Path $errorsPath -NoTypeInformation -Encoding UTF8
        }
        else {
            "No findings" | Out-File -FilePath $errorsPath -Encoding UTF8
        }
        Write-Log -Level INFO -Message "Wrote CSV: $errorsPath"

        $actionsPath = Join-Path $ReportPath "$($Script:reportBaseName)_ActionsTaken.csv"
        if ($Script:actionsTaken.Count -gt 0) {
            $Script:actionsTaken | ForEach-Object { [PSCustomObject]@{ Action = $_ } } | Export-Csv -Path $actionsPath -NoTypeInformation -Encoding UTF8
        }
        else {
            "No findings" | Out-File -FilePath $actionsPath -Encoding UTF8
        }
        Write-Log -Level INFO -Message "Wrote CSV: $actionsPath"
    }

    function Build-HtmlKeyValueTable {
        <#
        .SYNOPSIS
            Builds an HTML key/value table from a hashtable, in insertion order.
        #>
        param(
            [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Data
        )
        $rows = foreach ($key in $Data.Keys) {
            "<tr><td><strong>$key</strong></td><td>$($Data[$key])</td></tr>"
        }
        return "<table>$($rows -join '')</table>"
    }

    function Build-HtmlDataTable {
        <#
        .SYNOPSIS
            Builds an HTML table from an array of PSCustomObjects, or a "no
            findings" message if the array is empty.
        #>
        param(
            [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][array]$Data,
            [string]$RowClass = "warn"
        )
        # A filtered pipeline with no results arrives as $null, so normalise first.
        $Data = @($Data | Where-Object { $null -ne $_ })
        if ($Data.Count -eq 0) {
            return "<p class='ok'>No findings.</p>"
        }
        $headers = $Data[0].PSObject.Properties.Name
        $headerRow = ($headers | ForEach-Object { "<th>$_</th>" }) -join ""
        $rows = foreach ($item in $Data) {
            $cells = ($headers | ForEach-Object { "<td>$($item.$_)</td>" }) -join ""
            "<tr class='$RowClass'>$cells</tr>"
        }
        return "<table><tr>$headerRow</tr>$($rows -join '')</table>"
    }

    function Export-AuditHtml {
        <#
        .SYNOPSIS
            Builds and writes the full HTML report.
        #>
        $style = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; color: #222; }
h1 { border-bottom: 2px solid #333; padding-bottom: 8px; }
h2 { margin-top: 30px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 10px; }
th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 13px; }
th { background-color: #333; color: #fff; }
tr.warn { background-color: #fff3cd; }
tr.risk { background-color: #f8d7da; }
p.ok { color: #2e7d32; font-weight: bold; }
.summary { background-color: #f5f5f5; border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; }
.summary span { display: inline-block; margin-right: 30px; font-weight: bold; }
.footnote { font-size: 12px; color: #666; margin-top: 40px; }
</style>
"@

        $summaryClass = if (-not $syncSucceeded -or $Script:updateErrors.Count -gt 0) { "risk" } else { "ok" }
        $summary = @"
<div class='summary'>
<span>Sync succeeded: $syncSucceeded ($syncs attempt(s))</span>
<span>Update errors: $($Script:updateErrors.Count)</span>
<span>Reboot pending: $rebootPending</span>
<span>Certificate trusted: $($certTrustResult.IsTrusted)</span>
<span>Actions taken: $($Script:actionsTaken.Count)</span>
</div>
"@

        $configData = [ordered]@{
            "WSUS Server"          = $WUServer
            "WSUS Status Server"   = $WUStatusServer
            "GPO changed WUServer" = ($initialWUServer -ne $WUServer)
        }
        $connectivityData = [ordered]@{
            "Ping reachable"       = $pingCheck
            "Port reachable"       = $portCheck
            "Certificate trusted"  = $certTrustResult.IsTrusted
            "Certificate issuer"   = $certTrustResult.Issuer
            "Certificate expiry"   = $certTrustResult.NotAfter
        }
        $healthData = [ordered]@{
            "Reboot pending"  = $rebootPending
            "Reboot reasons"  = ($rebootReasons -join ', ')
            "Free space (GB)" = $freeSpaceGB
            "Total space (GB)" = $totalSpaceGB
        }
        $syncData = [ordered]@{
            "Sync succeeded" = $syncSucceeded
            "Sync attempts"  = $syncs
        }

        $body = ""
        $body += "<h2>Configuration</h2>" + (Build-HtmlKeyValueTable -Data $configData)
        $body += "<h2>Connectivity &amp; Certificate</h2>" + (Build-HtmlKeyValueTable -Data $connectivityData)
        $body += "<h2>System Health</h2>" + (Build-HtmlKeyValueTable -Data $healthData)
        $body += "<h2>Service States</h2>" + (Build-HtmlDataTable -Data $Script:serviceStates -RowClass "warn")
        $body += "<h2>Synchronisation</h2>" + (Build-HtmlKeyValueTable -Data $syncData)
        $body += "<h2>Update Errors ($($Script:updateErrors.Count))</h2>" + (Build-HtmlDataTable -Data $Script:updateErrors -RowClass "risk")
        $actionsForTable = $Script:actionsTaken | ForEach-Object { [PSCustomObject]@{ Action = $_ } }
        $body += "<h2>Actions Taken ($($Script:actionsTaken.Count))</h2>" + (Build-HtmlDataTable -Data $actionsForTable -RowClass "warn")

        $footnote = @"
<p class='footnote'>
Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by WSUS-ClientSync.ps1 on $env:COMPUTERNAME.
</p>
"@

        $html = "<html><head><title>WSUS Client Sync Report</title>$style</head><body><h1>WSUS Client Sync Report - $env:COMPUTERNAME</h1>$summary$body$footnote</body></html>"

        $htmlPath = Join-Path $ReportPath "$($Script:reportBaseName).html"
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Log -Level INFO -Message "Wrote HTML report: $htmlPath"
    }

    Try {
        Export-AuditCsv
        Export-AuditHtml
    }
    Catch {
        Write-Log -Level ERROR -Message "Failed to write report: $($_.Exception.Message)"
    }

    Write-Log -Level INFO -Message "WSUS Client Sync script has completed"
    Send-LogEvent -EventId 1001 -EntryType Information -Message "WSUS Client Sync script has completed"

    Remove-ExpiredOutput -Folder $ReportPath -OlderThanDays $RetentionDays
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
