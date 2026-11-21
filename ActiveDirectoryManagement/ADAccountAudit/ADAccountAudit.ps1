<#
.SYNOPSIS
    Audits Active Directory for stale accounts, disabled-but-privileged accounts,
    accounts nearing password expiry, and empty security groups.

.DESCRIPTION
    Read-only reporting tool. Makes no changes to Active Directory.

    Produces four findings:
      1. Enabled accounts with no logon activity in more than -StaleDays days.
      2. Disabled accounts still holding membership (including nested/recursive)
         of one or more privileged groups.
      3. Enabled accounts whose password will expire within -PasswordExpiryWarningDays
         days (accounts with PasswordNeverExpires are excluded).
      4. Security groups with zero members. Distribution groups are excluded
         by default; pass -IncludeDistributionGroups to include them.

    Outputs a single HTML report (colour-coded, summary counts at the top) and
    a matching CSV export per run, plus an appended log file. Reports older than
    -RetentionDays are cleaned up automatically at the end of each run, and the
    log file rotates by size.

    Designed to run unattended via Scheduled Task: no prompts, exit code 0 on
    success, exit code 1 on any fatal error.

.PARAMETER StaleDays
    Number of days since last logon (via LastLogonTimestamp) after which an
    enabled account is flagged as stale. Default 90.
    Note: LastLogonTimestamp replicates across DCs with up to 14 days of lag
    by design, so treat this as "roughly this stale", not exact.

.PARAMETER PasswordExpiryWarningDays
    Number of days before password expiry to flag an account. Default 14.

.PARAMETER PrivilegedGroups
    Array of group names to check disabled-but-still-privileged membership
    against. Membership is checked recursively (nested groups included).
    Default: Domain Admins, Enterprise Admins, Schema Admins, Administrators.

.PARAMETER SearchBase
    Optional distinguished name to scope all searches to a specific OU.
    Defaults to the whole domain if not supplied.

.PARAMETER IncludeDistributionGroups
    Switch. Also reports empty distribution groups, not just security groups.

.PARAMETER OutputRoot
    Deprecated, kept so existing scheduled tasks keep working. When supplied, the log
    is written to <OutputRoot>\Logs\ADAccountAudit.log and reports to
    <OutputRoot>\Reports, unless -LogPath or -ReportPath is also supplied.

.PARAMETER LogPath
    Log file location. Defaults to
    C:\ProgramData\PickeringCloud\ADAccountAudit\Logs\ADAccountAudit.log. The file is
    appended to across runs and rotated at 10 MB.

.PARAMETER LoggingLevel
    Debug, Verbose, Info, Warn, Error, Critical or None (1 to 7, 0 also means None).
    Defaults to Info. -Debug and -Verbose raise it if this is not set.

.PARAMETER ReportPath
    Folder for the HTML and CSV reports. Defaults to
    C:\ProgramData\PickeringCloud\ADAccountAudit\Reports.

.PARAMETER RetentionDays
    Reports older than this many days are removed. Default 30. 0 disables cleanup.
    Only this tool's own reports are removed. -LogRetentionDays is accepted as an
    alias for compatibility with earlier versions.

.PARAMETER DisableUpdateCheck
    Skips the check for a newer version. No network request is made for this purpose.

.PARAMETER DisableTelemetry
    Stops anonymous usage telemetry being sent. The update check still runs unless
    -DisableUpdateCheck is also used. The PICKERINGCLOUD_NOTELEMETRY=1 and
    DO_NOT_TRACK=1 environment variables do the same.

.EXAMPLE
    .\ADAccountAudit.ps1

    Runs with all defaults: 90-day stale threshold, 14-day password expiry
    warning, default privileged group list, whole-domain scope, security
    groups only, 30-day report retention.

.EXAMPLE
    .\ADAccountAudit.ps1 -StaleDays 60 -PrivilegedGroups @("Domain Admins","Backup Operators") -IncludeDistributionGroups

    Runs with a 60-day stale threshold, a custom privileged group list, and
    includes empty distribution groups in the report.

.OUTPUTS
    None to the pipeline. Writes an HTML report and CSV exports to -ReportPath, and
    appends to the log file at -LogPath. Exits with code 0 on success, 1 on fatal
    error.

.NOTES
    Author: Bradley Pickering
    Version: 1.1.0
    Requires: ActiveDirectory PowerShell module (RSAT). The script will
    attempt to install this automatically if missing - see Install-RequiredModules.
    Read-only: performs no writes, disables, or membership changes against AD.

    Update check and telemetry: after the run, the script reads a static version
    file from pickering.cloud and tells you if a newer version exists. It never
    downloads or installs anything. Unless disabled, it also sends anonymous usage
    data (tool, version, OS, PowerShell version, timezone, run mode). No domain,
    user, group or host details are sent. See TELEMETRY.md in the repository root.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # ---- Script-specific parameters go here (each one ends with a comma) ----
    [int]$StaleDays = 90,
    [int]$PasswordExpiryWarningDays = 14,
    [string[]]$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"),
    [string]$SearchBase,
    [switch]$IncludeDistributionGroups,
    [string]$OutputRoot,

    # ---- Standard toolkit parameters (do not remove) ----
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
$ScriptName    = 'ADAccountAudit'
$ScriptVersion = '1.1.0'

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

# Deprecated -OutputRoot: keep the pre-1.1.0 layout for anyone still passing it.
if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
    if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path -Path $OutputRoot -ChildPath ('Logs\{0}.log' -f $ScriptName) }
    if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = Join-Path -Path $OutputRoot -ChildPath 'Reports' }
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
$Script:reportBaseName = '{0}_{1}' -f $ScriptName, $RunStamp

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
# Module bootstrap
##################################################

function Install-RequiredModules {
    <#
    .SYNOPSIS
        Ensures the ActiveDirectory module is available, installing it if not.
    .DESCRIPTION
        The ActiveDirectory module ships as part of RSAT, not the PowerShell
        Gallery, so it can't be pulled with Install-Module. This attempts the
        correct install path for the local OS (Add-WindowsCapability on
        Windows 10/11 client, Install-WindowsFeature on Windows Server), then
        imports the module. Requires an elevated session to succeed. Fails
        with a Critical log entry and the manual install command if automatic
        installation isn't possible, or if -WhatIf skips the install.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Log -Message "ActiveDirectory module already available." -Level INFO
        Import-Module ActiveDirectory -ErrorAction Stop
        return
    }

    Write-Log -Message "ActiveDirectory module not found. Attempting automatic install via RSAT." -Level WARN

    if (-not $PSCmdlet.ShouldProcess('RSAT Active Directory PowerShell tools', 'Install Windows capability or feature')) {
        Exit-WithError "The ActiveDirectory module is required and its installation was skipped (WhatIf)."
    }

    Try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.ProductType -eq 1) {
            # Windows client (10/11)
            Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop | Out-Null
        }
        else {
            # Windows Server
            Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop | Out-Null
        }
        Write-Log -Message "RSAT AD PowerShell tools installed successfully." -Level INFO
    }
    Catch {
        Exit-WithError "Automatic install of the ActiveDirectory module failed: $($_.Exception.Message). Install RSAT manually - 'Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' on Windows 10/11, or 'Install-WindowsFeature RSAT-AD-PowerShell' on Windows Server - then re-run this script."
    }

    Import-Module ActiveDirectory -ErrorAction Stop
}

##################################################
# Audit functions
##################################################

function Get-StaleAccounts {
    <#
    .SYNOPSIS
        Finds enabled accounts with no logon activity within the stale threshold.
    .DESCRIPTION
        Uses LastLogonTimestamp, converting the stored FileTime value to a
        DateTime. Accounts that have never logged on (null timestamp) are
        included, since "never logged on" is at least as notable as "stale".
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for stale accounts (no logon in $StaleDays+ days)..." -Level INFO

    $adParams = @{
        Filter     = "Enabled -eq 'True'"
        Properties = @("LastLogonTimestamp", "whenCreated", "DisplayName")
    }
    if ($SearchBase) { $adParams["SearchBase"] = $SearchBase }

    $users = Get-ADUser @adParams
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    $results = @()

    foreach ($user in $users) {
        $lastLogon = $null
        if ($user.LastLogonTimestamp) {
            $lastLogon = [DateTime]::FromFileTime($user.LastLogonTimestamp)
        }

        if ($null -eq $lastLogon -or $lastLogon -lt $cutoff) {
            $results += [PSCustomObject]@{
                SamAccountName = $user.SamAccountName
                DisplayName    = $user.DisplayName
                LastLogon      = if ($lastLogon) { $lastLogon.ToString("yyyy-MM-dd") } else { "Never" }
                Created        = $user.whenCreated.ToString("yyyy-MM-dd")
                DistinguishedName = $user.DistinguishedName
            }
        }
    }

    Write-Log -Message "Found $($results.Count) stale account(s)." -Level INFO
    return $results
}

function Get-DisabledPrivilegedAccounts {
    <#
    .SYNOPSIS
        Finds disabled accounts still holding privileged group membership.
    .DESCRIPTION
        Checks each group named in $PrivilegedGroups recursively, so nested
        group membership is caught, not just direct membership. Missing
        groups are logged as a WARN and skipped rather than failing the run.
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for disabled accounts in privileged groups..." -Level INFO

    $results = @()

    foreach ($groupName in $PrivilegedGroups) {
        Try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop |
                Where-Object { $_.objectClass -eq "user" }
        }
        Catch {
            Write-Log -Message "Could not enumerate group '$groupName': $($_.Exception.Message)" -Level WARN
            continue
        }

        foreach ($member in $members) {
            Try {
                $user = Get-ADUser -Identity $member.distinguishedName -Properties Enabled, DisplayName -ErrorAction Stop
            }
            Catch {
                Write-Log -Message "Could not resolve member $($member.distinguishedName): $($_.Exception.Message)" -Level WARN
                continue
            }

            if (-not $user.Enabled) {
                $results += [PSCustomObject]@{
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    PrivilegedGroup   = $groupName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }

    Write-Log -Message "Found $($results.Count) disabled-but-privileged account(s)." -Level INFO
    return $results
}

function Get-ExpiringPasswords {
    <#
    .SYNOPSIS
        Finds enabled accounts whose password expires within the warning window.
    .DESCRIPTION
        Uses the computed msDS-UserPasswordExpiryTimeComputed attribute, which
        correctly accounts for fine-grained password policies. Accounts with
        PasswordNeverExpires set are excluded.
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for passwords expiring within $PasswordExpiryWarningDays days..." -Level INFO

    $adParams = @{
        Filter     = "Enabled -eq 'True' -and PasswordNeverExpires -eq 'False'"
        Properties = @("DisplayName", "msDS-UserPasswordExpiryTimeComputed")
    }
    if ($SearchBase) { $adParams["SearchBase"] = $SearchBase }

    $users = Get-ADUser @adParams
    $warningCutoff = (Get-Date).AddDays($PasswordExpiryWarningDays)
    $results = @()

    foreach ($user in $users) {
        $expiryRaw = $user."msDS-UserPasswordExpiryTimeComputed"
        if (-not $expiryRaw -or $expiryRaw -eq 0 -or $expiryRaw -eq 9223372036854775807) {
            continue
        }

        $expiryDate = [DateTime]::FromFileTime($expiryRaw)

        if ($expiryDate -lt $warningCutoff) {
            $daysRemaining = [math]::Round(($expiryDate - (Get-Date)).TotalDays)
            $results += [PSCustomObject]@{
                SamAccountName    = $user.SamAccountName
                DisplayName       = $user.DisplayName
                ExpiryDate        = $expiryDate.ToString("yyyy-MM-dd")
                DaysRemaining     = $daysRemaining
                DistinguishedName = $user.DistinguishedName
            }
        }
    }

    Write-Log -Message "Found $($results.Count) account(s) with password expiring soon." -Level INFO
    return $results
}

function Get-EmptyGroups {
    <#
    .SYNOPSIS
        Finds security groups (and optionally distribution groups) with zero members.
    .DESCRIPTION
        Security groups are included by default since an empty security group
        can silently mean "nobody currently has this access" if referenced in
        an ACL, GPO, or application role. Distribution groups carry no access
        implications and are excluded by default to keep the report focused
        on actionable security findings; pass -IncludeDistributionGroups to
        include them anyway.
    .OUTPUTS
        Array of PSCustomObject.
    #>
    Write-Log -Message "Checking for empty groups..." -Level INFO

    $adParams = @{
        Filter     = "*"
        Properties = @("Members", "GroupCategory", "Description")
    }
    if ($SearchBase) { $adParams["SearchBase"] = $SearchBase }

    $groups = Get-ADGroup @adParams
    $results = @()

    foreach ($group in $groups) {
        if ($group.Members.Count -gt 0) { continue }
        if (-not $IncludeDistributionGroups -and $group.GroupCategory -eq "Distribution") { continue }

        $results += [PSCustomObject]@{
            GroupName         = $group.Name
            GroupCategory     = $group.GroupCategory
            Description       = $group.Description
            DistinguishedName = $group.DistinguishedName
        }
    }

    Write-Log -Message "Found $($results.Count) empty group(s)." -Level INFO
    return $results
}

##################################################
# Report generation
##################################################

function Export-AuditCsv {
    <#
    .SYNOPSIS
        Writes each finding set to its own CSV file for filtering in Excel.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$StaleAccounts,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$PrivilegedDisabled,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$ExpiringPasswords,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$EmptyGroups
    )

    $csvSets = @{
        "StaleAccounts"      = $StaleAccounts
        "DisabledPrivileged" = $PrivilegedDisabled
        "ExpiringPasswords"  = $ExpiringPasswords
        "EmptyGroups"        = $EmptyGroups
    }

    foreach ($name in $csvSets.Keys) {
        $path = Join-Path $ReportPath "$($Script:reportBaseName)_$name.csv"
        if ($csvSets[$name].Count -gt 0) {
            $csvSets[$name] | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        }
        else {
            "No findings" | Out-File -FilePath $path -Encoding UTF8
        }
        Write-Log -Message "Wrote CSV: $path" -Level INFO
    }
}

function Build-HtmlSection {
    <#
    .SYNOPSIS
        Builds one colour-coded HTML table section for the report.
    #>
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Data,
        [Parameter(Mandatory)][string]$RowClass
    )

    if ($Data.Count -eq 0) {
        return "<h2>$Title</h2><p class='ok'>No findings.</p>"
    }

    $headers = $Data[0].PSObject.Properties.Name
    $headerRow = ($headers | ForEach-Object { "<th>$_</th>" }) -join ""

    $rows = foreach ($item in $Data) {
        $cells = ($headers | ForEach-Object { "<td>$($item.$_)</td>" }) -join ""
        "<tr class='$RowClass'>$cells</tr>"
    }

    return "<h2>$Title ($($Data.Count))</h2><table><tr>$headerRow</tr>$($rows -join '')</table>"
}

function Export-AuditHtml {
    <#
    .SYNOPSIS
        Builds and writes the full HTML report.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$StaleAccounts,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$PrivilegedDisabled,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$ExpiringPasswords,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$EmptyGroups
    )

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

    $summary = @"
<div class='summary'>
<span>Stale accounts: $($StaleAccounts.Count)</span>
<span>Disabled but privileged: $($PrivilegedDisabled.Count)</span>
<span>Expiring passwords: $($ExpiringPasswords.Count)</span>
<span>Empty groups: $($EmptyGroups.Count)</span>
</div>
"@

    $body = ""
    $body += Build-HtmlSection -Title "Stale Accounts (no logon $StaleDays+ days)" -Data $StaleAccounts -RowClass "warn"
    $body += Build-HtmlSection -Title "Disabled Accounts in Privileged Groups" -Data $PrivilegedDisabled -RowClass "risk"
    $body += Build-HtmlSection -Title "Passwords Expiring within $PasswordExpiryWarningDays Days" -Data $ExpiringPasswords -RowClass "warn"
    $body += Build-HtmlSection -Title "Empty Groups" -Data $EmptyGroups -RowClass "warn"

    $footnote = @"
<p class='footnote'>
Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by ADAccountAudit.ps1. Read-only report - no changes were made to Active Directory.
Note: LastLogonTimestamp can lag up to 14 days across DC replication, so treat stale-account dates as approximate rather than exact.
</p>
"@

    $html = "<html><head><title>AD Account Audit</title>$style</head><body><h1>AD Account Audit Report</h1>$summary$body$footnote</body></html>"

    $htmlPath = Join-Path $ReportPath "$($Script:reportBaseName).html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log -Message "Wrote HTML report: $htmlPath" -Level INFO
}

##################################################
# Main
##################################################

Write-Log -Message "=== ADAccountAudit starting ===" -Level INFO
Write-Log -Message "Parameters: StaleDays=$StaleDays, PasswordExpiryWarningDays=$PasswordExpiryWarningDays, PrivilegedGroups=$($PrivilegedGroups -join ', '), SearchBase=$SearchBase, IncludeDistributionGroups=$($IncludeDistributionGroups.IsPresent), RetentionDays=$RetentionDays" -Level INFO

Try {
    Initialize-OutputFolder

    Install-RequiredModules

    Try {
        Get-ADDomain -ErrorAction Stop | Out-Null
    }
    Catch {
        Exit-WithError "Could not contact a domain controller: $($_.Exception.Message). Check network connectivity and that this machine is domain-joined."
    }

    # @() keeps an empty result as an empty array rather than $null.
    $staleAccounts      = @(Get-StaleAccounts)
    $privilegedDisabled = @(Get-DisabledPrivilegedAccounts)
    $expiringPasswords  = @(Get-ExpiringPasswords)
    $emptyGroups        = @(Get-EmptyGroups)

    Export-AuditCsv -StaleAccounts $staleAccounts -PrivilegedDisabled $privilegedDisabled -ExpiringPasswords $expiringPasswords -EmptyGroups $emptyGroups
    Export-AuditHtml -StaleAccounts $staleAccounts -PrivilegedDisabled $privilegedDisabled -ExpiringPasswords $expiringPasswords -EmptyGroups $emptyGroups

    Remove-ExpiredOutput -Folder $ReportPath -OlderThanDays $RetentionDays

    Write-Log -Message "=== ADAccountAudit completed successfully ===" -Level INFO -Success
    exit 0
}
Catch {
    Exit-WithError "Unhandled error: $($_.Exception.Message)"
}
Finally {
    # Runs on every exit path, including Exit-WithError and the exit 0 above.
    try {
        Invoke-UpdateCheckAndTelemetry
    }
    catch {
        Write-Log -Message "Update check or telemetry error: $($_.Exception.Message)" -Level Debug
    }
}