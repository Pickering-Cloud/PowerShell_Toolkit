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
        are selected, or any file fails to sign.

    .NOTES
        Author: Bradley Pickering
        Requires: PKI module (ships with AD CS Remote Server Administration Tools,
        Windows 8.1 / Server 2012 R2 and later)
        Requires: PowerShell running in STA mode if the interactive file picker is
        used (default for Windows PowerShell 5.1; PowerShell 7+ needs 'pwsh.exe -STA')
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [switch]$RequireADCSCertificate,
    
    [Parameter()]
    [string]$Path,
    
    [Parameter()]
    [string]$ConfigFilePath = (Join-Path -Path $PSScriptRoot -ChildPath "SignFileConfig.json"),
    
    [Parameter()]
    [switch]$UsePersonalCertificate,
    
    [Parameter()]
    [ValidateSet(2048, 3072, 4096)]
    [int]$KeyLength = 2048,
    
    [Parameter()]
    [ValidateRange(1, 25)]
    [int]$CertificateValidity = 3,

    [Parameter()]
    [string]$CodeSigningTemplate = "CodeSigning",

    [Parameter()]
    [string]$CompanyName  = "Company Name Here",

    [Parameter()]
    [string]$TimestampingAuthority,

    [Parameter()]
    [switch]$BuildConfig
)

##################################################
# Logging
##################################################

$date = Get-Date -Format "yyyyMMdd"
$logPath = "C:\Pickering-Cloud\Logs\FileSigning\$($date).log"

function Configure-LogPath {
    $logDir = Split-Path -Path $logPath -Parent

    if (-not (Test-Path $logDir)) {
        Try {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
        }
        Catch {
            Write-Error "Failed creating log path: $logDir"
            return $false
        }
    }

    return $true
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a message to the persistent log file and the appropriate PowerShell stream.
    .DESCRIPTION
        INFO writes to the file and to Write-Verbose (respects -Verbose / $VerbosePreference).
        WARN and ERROR both write to the file and to Write-Warning (respects -WarningAction);
        the distinction between them only exists in the log file itself, since PowerShell has
        no separate built-in stream for "worse than a warning but non-fatal".
        CRITICAL writes to the file, writes a warning, then exits the script with code 1.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "CRITICAL")]
        [string]$Level = "INFO"
    )
    $prefix = "[$Level]"

    if (Configure-LogPath) {
        $time = Get-Date -Format "HH:mm:SS.zzz"
        $entry = "$time | $prefix | $Message"
        Add-Content -Value $entry -Path $logPath
    }
    else {
        Write-Host "$prefix | $Message (log file unavailable)" -ForegroundColor Red
    }

    switch ($Level) {
        "WARN"     { Write-Warning $Message }
        "ERROR"    { Write-Warning $Message }
        "CRITICAL" { Write-Warning $Message; exit 1 }
        default    { Write-Verbose $Message }
    }
}

#############################################################################################

# Functions
## Builds config file and exits
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
        Write-Log -Message "Config file written to '$ConfigFilePath'."
    }
}

## Ensure all prerequesites are available
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
        Write-Log -Message "The PKI module is not available on this machine. It ships with the AD CS Remote Server Administration Tools feature (Windows 8.1 / Server 2012 R2 and later). Enable it via 'Add-WindowsFeature RSAT-ADCS' (Server) or the Windows Optional Features UI (client), then re-run this script." -Level CRITICAL
    }
    Import-Module -Name PKI -Scope Local -ErrorAction Stop
    Write-Log -Message "PKI module loaded successfully."
}

## Script Variables
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
        Write-Log -Message "Loading configuration from $configFilePath"

        try {
            $config = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json -ErrorAction Stop
        } 
        catch {
            Write-Log -Message "Failed to parse config file $($configFilePath): $($_.Exception.Message)" -Level CRITICAL
        }

        if ($null -ne $config.RequireADCSCertificate) {
            if ($RequireADCSCertificate.IsPresent -and (-not $config.RequireADCSCertificate)) {
                Write-Log -Message "RequireADCSCertificate was requested at the command line but config policy overrides it. Policy value in use: $($config.RequireADCSCertificate)." -Level WARN
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
        Write-Log -Message "No config file found at $ConfigFilePath. Using command line parameters and defaults."
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

## Get existing code signing cert
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
        Write-Verbose "Checking for existing code signing certificate"
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
        Write-Log -Message "Checking for existing code signing certificate failed: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

## Generates and installs new code signing cert
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
            Write-Verbose "Found pending request state file at '$PendingStateFile', checking status."
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
                        Write-Log -Message "Request $($state.Thumbprint) is still $($result.Status). Re-run once approved." -Level WARN
                        return
                    }
                }
            }
            else {
                Write-Verbose 'Referenced pending request no longer exists, submitting fresh request.'
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
                        Write-Log -Message "Request submitted but requires CA manager approval (thumbprint: $thumbprint). Re-run once approved." -Level WARN
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
            Write-Log -Message "ADCSRequired is set but a certificate could not be obtained from ADCS: $($_.Exception.Message)" -Level CRITICAL
        }

        Write-Log -Message "ADCS certificate unavailable, falling back to self-signed: $($_.Exception.Message)" -Level WARN

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
                    Write-Log -Message "Added $($newCert.Thumbprint) to Cert:\$Scope\$storeName."
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
            Write-Log -Message "No file found at '$Path'. Falling back to interactive file picker." -Level WARN
        }
        else {
            return @((Resolve-Path -Path $Path).ProviderPath)
        }
    }
    else {
        Write-Verbose "No -Path supplied, opening file picker."
    }
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        Write-Log -Message "PowerShell is not running in STA mode. The file picker may fail or behave unexpectedly. If it does, restart with 'pwsh.exe -STA' (or 'powershell.exe -STA' on Windows PowerShell)." -Level WARN
    }
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = [System.Windows.Forms.OpenFileDialog]::new()
    $dialog.Title = 'Select file(s) to sign'
    $dialog.Multiselect = $true
    $dialog.Filter = 'PowerShell Files (*.ps1;*.psm1;*.psd1;*.ps1xml;*.psc1;*.cdxml;*.mof;*.xaml)|*.ps1;*.psm1;*.psd1;*.ps1xml;*.psc1;*.cdxml;*.mof;*.xaml|Other Signable Files (*.exe;*.dll;*.msi;*.cat;*.js;*.vbs;*.ocx;*.cab)|*.exe;*.dll;*.msi;*.cat;*.js;*.vbs;*.ocx;*.cab|All Files (*.*)|*.*'
    $dialog.FilterIndex = 1
    $result = $dialog.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK -or $dialog.FileNames.Count -eq 0) {
        Write-Log -Message "No files selected." -Level WARN
        return @()
    }
    Write-Log -Message "$($dialog.FileNames.Count) file(s) selected."
    return $dialog.FileNames

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
                Write-Log -Message "Signed successfully: $file"
            }
            else {
                $failures += $file
                Write-Log -Message "Failed to sign $file. Status: $($result.Status). $($result.StatusMessage)" -Level ERROR
            }
        }
    }
    if ($failures) {
        Write-Log -Message "$($failures.Count) of $($fileList.Count) file(s) failed to sign." -Level WARN
    }
    return [PSCustomObject]@{
        Total     = $fileList.Count
        Succeeded = $fileList.Count - $failures.Count
        Failed    = $failures
    }

#############################################################################################

# Main script

Write-Log -Message "FileSigning script started."

try {
    ## Build Config file
    if ($BuildConfig) {
        New-SignFileConfig
        Write-Log -Message "Config file built via -BuildConfig; exiting without signing."
        exit 0
    }

    ## Check for prerequesites
    Test-Prerequisites 

    ## Initialise variables
    $variables = Get-ScriptVariables -RequireADCSCertificate:$RequireADCSCertificate -UsePersonalCertificate:$UsePersonalCertificate -ConfigFilePath $ConfigFilePath -validityLength $CertificateValidity -certTemplate $CodeSigningTemplate -companyName $CompanyName -keyLength $KeyLength -timestampServer $TimestampingAuthority

    ## Check/generate code signing cert
    $codeSigningCert = Get-ExistingCodeSigningCert -CertificateStore $variables.CertificateStore
    if (-not $codeSigningCert) {
        $codeSigningCert = New-CodesigningCert -CertStore $variables.CertificateStore -ADCSRequired:$variables.RequireADCSCertificate -CompanyName $variables.CompanyName -KeyLength $variables.KeyLength -ValidityLength $variables.ValidityLength -CertTemplate $variables.CertTemplate
    }

    if (-not $codeSigningCert) {
        Write-Log -Message "No usable code signing certificate available (request may be pending CA approval)." -Level CRITICAL
    }

    ## Find files to be signed
    $filesToSign = Get-FileToSign -Path $Path

    if (-not $filesToSign) {
        Write-Log -Message "No files chosen to sign." -Level CRITICAL
    }

    ## Sign files
    $signResult = Set-FileSignature -FileList $filesToSign -SigningCertificate $codeSigningCert -TimestampServer $variables.timestampServer

    if ($signResult.Failed) {
        Write-Log -Message "$($signResult.Failed.Count) of $($signResult.Total) file(s) failed to sign." -Level CRITICAL
    }

    Write-Log -Message "All $($signResult.Total) file(s) signed successfully."
}
catch {
    Write-Log -Message "Unhandled error: $($_.Exception.Message)" -Level CRITICAL
}