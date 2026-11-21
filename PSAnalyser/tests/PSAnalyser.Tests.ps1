#Requires -Version 5.1
<#
.SYNOPSIS
    Pester 5 tests for PSAnalyser.
.DESCRIPTION
    Every test runs PSAnalyser in a separate, non-interactive process on the same
    PowerShell engine that is running Pester, so the suite checks Windows PowerShell 5.1
    when run under powershell.exe and PowerShell 7 when run under pwsh.exe.

    Run from the repository root:
        Invoke-Pester -Path .\PSAnalyser\tests -Output Detailed
#>

BeforeDiscovery {
    $fixtureRoot = Join-Path -Path $PSScriptRoot -ChildPath 'fixtures'
    $expected = Import-PowerShellDataFile -Path (Join-Path -Path $fixtureRoot -ChildPath 'expected.psd1')
    $RuleCases = foreach ($key in ($expected.Keys | Sort-Object)) {
        @{ RuleId = $key; Count = $expected[$key] }
    }
    $FixCases = foreach ($dir in (Get-ChildItem -Path (Join-Path -Path $fixtureRoot -ChildPath 'fix') -Directory | Sort-Object -Property Name)) {
        @{ Name = $dir.Name; Dir = $dir.FullName }
    }
}

BeforeAll {
    $script:Root = Split-Path -Path $PSScriptRoot -Parent
    $script:Tool = Join-Path -Path $script:Root -ChildPath 'PSAnalyser.ps1'
    $script:Fixtures = Join-Path -Path $PSScriptRoot -ChildPath 'fixtures'
    $script:TestConfig = Join-Path -Path $PSScriptRoot -ChildPath 'psanalyser.test.json'
    $script:Engine = (Get-Process -Id $PID).Path

    function Invoke-PSAnalyser {
        <#
        .SYNOPSIS
            Runs PSAnalyser in a child process and returns its exit code and output.
        #>
        param(
            [string[]]$Arguments = @()
        )

        $logPath = Join-Path -Path $TestDrive -ChildPath ('log-{0}.log' -f [guid]::NewGuid().ToString('N'))
        $allArguments = @('-NoProfile', '-NonInteractive', '-File', $script:Tool) + $Arguments + @('-LogPath', $logPath, '-DisableTelemetry', '-DisableUpdateCheck')
        $output = & $script:Engine @allArguments 2>&1 | Out-String
        $log = ''
        if (Test-Path -LiteralPath $logPath) {
            $log = Get-Content -LiteralPath $logPath -Raw
        }
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output; Log = $log }
    }

    function Get-JsonReport {
        <#
        .SYNOPSIS
            Returns the newest JSON report in a folder.
        #>
        param(
            [string]$Folder
        )

        $file = Get-ChildItem -Path $Folder -Filter '*.json' | Sort-Object -Property LastWriteTime | Select-Object -Last 1
        return (Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json)
    }

    function ConvertTo-VisibleText {
        <#
        .SYNOPSIS
            Shows a file's bytes as text with the BOM and line endings made visible, so
            a failed comparison is readable.
        #>
        param(
            [string]$Path
        )

        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $prefix = ''
        $start = 0
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $prefix = '<BOM>'
            $start = 3
        }
        $text = (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false).GetString($bytes, $start, $bytes.Length - $start)
        return $prefix + $text.Replace("`r", '<CR>').Replace("`n", '<LF>').Replace("`t", '<TAB>')
    }

    function Get-TemplateRegion {
        <#
        .SYNOPSIS
            Returns the PC-TEMPLATE region of a script, with line endings normalised.
        #>
        param(
            [string]$Path
        )

        $text = [System.IO.File]::ReadAllText($Path) -replace "`r`n", "`n"
        return [regex]::Match($text, '(?ms)^#region PC-TEMPLATE.*?^#endregion PC-TEMPLATE[^\n]*').Value
    }
}

Describe 'Rule detection' {
    BeforeAll {
        $reportDir = Join-Path -Path $TestDrive -ChildPath 'detect'
        $script:DetectRun = Invoke-PSAnalyser -Arguments @('-Path', $script:Fixtures, '-Recurse', '-Exclude', 'fix\*,suppression\*', '-ConfigPath', $script:TestConfig, '-Report', 'Json,Csv', '-ReportPath', $reportDir)
        $script:Detect = Get-JsonReport -Folder $reportDir
        $script:DetectCsv = Get-ChildItem -Path $reportDir -Filter '*.csv' | Select-Object -First 1
    }

    It 'completes with exit code 0' {
        $script:DetectRun.ExitCode | Should -Be 0 -Because $script:DetectRun.Output
    }

    It 'finds <Count> <RuleId> finding(s) in <RuleId>\bad.ps1' -ForEach $RuleCases {
        $found = @($script:Detect.findings | Where-Object { $_.RuleId -eq $RuleId -and $_.File -like "*\$RuleId\bad.ps1" })
        $found.Count | Should -Be $Count -Because (($found | ForEach-Object { '{0}:{1} {2}' -f $_.Line, $_.Column, $_.Message }) -join '; ')
    }

    It 'finds no <RuleId> findings in <RuleId>\good.ps1' -ForEach $RuleCases {
        $found = @($script:Detect.findings | Where-Object { $_.RuleId -eq $RuleId -and $_.File -like "*\$RuleId\good.ps1" })
        $found.Count | Should -Be 0 -Because (($found | ForEach-Object { '{0}:{1} {2}' -f $_.Line, $_.Column, $_.Message }) -join '; ')
    }

    It 'writes a CSV report with the same number of findings' {
        $script:DetectCsv | Should -Not -BeNullOrEmpty
        @(Import-Csv -LiteralPath $script:DetectCsv.FullName).Count | Should -Be @($script:Detect.findings).Count
    }

    It 'never shows hard-coded secret values in the console, log or reports' {
        $report = Get-Content -LiteralPath $script:DetectCsv.FullName -Raw
        $json = $script:Detect | ConvertTo-Json -Depth 6
        foreach ($secret in 'Sup3rS3cretValue!', 'k3y-abcd1234efgh5678', 'abcdefghijklmnopqrstuvwxyz0123456789') {
            $script:DetectRun.Output | Should -Not -Match ([regex]::Escape($secret))
            $script:DetectRun.Log | Should -Not -Match ([regex]::Escape($secret))
            $report | Should -Not -Match ([regex]::Escape($secret))
            $json | Should -Not -Match ([regex]::Escape($secret))
        }
    }

    It 'gives every security finding a CWE' {
        $security = @($script:Detect.findings | Where-Object { $_.Category -eq 'Security' })
        $security.Count | Should -BeGreaterThan 0
        @($security | Where-Object { $_.Cwe -notmatch '^CWE-\d+' }).Count | Should -Be 0
    }
}

Describe 'Suppressions' {
    It 'honours psa-ignore on the same line and the next line, and psa-disable regions' {
        $reportDir = Join-Path -Path $TestDrive -ChildPath 'suppress'
        $run = Invoke-PSAnalyser -Arguments @('-Path', (Join-Path -Path $script:Fixtures -ChildPath 'suppression'), '-ConfigPath', $script:TestConfig, '-Report', 'Json', '-ReportPath', $reportDir)
        $run.ExitCode | Should -Be 0
        $report = Get-JsonReport -Folder $reportDir
        @($report.findings | Where-Object { $_.RuleId -in 'PSL004', 'PSL007' }).Count | Should -Be 0
    }
}

Describe 'Safe fixes' {
    It '<Name>: output matches, parses, and a second run changes nothing' -ForEach $FixCases {
        $work = Join-Path -Path $TestDrive -ChildPath ('fix-{0}' -f $Name)
        [void](New-Item -Path $work -ItemType Directory -Force)
        $target = Join-Path -Path $work -ChildPath 'script.ps1'
        Copy-Item -LiteralPath (Join-Path -Path $Dir -ChildPath 'before.ps1') -Destination $target
        $backups = Join-Path -Path $work -ChildPath 'backups'
        $arguments = @('-Path', $target, '-Fix', '-ConfigPath', $script:TestConfig, '-BackupPath', $backups)
        if ($Name -ne 'All') {
            $arguments += @('-Rules', $Name)
        }

        $first = Invoke-PSAnalyser -Arguments $arguments
        $first.ExitCode | Should -Be 0 -Because $first.Output
        ConvertTo-VisibleText -Path $target | Should -BeExactly (ConvertTo-VisibleText -Path (Join-Path -Path $Dir -ChildPath 'after.ps1'))

        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$null, [ref]$parseErrors)
        @($parseErrors).Count | Should -Be 0

        @(Get-ChildItem -Path $backups -Recurse -File).Count | Should -Be 1

        $hash = (Get-FileHash -LiteralPath $target).Hash
        $second = Invoke-PSAnalyser -Arguments $arguments
        $second.ExitCode | Should -Be 0
        (Get-FileHash -LiteralPath $target).Hash | Should -Be $hash
    }

    It 'shows a diff and writes nothing under -WhatIf' {
        $work = Join-Path -Path $TestDrive -ChildPath 'whatif'
        [void](New-Item -Path $work -ItemType Directory -Force)
        $target = Join-Path -Path $work -ChildPath 'script.ps1'
        Copy-Item -LiteralPath (Join-Path -Path $script:Fixtures -ChildPath 'fix\All\before.ps1') -Destination $target
        $hash = (Get-FileHash -LiteralPath $target).Hash
        $backups = Join-Path -Path $work -ChildPath 'backups'

        $run = Invoke-PSAnalyser -Arguments @('-Path', $target, '-Fix', '-WhatIf', '-ConfigPath', $script:TestConfig, '-BackupPath', $backups)
        $run.ExitCode | Should -Be 0
        $run.Output | Should -Match '(?m)^--- a/'
        $run.Output | Should -Match '(?m)^@@ -\d+,\d+ \+\d+,\d+ @@'
        $run.Output | Should -Match '(?m)^\+Get-ChildItem'
        (Get-FileHash -LiteralPath $target).Hash | Should -Be $hash
        Test-Path -LiteralPath $backups | Should -BeFalse
    }

    It 'does not apply fixes in an unattended run without -Fix' {
        $work = Join-Path -Path $TestDrive -ChildPath 'nofix'
        [void](New-Item -Path $work -ItemType Directory -Force)
        $target = Join-Path -Path $work -ChildPath 'script.ps1'
        Copy-Item -LiteralPath (Join-Path -Path $script:Fixtures -ChildPath 'fix\All\before.ps1') -Destination $target
        $hash = (Get-FileHash -LiteralPath $target).Hash

        $run = Invoke-PSAnalyser -Arguments @('-Path', $target, '-ConfigPath', $script:TestConfig)
        $run.ExitCode | Should -Be 0
        $run.Output | Should -Match 'safe fix'
        (Get-FileHash -LiteralPath $target).Hash | Should -Be $hash
    }
}

Describe 'Options and exit codes' {
    It 'exits with 2 when -FailOnSeverity is met' {
        $run = Invoke-PSAnalyser -Arguments @('-Path', (Join-Path -Path $script:Fixtures -ChildPath 'PSS004\bad.ps1'), '-ConfigPath', $script:TestConfig, '-FailOnSeverity', 'High')
        $run.ExitCode | Should -Be 2
    }

    It 'exits with 0 when -FailOnSeverity is not met' {
        $run = Invoke-PSAnalyser -Arguments @('-Path', (Join-Path -Path $script:Fixtures -ChildPath 'PSL004\bad.ps1'), '-ConfigPath', $script:TestConfig, '-FailOnSeverity', 'High')
        $run.ExitCode | Should -Be 0
    }

    It 'exits with 1 when a path does not exist' {
        $run = Invoke-PSAnalyser -Arguments @('-Path', (Join-Path -Path $TestDrive -ChildPath 'missing.ps1'))
        $run.ExitCode | Should -Be 1
    }

    It 'exits with 1 when the config file is not valid JSON' {
        $config = Join-Path -Path $TestDrive -ChildPath 'broken.json'
        Set-Content -LiteralPath $config -Value '{ not json'
        $run = Invoke-PSAnalyser -Arguments @('-Path', (Join-Path -Path $script:Fixtures -ChildPath 'PSL004\bad.ps1'), '-ConfigPath', $config)
        $run.ExitCode | Should -Be 1
    }

    It 'applies config rule settings (disabled rules and severity overrides)' {
        $config = Join-Path -Path $TestDrive -ChildPath 'rules.json'
        Set-Content -LiteralPath $config -Value '{ "rules": { "PSL004": { "enabled": false }, "PSL001": { "severity": "High" } } }'
        $reportDir = Join-Path -Path $TestDrive -ChildPath 'config'
        $work = Join-Path -Path $TestDrive -ChildPath 'config-files'
        [void](New-Item -Path $work -ItemType Directory -Force)
        Copy-Item -LiteralPath (Join-Path -Path $script:Fixtures -ChildPath 'PSL004\bad.ps1') -Destination (Join-Path -Path $work -ChildPath 'psl004.ps1')
        Copy-Item -LiteralPath (Join-Path -Path $script:Fixtures -ChildPath 'PSL001\bad.ps1') -Destination (Join-Path -Path $work -ChildPath 'psl001.ps1')
        $run = Invoke-PSAnalyser -Arguments @('-Path', $work, '-ConfigPath', $config, '-Report', 'Json', '-ReportPath', $reportDir)
        $run.ExitCode | Should -Be 0
        $report = Get-JsonReport -Folder $reportDir
        @($report.findings | Where-Object { $_.RuleId -eq 'PSL004' }).Count | Should -Be 0
        @($report.findings | Where-Object { $_.RuleId -eq 'PSL001' -and $_.Severity -ne 'High' }).Count | Should -Be 0
        @($report.findings | Where-Object { $_.RuleId -eq 'PSL001' }).Count | Should -Be 3
    }

    It 'skips PSC001 when 5.1 is not a target version' {
        $config = Join-Path -Path $TestDrive -ChildPath 'seven.json'
        Set-Content -LiteralPath $config -Value '{ "targetVersions": ["7"] }'
        $reportDir = Join-Path -Path $TestDrive -ChildPath 'seven'
        $run = Invoke-PSAnalyser -Arguments @('-Path', (Join-Path -Path $script:Fixtures -ChildPath 'PSC001\bad.ps1'), '-ConfigPath', $config, '-Report', 'Json', '-ReportPath', $reportDir)
        $run.ExitCode | Should -Be 0
        $report = Get-JsonReport -Folder $reportDir
        @($report.findings | Where-Object { $_.RuleId -eq 'PSC001' }).Count | Should -Be 0
    }

    It 'only runs the rules named in -Rules' {
        $reportDir = Join-Path -Path $TestDrive -ChildPath 'rulefilter'
        $run = Invoke-PSAnalyser -Arguments @('-Path', $script:Fixtures, '-Recurse', '-Exclude', 'fix\*', '-ConfigPath', $script:TestConfig, '-Rules', 'PSS*', '-ExcludeRules', 'PSS004', '-Report', 'Json', '-ReportPath', $reportDir)
        $run.ExitCode | Should -Be 0
        $report = Get-JsonReport -Folder $reportDir
        @($report.findings).Count | Should -BeGreaterThan 0
        @($report.findings | Where-Object { $_.RuleId -notlike 'PSS*' -or $_.RuleId -eq 'PSS004' }).Count | Should -Be 0
    }

    It 'hides findings below -MinimumSeverity' {
        $reportDir = Join-Path -Path $TestDrive -ChildPath 'minsev'
        $run = Invoke-PSAnalyser -Arguments @('-Path', (Join-Path -Path $script:Fixtures -ChildPath 'PSL004\bad.ps1'), '-ConfigPath', $script:TestConfig, '-MinimumSeverity', 'Medium', '-Report', 'Json', '-ReportPath', $reportDir)
        $run.ExitCode | Should -Be 0
        $report = Get-JsonReport -Folder $reportDir
        @($report.findings).Count | Should -Be 0
    }

    It 'lists every rule with -ListRules' {
        $run = Invoke-PSAnalyser -Arguments @('-ListRules')
        $run.ExitCode | Should -Be 0
        $expected = Import-PowerShellDataFile -Path (Join-Path -Path $script:Fixtures -ChildPath 'expected.psd1')
        foreach ($id in $expected.Keys) {
            $run.Output | Should -Match ('(?m)^{0}\s' -f $id)
        }
        $listed = @([regex]::Matches($run.Output, '(?m)^PS[FLSCT]\d{3}\s')).Count
        $listed | Should -Be $expected.Count -Because 'every rule needs a fixture and an expected count'
    }
}

Describe 'PSAnalyser itself' {
    It 'lints itself clean' {
        $reportDir = Join-Path -Path $TestDrive -ChildPath 'self'
        $run = Invoke-PSAnalyser -Arguments @('-Path', $script:Tool, '-Report', 'Json', '-ReportPath', $reportDir)
        $run.ExitCode | Should -Be 0
        $report = Get-JsonReport -Folder $reportDir
        @($report.findings).Count | Should -Be 0 -Because (($report.findings | ForEach-Object { '{0}:{1} {2} {3}' -f $_.Line, $_.Column, $_.RuleId, $_.Message }) -join '; ')
    }

    It 'has a PC-TEMPLATE region unchanged from the canonical template' {
        # template.ps1 is kept out of source control, so fall back to another toolkit
        # script that carries the same synced region.
        $canonical = Join-Path -Path (Split-Path -Path $script:Root -Parent) -ChildPath 'template.ps1'
        if (-not (Test-Path -LiteralPath $canonical)) {
            $canonical = Join-Path -Path (Split-Path -Path $script:Root -Parent) -ChildPath 'EntraAppExpiryScanner\EntraAppExpiryScanner.ps1'
        }
        $expectedRegion = Get-TemplateRegion -Path $canonical
        $expectedRegion | Should -Not -BeNullOrEmpty
        Get-TemplateRegion -Path $script:Tool | Should -BeExactly $expectedRegion
    }
}
