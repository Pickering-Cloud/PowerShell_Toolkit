[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
Invoke-WebRequest https://example.com -SkipCertificateCheck
