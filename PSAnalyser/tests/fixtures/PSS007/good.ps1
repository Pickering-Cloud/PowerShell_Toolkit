Get-FileHash -Algorithm SHA256 -Path x.zip
$sha = [System.Security.Cryptography.SHA256]::Create()
