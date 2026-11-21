[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls
Invoke-RestMethod -Uri 'http://example.com/api'
