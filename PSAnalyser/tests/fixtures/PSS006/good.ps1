[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-RestMethod -Uri 'https://example.com/api'
Invoke-RestMethod -Uri 'http://localhost:8080/api'
