Get-ChildItem C:\ | Where-Object { $_.Length -gt 0 } | ForEach-Object { $_.Name }
sc -Path x.txt -Value 1
