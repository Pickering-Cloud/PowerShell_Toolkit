gci C:\ | ? { $_.Length -gt 0 } | % { $_.Name }
sc -Path x.txt -Value 1
