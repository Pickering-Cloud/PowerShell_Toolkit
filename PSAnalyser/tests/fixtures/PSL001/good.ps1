function ls { Get-ChildItem }
ls
Get-ChildItem C:\ | Where-Object { $_.Length -gt 0 }
foreach ($i in 1..2) { $i }
