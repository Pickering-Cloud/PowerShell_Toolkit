gci C:\ | ? { $_.Name -eq $null };  
	Write-Output 'café'
Get-Date