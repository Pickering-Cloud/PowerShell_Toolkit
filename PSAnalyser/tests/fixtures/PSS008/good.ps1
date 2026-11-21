Start-Process "$env:SystemRoot\notepad.exe"
Start-Process notepad.exe -ArgumentList @('/a', $file)
& $scriptBlock
& "$PSScriptRoot\helper.ps1"
