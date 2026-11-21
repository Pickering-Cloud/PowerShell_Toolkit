param([string]$Password)
$secure = ConvertTo-SecureString $Password -AsPlainText -Force
