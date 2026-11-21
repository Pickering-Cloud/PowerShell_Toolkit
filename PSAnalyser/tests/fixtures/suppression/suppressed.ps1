Write-Host 'a' # psa-ignore PSL004 -- same-line suppression
# psa-ignore PSL004 -- next-line suppression
Write-Host 'b'
# psa-disable PSL004 -- region suppression
Write-Host 'c'
Write-Host 'd'
# psa-enable PSL004
