$py_path = "C:\Users\<username>\Desktop\DiscordC2_Proj\Tools"
$py_server = "python -m http.server 80"
$ng_path = "C:\Users\<username>\Desktop\Projects & Tools"
$ng_server = ".\ngrok.exe http --domain=constantly-happy-heron.ngrok-free.app 80"

Start-Job -ScriptBlock {
    param($path, $command)
    Set-Location $path
    Invoke-Expression $command
} -ArgumentList $py_path, $py_server

Start-Job -ScriptBlock {
    param($path, $command)
    Set-Location $path
    Invoke-Expression $command
} -ArgumentList $ng_path, $ng_server
pause
Stop-Job *
Get-Job | Remove-Job
