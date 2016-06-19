Set-ExecutionPolicy RemoteSigned
$creds = Get-Credential

$session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/powershell/ -Authentication Basic -Credential $creds
Import-PSSession $session

Remove-PSSession $session