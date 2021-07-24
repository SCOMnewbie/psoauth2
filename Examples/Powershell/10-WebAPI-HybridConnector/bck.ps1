# Same idea with function app instead
using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)


Write-Host "PowerShell timer trigger function ran!"

$UserName = $Env:ServiceAccountUserName
$Password = ConvertTo-SecureString -String $($Env:ServiceAccountPassword) -AsPlainText -Force
$credential = [system.management.automation.pscredential]::new($UserName,$Password)

$Script = {
    $env:COMPUTERNAME
    $UserNameOrg = $using:UserNameOrg
    $PasswordOrg = ConvertTo-SecureString -String $($using:PasswordOrg) -AsPlainText -Force
    $credentialOrg = [system.management.automation.pscredential]::new($UserNameOrg,$PasswordOrg)

    get-aduser fanf -Credential $credentialOrg

}

invoke-command -ComputerName "endpoint name" `
                -Credential $credential `
                -Port 5986 `
                -UseSSL `
                -ScriptBlock $Script `
                -SessionOption (New-PSSessionOption -SkipCACheck)

