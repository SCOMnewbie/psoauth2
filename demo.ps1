<#
$ClientId = "564b5938-5f3a-4471-bc38-cdc181b28783"
$TenantId = "e192cada-a04d-4cfc-8b90-d14338b2c7ec"

$Splatting = @{
    Resource       = $ClientId
    TenantId       = $TenantId
    Scope          = "https://storage.azure.com/user_impersonation openid offline_access"
    DeviceCodeFlow = $true
    verbose        = $true
}
#>

#Load functions in memory
#$Functions = @( Get-ChildItem -Path ".\src\*.ps1" -ErrorAction SilentlyContinue )
$Functions = @( Get-ChildItem -Path ".\src\" -Recurse -File '*.ps1' -ErrorAction SilentlyContinue )
Foreach ($Function in $Functions) {
    Try {
         . $Function.fullname
    }
    catch{
        Write-Error "Unable to load functions"
    }
}

#region DemoScenario1 

$clientId = "ca4aebf7-db32-4275-a688-c431232400f0"
$TenantId = "e192cada-a04d-4cfc-8b90-d14338b2c7ec"
$secret = "P-eWYVHVLFehPv.OYvYrn273202.C6-O8w"

$Splatting = @{
    Resource       = $ClientId
    TenantId       = $TenantId
    Scope          = "https://graph.microsoft.com/.default openid offline_access"
    secret = $secret
    ClientCredentialFlow = $true
    verbose        = $true
}

$token = New-AccessToken @Splatting

#Now we have token let's try to access any mailbox

$uri = "https://graph.microsoft.com/v1.0/users/862d98e9-6102-4019-bf4d-b840708996ee/messages?`$select=subject"
$Messages = Invoke-RestMethod -ContentType 'application/json' -Headers @{'Authorization' = "Bearer $token"} -Uri $uri -Method get

#$error normal because permission not granted. Let's grant it
# Remove the cache
# now it's working

$Messages = Invoke-RestMethod -ContentType 'application/json' -Headers @{'Authorization' = "Bearer $token"} -Uri $uri -Method get
# Display top 10 subjects
$messages.value | select subject

#Now enable user assignment required
#Clear cache, and again with credental flow, it's working ...

#Let's try with auth code

$token2 = New-AccessToken -AuthCodeFlow -Scope "https://graph.microsoft.com/.default openid offline_access" -TenantId $TenantId -secret $secret -Resource $clientId -RedirectUri "https://login.microsoftonline.com/common/oauth2/nativeclient" -Verbose

<#
 {"error":"invalid_client","error_description":"AADSTS700025: Client is public so neither 'client_assertion' nor 'client_secret' should be presented.\r\nTrace ID:
     | 51c635f3-ae89-47d2-88a3-771f07c51300\r\nCorrelation ID: 1895eb12-b5e1-4931-9dec-471562d501db\r\nTimestamp: 2021-03-31 19:25:00Z","error_codes":[700025],"timestamp":"2021-03-31
     | 19:25:00Z","trace_id":"51c635f3-ae89-47d2-88a3-771f07c51300","correlation_id":"1895eb12-b5e1-4931-9dec-471562d501db"}
#>

# At least the flow is blocking us of doing stupid things ! 
#endregion