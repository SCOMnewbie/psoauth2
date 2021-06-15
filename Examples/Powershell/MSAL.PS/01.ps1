$AppIdFront = "6ea03e19-4893-407f-b443-7671dc46bedf"
$TenantId = "9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20"
$RedirectURI = "http://localhost"

New-MsalClientApplication -ClientId $AppIdFront -RedirectUri $RedirectURI -TenantId $TenantId -Verbose



# Get all UPN
Get-MsalClientApplication -ClientId $AppIdFront | Get-MsalAccount


Get-MsalClientApplication -ClientId $AppIdFront | Get-MsalToken -Scopes 'openid'
#fail
Get-MsalClientApplication -ClientId $AppIdFront | Enable-MsalTokenCacheOnDisk


Get-MsalToken -ClientId $AppIdFront -RedirectUri $RedirectURI -TenantId $TenantId -Interactive
Get-MsalToken -ClientId $AppIdFront -RedirectUri $RedirectURI -TenantId $TenantId -Silent

$ConfidentialClientOptions = New-Object Microsoft.Identity.Client.ConfidentialClientApplicationOptions
$ConfidentialClientOptions.ClientId

# User assignment no role
<#
❯ Get-MsalClientApplication -ClientId $AppIdFront | Get-MsalToken -Scopes 'api://825388eb-37d5-4b0d-8e09-05ab16c52492/user_impersonation openid offline_access' -Silent
Get-MsalToken: AADSTS50105: The signed in user '{EmailHidden}' is not assigned to a role for the application '825388eb-37d5-4b0d-8e09-05ab16c52492'(DemoTest3BackAPI).
Trace ID: 96684870-0571-4c22-8f97-9c06162b6502
Correlation ID: 84530d16-978f-4dbe-ba9a-a77349cf6f01
Timestamp: 2021-06-03 11:09:16Z
#>

$secret = ConvertTo-SecureString -String "WUiUa9n6V6h_0-Vi" -AsPlainText -Force
Get-MsalToken -ClientId "58d23568-b24e-4cf7-ab30-4436c2725a8a" -ClientSecret $secret -TenantId $TenantId # Force client cred flow (./default)


## Share caching between session

### In first session

Get-MsalToken -ClientId $AppIdFront -RedirectUri $RedirectURI -TenantId $TenantId -Interactive
Get-MsalToken -ClientId $AppIdFront -RedirectUri $RedirectURI -TenantId $TenantId -Silent # Still use memory

Get-MsalClientApplication -ClientId $AppIdFront | Enable-MsalTokenCacheOnDisk # Dump the cache on the disk

### In another session
$AppIdFront = "6ea03e19-4893-407f-b443-7671dc46bedf"
$TenantId = "9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20"
$RedirectURI = "http://localhost"

New-MsalClientApplication -ClientId $AppIdFront -RedirectUri $RedirectURI -TenantId $TenantId | Add-MsalClientApplication -PassThru
Get-MsalClientApplication -ClientId $AppIdFront | Enable-MsalTokenCacheOnDisk
Get-MsalClientApplication -ClientId $AppIdFront | Get-MsalToken -Scopes "openid" -Silent

# BOOM