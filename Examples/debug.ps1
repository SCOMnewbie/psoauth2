
#Use the previously created module
# Import-Module 'C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1'
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

# To avoid surprises when you had generated a cache on another tenant :p
#Clear-TokenCache


$AppId = "285c1bd1-ca28-481c-9bf6-c45541985aad"
#Define variable for the demo
$TenantId = '9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20'

$Splatting = @{
    Resource     = $AppId
    TenantId     = $TenantId
    Scope        = "https://graph.microsoft.com/User.Read OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

# No role in Access token but roles in Id Token

# Now let's expose a backend api
Clear-TokenCache
$Splatting = @{
    Resource     = $AppId # DemoJPDAFrontEnd
    TenantId     = $TenantId
    Scope        = "api://d551af50-b077-4292-8183-8338c96a6607/user_impersonation openid" # DemoJPDABackend
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

$AccessToken | clip





https://graph.microsoft.com/v1.0/applications/0c992489-84cb-4325-830a-81366f785ead # ObjectId App registration

https://graph.microsoft.com/v1.0/servicePrincipals/01ba0034-d430-410b-8dee-b394a2192e74 #ObjectId Enterprise app POST
# This is body of the post
<#
{
    "principalId": "a149cdc8-4218-4841-a9c4-ee3359cc49c7", # Object Id of the frontend SP
    "resourceId": "01ba0034-d430-410b-8dee-b394a2192e74", # Same ObjectId from the request
    "appRoleId": "ccbc3218-fe1b-4b02-be5a-203ef24791ef" # Id of the backend app role
}
#>



####TEST with client flow

$AppId2 = "539df090-ff0b-42d2-8f8f-225349cf97f7"
$Secret = "51d-fC~TnnY1Cs1~Je5_s"

Clear-TokenCache
$Splatting = @{
    Resource     = $AppId2 # DemoJPDAFrontEnd
    TenantId     = $TenantId
    Scope        = "api://d551af50-b077-4292-8183-8338c96a6607/.default" # DemoJPDABackend
    ClientCredentialFlow = $true
    Secret = $Secret
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

## Happy days, roles appear in the access toekn

#### Let's now try if we simailate a web app

$AppId3 = "445dcdeb-9bb1-4698-b0e8-8d50c4fee7a8"
$Secret = "xU7I2emg8H~iM0e-K-N"


Clear-TokenCache
$Splatting = @{
    Resource     = $AppId3 # DemoJPDAFrontEnd
    TenantId     = $TenantId
    Scope        = "api://d551af50-b077-4292-8183-8338c96a6607/user_impersonation openid" # DemoJPDABackend
    RedirectUri  = 'http://localhost'
    AuthCodeFlow = $true
    Secret = $Secret
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting


Clear-TokenCache
$Splatting = @{
    Resource     = $AppId3 # DemoJPDAFrontEnd
    TenantId     = $TenantId
    Scope        = "https://graph.microsoft.com/User.Read openId" # DemoJPDABackend
    RedirectUri  = 'http://localhost'
    AuthCodeFlow = $true
    Secret = $Secret
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting




$AppId4 = "22b5e4a9-ead3-471c-9b12-8650b2ea2cad"
$appIdBack = "83527de6-43f4-4c30-b7be-fa10322ea062"
# Now let's expose a backend api
Clear-TokenCache
$Splatting = @{
    Resource     = $AppId4 # DemoJPDAFrontEnd
    TenantId     = $TenantId
    Scope        = "api://83527de6-43f4-4c30-b7be-fa10322ea062/Files.Read" # DemoJPDABackend
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
    AuthCodeFlow = $true
    prompt = 'select_account'
    verbose      = $true
    
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

$AccessToken | clip


#### FAKE
$AppId4 = "6055ba6f-0902-4379-b128-a96e522fb521"
Clear-TokenCache
$Splatting = @{
    Resource     = $AppId4 # DemoJPDAFrontEnd
    TenantId     = $TenantId
    Scope        = "api://83527de6-43f4-4c30-b7be-fa10322ea062/Files.Read" # DemoJPDABackend
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
    AuthCodeFlow = $true
    prompt = 'select_account'
    verbose      = $true
    
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting
