<#
    # INTRO

    Now that we've seen how to connect and different tokens, I wanted to talk about a concept I've dicovered recently: App Roles. Long story short you create app roles in your app registration
    for either user/group or application (Service principal) or both.
    Following this question: https://twitter.com/ehrnst/status/1399662927783813121?s=20, I wanted to better understand what you can do with those app roles.
    It's still not 100% in my head, but it's better than nothing :)

    Let's play

    # DEMO
        For this demo, we will create several apps and several configuration to better understand the behavior.




        For simplicity, we will create 4 applications and see in parallel what are the differences:
        We will create 5:
        * An PUBLIC app registration account (Means all the tenant + guest accounts can log in)
            * As usual V2 endpoint enforced, single tenant enforced from my PSAADApplication module
        * Add a service principal on it (it becomes an app with an identity)
        * I won't enforce the assignment this time (too painful for the demo :p)
        * And create a new app called joker. (Add a logo to the app because why not > Fail the logo is on the other repo, but you can use Add-AppRegistrationLogo)
        * Play with OIDC scopes
        * Delete the apps

    In this demo, I will use the beta graph api endpoint to list the authetication method a user have assigned.

    Notes: To get the Id you have to use in your app registration manifest, you can use:
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id


#>


# Get token for Front app

Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

$AppIdFront = "6ea03e19-4893-407f-b443-7671dc46bedf"
$AppIdBackendAPI = "825388eb-37d5-4b0d-8e09-05ab16c52492"
$BackEndGraphAPI = "58d23568-b24e-4cf7-ab30-4436c2725a8a"
$Password = ConvertTo-SecureString -String "blah" -AsPlainText -Force

$TenantId = '9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20'


# Get Token from frontend to backend


$Splatting = @{
    Resource     = $AppIdFront
    TenantId     = $TenantId
    Scope        = "api://825388eb-37d5-4b0d-8e09-05ab16c52492/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    #withoutcache = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

$Headers = @{
    'Authorization'  = $AccessToken
}

$Params = @{
    Headers = $headers
    uri     = "https://funwithidentity.azurewebsites.net/api/DemoBackendAPI-Application?code=jkwvUQ/siRAfd/oyBV64DTlRzTAgI7OwRTsxcFcHfCQ=="
    Body    = $null
    method  = 'Get'
}

Invoke-RestMethod @Params

######## HERE we managed the application permission

#### Work on the delegated now

#1 connect with LX
#2 genrete new token with OBO
#3 do graph queries

$Splatting = @{
    Resource     = $AppIdFront
    TenantId     = $TenantId
    Scope        = "api://825388eb-37d5-4b0d-8e09-05ab16c52492/user_impersonation" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    #withoutcache = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting


$Test = "eyJ0eXAiOiJkhB8qkLdlgA"

$Headers = @{
    'Authorization' = $Test
    "Content-Type"  = 'application/json'
}

Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/groups"
