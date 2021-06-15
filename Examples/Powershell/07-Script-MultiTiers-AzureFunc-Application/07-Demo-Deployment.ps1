<#
    # INTRO
    With the following demos (07,08) we will imagine we have a frontend app (in charge of authentication) and an Azure function which will represent our backend api. 
    - This backend API will first (07) take a request from an authenticated AND authorized user and execute a read all tenant user (application permission) with a credential flow
    - And then with 08 we will try the /me with the OBO flow. Again you have to be authorize to use it.
    - Finally, we will protect our backend from junk calls. Even if our azure function will 401, Azure still execute it. We will see how we can protect our functions with EasyAuth.
    Now let's imagine we want to create a frontend which will be in charge of managing the authentication part. Once logged in, this application
    should be able to contact our custom backend api. For this demo we will use an azure function to act as a custom API.


    # DEMO
        We will create 2 applications:
            - We will configure everything for the full demo 07/08/09 oneshoot
            - Both applications are confidential app. Even the frontend (without secret) to avoid ROPC/Device code flow.
            - We start by the backend one
                - No redirect(authentication), the API will validate the token. The authentication part is made by the frontend (Script/Desktop/SPA/MobileApp)
                - Confidential
                - Add secret
                - API Permissions: User.Read.All (application), User.ReadBasic.All (delegated), OIDC... for the backendend. For the frontend, we will use the backend
                - Expose API (for backend only):
                    - user_impersonation
                - Later we will enforce the user assignment to understand the why it's important.
            - Then we create a frontend app
                - Desktop in this case (can be mobile, SPA, Desktop, anything in fact...)
                - redirect to http://localhost
                - Api permission to backend user_impersonation
        Once both applications created, we will play to understand the interraction between the 2 apps and then we will create a real backend based on Azure functions. 
        Our function app we will composed of 2 functions, one which simulates an application permission (this demo), then a delegueted (08)

        You can find the application backend function app in the folder: 07-Script-MultiTiers-AzureFunc-Application/FunctionApp/run.ps1
        #>

throw "don't press F5"

#Use the previously created module
Import-Module 'C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1'
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

# To avoid surprises when you had generated a cache on another tenant :p
Clear-TokenCache

#Define variable for the demo
$TenantId = [Environment]::GetEnvironmentVariable('LabTenantId')

$token = 'Bearer {0}' -f (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token

#Declare your backend settings
$BackendSettings = @{
    displayName            = 'DemoBackend10'
    requiredResourceAccess = @(
        @{
            resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
            resourceAccess = @(
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -ScopeKeyword 'User.Read.All' -Application | Where-Object value -ne 'IdentityRiskyUser.Read.All' | ForEach-Object Id) # Role means application mails.readbasic
                    type = 'Role' # Other choice is scope = deleguated, Role means application delegation
                },
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -ScopeKeyword 'User.ReadBasic.All' -Deleguated | ForEach-Object Id) # Role means application mails.readbasic
                    type = 'Scope' # Other choice is scope = deleguated, Role means application delegation
                }
            )
        }
    )
    appRoles = @(
        @{
            allowedMemberTypes = @("User")                   # Can be user and/or application
            description        = "Grant access to application permission (list tenant users)"
            displayName        = "Write.Access"
            id                 = $((new-guid).guid) # has to be a unique value
            isEnabled          = "true"
            value              = "Write.Access"
        },
        @{
            allowedMemberTypes = @("User")                   # Can be user and/or application
            description        = "Grant access to delegated permission (/me)"
            displayName        = "Read.Access"
            id                 = $((new-guid).guid) # has to be a unique value
            isEnabled          = "true"
            value              = "Read.Access"
        },
        @{
            allowedMemberTypes = @("User")                   # Can be user and/or application
            description        = "Grant access to everything"
            displayName        = "Admin.Access"
            id                 = $((new-guid).guid) # has to be a unique value
            isEnabled          = "true"
            value              = "Admin.Access"
        }
    )
    api = @{
        oauth2PermissionScopes = @(
            @{
                'adminConsentDescription' = 'Allow this application to access the backend app on behalf of the signed-in user'
                'adminConsentDisplayName' = 'Access this application'
                'id'                      = $((New-Guid).guid) # has to be a unique value
                'isEnabled'               = 'true'
                'type'                    = 'User' #Define the consent policy Admin is the other value
                'userConsentDescription'  = 'Allow this application to access the backend app on your behalf'
                'userConsentDisplayName'  = 'Access this application'
                'value'                   = 'user_impersonation'
            }
        )
    }
}

# Just in case to make sure you work on the good tenant
Connect-AzAccount

$BackendSettingInJson = Convert-SettingsToJson -TemplateSettings $BackendSettings

#Build App registration
# Warning you may have error message if you have multiple Ids returned in the resourceAccess part
$BackendAppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $BackendSettingInJson -ConfidentialApp

# Create a secret automatically (valid 2 years)
$BackendAppRegistrationCreds = Add-AppRegistrationPassword -AccessToken $token -ObjectId $BackendAppRegistration.Id

# Create a SP from this App registration
$BackendServicePrincipal = New-ServicePrincipal -AccessToken $token -AppId $BackendAppRegistration.appId

# Create the IdentifierUris
Set-AppRegistrationIdentifierUris -AccessToken $token -ObjectId $BackendAppRegistration.Id -AppId $BackendAppRegistration.AppId

#Now we can create scopes of our custom api
Set-AppRegistrationoauth2PermissionScopes -AccessToken $token -ObjectId $BackendAppRegistration.Id -InputWithVariable $BackendSettingInJson

# Now we have a new backend app with an exposed api generated with random Id. We need to get this value to give it to the Public App !
# Get the scopeID Info
$ScopeInfo = Get-APIScopesInfo -AccessToken $token -AppId $BackendAppRegistration.AppId -Deleguated #Because our exposed api is in delegated permission

# Create the frontend app (Relace with your value for the displayname)

$FrontendSettings = @{
    displayName            = 'DemoFrontEnd010'
    publicClient           = @{
        redirectUris = @(
            'http://localhost'  # Array here can have multiple values
        )
    }
    requiredResourceAccess = @(
        @{
            resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
            resourceAccess = @(
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'openid' | ForEach-Object id) # OpenId permission Id
                    type = 'Scope'
                },
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'offline_access' | ForEach-Object id) # delegated offline-access permission Id
                    type = 'Scope'
                },
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'email' | ForEach-Object id) # delegated email permission Id
                    type = 'Scope'
                },
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'profile' | Where-Object value -NE 'OnPremisesPublishingProfiles.ReadWrite.All' | ForEach-Object id) # delegated profile permission Id. And yes 2 API has the word profile so I have to escape the wrong one.
                    type = 'Scope'
                }
            )
        },
        @{
            resourceAppId  = $BackendAppRegistration.AppId #$BackendAppRegistration.appId
            resourceAccess = @(
                @{
                    id   = $ScopeInfo.Id #$ScopeInfo.id
                    type = 'Scope'
                }
            )
        }
    )
}

$FrontendSettingsInJson = Convert-SettingsToJson -TemplateSettings $FrontendSettings -Verbose

#Build App registration
# Here even if it's a frontend app, we will make sure the app behave like a confidential app. In other words, we will only
# authorize the auth code flow because the implicit is disabled by default in my app creation process.
$FrontendAppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $FrontendSettingsInJson -ConfidentialApp

# Create a SP from this App registration
$FrontendServicePrincipal = New-ServicePrincipal -AccessToken $token -AppId $FrontendAppRegistration.appId

<#
#########
# Here make sure admin consent is applied to your backend app mail read and then continue

Current status:
    We've just created 2 AAD app for now:
    - Frontend:
        - No user assignment anyone from the tenant can authenticate to this app
        - API permission:
            - Consume the backend API through the scope: api://<backendAppId>/user_impersonation
            - OIDC stuff
        - As usual, V2 token enforced by the app creation process
    - Backend:
        - API Permission:
            - User.Read.All > Application (has to be admin consented)
            - User.ReadBasic.All > Delegated
        - Expose an API:
            - api://<backendAppId>/user_impersonation
        - App Roles:
            - Admin.access
            - Read.Access    ====> Those roles will be consummed by your backend api.
            - Write.Access
    
    IMPORTANT:
        Application Role is a concept which does not exist in modern auth world (to my knowledge), but only in the AAD Microsoft world.
        The idea is simple, you define role to an app (here the backend) and those role(s) assigned will be only available within this app.
        To assign a role, you just have to go in the enterprise app and under user & group add an account. It can be a user/group (though GUI) or a service principal through Console (Check role definition in the app).

    Let's now connect from our frontend to the backend in several steps. Let's have fun!
#>

# No one is assigned to the backend, and user assignment is not enforced let's see what happen:

# IMPORTANT FROM THERE DON'T USE A GLOBAL ADMIN ACCOUNT. If you do this you bypass everything and mess up your consents:

$Splatting = @{
    Resource     = $FrontendAppRegistration.AppId
    TenantId     = $TenantId
    Scope        = "api://$($BackendAppRegistration.AppId)/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

$AccessToken = New-AccessToken @Splatting

# You should see a consent page from DemoFrontEnd010 where the app request access to OIDC + DemoBackend10. Click accept and let's see what do we have in the token
Start "https://jwt.ms/#access_token=$AccessToken"   # Start "https://jwt.ms/#id_token=$IdToken"

<#
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg"
}.{
  "aud": "<BackendAppId>",
  "iss": "https://login.microsoftonline.com/<my tenant>/v2.0",                 # TODO Have to test with multi tenant app later
  "iat": 1623324781,
  "nbf": 1623324781,
  "exp": 1623328681,
  "aio": "ATQAy/8TAAAApA0uxY2gjJUKG2hjpiH4mXKVLTmds927BB9BkkbJEZ0kZmr/+ZDbPvfD8/CEBKIv",
  "azp": "<FrontendAppId>",
  "azpacr": "0",
  "name": "username",
  "oid": "cac074f6-2316-4c6a-a1bf-39f8e5459322",
  "preferred_username": "UPN",
  "rh": "0.AUcA2sqS4U2g_EyLkNFDOLLH7KxJ42JLPOxPuXd4jmowPJxHABA.",
  "scp": "user_impersonation",
  "sub": "WmSqO_tj9QVCqyW_UpUblJXT4MWbhN15a9rQfH1YfTw",
  "tid": "<my tenant>",
  "uti": "uStuWewd5EGlcyDqnfvYAA",
  "ver": "2.0"
}.[Signature]
#>

# Is it normal that AAD give us an access token? Let's do few tests to understand

# Let's declare our backend app api and see what the api will answer. If you want to play, you can find the code in the function app folder. 
$FunctionURI = 'https://funwithidentity2.azurewebsites.net/api/DemoBackendAPI-Application?code=X4XoUE4Q3xS5vXtfOMlklq/7jBc8uwg/UWV8jnA=='  # Replace by your function app URL here

# With an expired token
$Headers = @{
    'Authorization' = $("Bearer " + $AccessToken)
    'Content-Type'  = 'application/json'
}

$Params = @{
    Headers = $headers
    uri     = $FunctionURI
    Body    = $null
    method  = 'Get'
}

Invoke-RestMethod @Params

# Because I had to stop, my token is now expired
# Let's now use the refresh token and try

$Splatting = @{
    Resource     = $FrontendAppRegistration.AppId
    TenantId     = $TenantId
    Scope        = "api://$($BackendAppRegistration.AppId)/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

$AccessToken = New-AccessToken @Splatting

#In the verbose logs you should see
<#
...
VERBOSE: New-AccessToken - Cache context found
VERBOSE: New-AccessToken - Access token is expired
VERBOSE: New-AccessToken - Auth code flow selected
VERBOSE: New-AccessToken - Access token is expired and a refresh token is found in the cache, go use it
VERBOSE: New-RefreshToken - Begin function
...
#>

$Headers = @{
    'Authorization' = $("Bearer " + $AccessToken)
    'Content-Type'  = 'application/json'
}

$Params = @{
    Headers = $headers
    uri     = $FunctionURI
    Body    = $null
    method  = 'Get'
}

Invoke-RestMethod @Params

# And here you should get a 401 > Not authorized which is normal because we really want to protect our backend from anonymous requests. But why do we have an access token delivered?

# Make sure user requirement is mandatory now (in the Enterprise App)
# Just in case ;):  $token = 'Bearer {0}' -f (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token
Set-ServicePrincipalAppRoleAssignmentRequired -AccessToken $token -ObjectId $BackendServicePrincipal.id

#Clean the cache and start from scratch
Clear-TokenCache

# Now we will have an interraction login

$Splatting = @{
    Resource     = $FrontendAppRegistration.AppId
    TenantId     = $TenantId
    Scope        = "api://$($BackendAppRegistration.AppId)/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

$AccessToken = New-AccessToken @Splatting

# And now we have our proper error message and we can't get our access token. 

<#
IMPORTANT: If you want to protect your backend api and allow only authenticated and authorized users, make sure to enforce the user assignment.
At least now it make sense we've received an access token before even if no app roles were added to our user
#>

# Now let's add the role Write.Access (or admin) to our user and start again.

# We have to clear the cache again to avoid using empty caching.
Clear-TokenCache

# Let's retry to get an AT

$Splatting = @{
    Resource     = $FrontendAppRegistration.AppId
    TenantId     = $TenantId
    Scope        = "api://$($BackendAppRegistration.AppId)/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

$AccessToken = New-AccessToken @Splatting

# Now we're talking. Let's verify both our access and id token we've received
Start "https://jwt.ms/#access_token=$AccessToken"

# We can see now we have a new claim called roles in our access token
<#
 "rh": "0.AUcA2sqS4U2g_EyLkNFD...JxHABA.",
  "roles": [
    "Write.Access"
  ],
  "scp": "user_impersonation",
#>

# And no change in the Id token. The audience is still the frontend AppId, nothing has changed
$Cache = Get-Content -Path "C:\Users\francois.leon\.psoauth2\accessTokens.json"
Start "https://jwt.ms/#id_token=$(Get-Content -Path "C:\Users\francois.leon\.psoauth2\accessTokens.json" -Raw | ConvertFrom-Json | % idToken)"

# Let's now call our backend API!
$Headers = @{
    'Authorization' = $("Bearer " + $AccessToken)
    'Content-Type'  = 'application/json'
}

$Params = @{
    Headers = $headers
    uri     = $FunctionURI
    Body    = $null
    method  = 'Get'
}

Invoke-RestMethod @Params

# And now we get all our tenant users Bravo!

<#
Key takeaways:

    - Server to Server auth (from your backend API) has to be admin consented.
    - Protect your backend API with user enforcement and potentially app roles defined in the backend app registration
    - All tokens received have to be verified by your api. Caching can be used for bigger workload.
    - You api is also in charge of checking roles.
    - App roles add roles claims in the access token when you're authenticated (oidc from frontend). App roles are an AAD concept
    - Expose your backend api by using the expose API tile. Consume and authorize this scope by adding it to the front end api permission

#>