<#
    # INTRO
    Now let's imagine we want to create a desktop app (a Powershell console for example) which will be in charge of managing the authentication part. Once logged in, this application
    should be able to contact our custom backend api. For this demo we will use an azure function to act as a custom API.


    # DEMO
        We will create 2 applications:
            - We start by the backend one
            - No redirect(authentication), the API will validate the token. The authentication part is made by the frontend (Script/Desktop/SPA/MobileApp)
            - Confidential
            - Add secret
            - API Permissions: Mail.ReadBasic
            - Expose API:
                - MyAPI.Mail.ReadBasic
            - Create a public App related to this backend API
                    * An PUBLIC app registration account (Means all the tenant + guest accounts can log in)
                        * As usual V2 endpoint enforced, single tenant enforced from my PSAADApplication module
                    * Add a service principal on it (it becomes an app with an identity)
                    * Require assignment on the service principal (This is where you will have to select who will be able to authenticate to your app)
                    * Play with the app with  graph and then delete it.

    In this demo, we will use an Azure fonction to act as a backend API

#>

#throw "don't press F5"

#Use the previously created module
Import-Module 'C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1'
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

# To avoid surprises when you had generated a cache on another tenant :p
Clear-TokenCache

#Define variable for the demo
$TenantId = '9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20'

$token = 'Bearer {0}' -f (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token

#Declare your backend settings
$BackendSettings = @{
    displayName            = 'DemoBackend01'
    requiredResourceAccess = @(
        @{
            resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
            resourceAccess = @(
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -ScopeKeyword 'Mail.ReadBasic.All' -Application | ForEach-Object Id) # Role means application mails.readbasic
                    type = 'Role' # Other choice is scope = deleguated, Role means application delegation
                }
            )
        }
    )
    api = @{
        oauth2PermissionScopes = @(
            @{
                'adminConsentDescription' = 'Allow this desktop application to access the backend app on behalf of the signed-in user'
                'adminConsentDisplayName' = 'Access this application'
                id                        = $((New-Guid).guid) # has to be a unique value
                'isEnabled'               = 'true'
                'type'                    = 'User' #Define the consent policy Admin is the other value
                'userConsentDescription'  = 'Allow this desktop application to access the backend app on your behalf'
                'userConsentDisplayName'  = 'Access this application'
                'value'                   = 'user_impersonation'
            }
        )
    }
}

#Connect-AzAccount

$BackendSettingInJson = Convert-SettingsToJson -TemplateSettings $BackendSettings

#Build App registration
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
# Get the scopeIDInfo
$ScopeInfo = Get-APIScopesInfo -AccessToken $token -AppId $BackendAppRegistration.AppId -Deleguated #Because our exposed api is in delegated permission

# Create the public app (Relace with your value for the displayname)

$DesktopSettings = @{
    displayName            = 'DemoFrontEnd01'
    publicClient           = @{
        redirectUris = @(
            'https://login.microsoftonline.com/common/oauth2/nativeclient'  # Array here can have multiple values
        )
    }
    requiredResourceAccess = @(
        @{
            resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
            resourceAccess = @(
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'openid' | ForEach-Object id) # OpenId permission Id #openId scope  To get a clientID https://docs.microsoft.com/fr-fr/azure/active-directory/develop/v2-permissions-and-consent#openid
                    type = 'Scope'  # Can be an Role  https://docs.microsoft.com/fr-fr/graph/api/resources/resourceaccess?view=graph-rest-1.0
                },
                @{
                    id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'offline_access' | ForEach-Object id) # delegated offline-access permission Id # offline_access scope > To get a Refresh token : https://docs.microsoft.com/fr-fr/azure/active-directory/develop/v2-permissions-and-consent#offline_access
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

#. .\src\Convert-SettingsToJson.ps1
$DesktopSettingsInJson = Convert-SettingsToJson -TemplateSettings $DesktopSettings -Verbose

#Build App registration
$FrontendAppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $DesktopSettingsInJson

# Create a SP from this App registration
$FrontendServicePrincipal = New-ServicePrincipal -AccessToken $token -AppId $FrontendAppRegistration.appId

# And make sure our app is not available for everyone in our tenant 
Set-ServicePrincipalAppRoleAssignmentRequired -AccessToken $token -ObjectId $FrontendServicePrincipal.Id

#########
# Here make sure admin consent is applied to your backend app mail read

$Splatting = @{
    Resource     = $FrontendAppRegistration.AppId
    TenantId     = $TenantId
    Scope        = "api://$($BackendAppRegistration.AppId)/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting
