<#
    # INTRO
    This is what we see everywhere on Internet where you will have to pass AppId/Secret.
        We will use a client credential flow to call graph. It's not what I recommend by default, but it's working.
            pros:
                * Simple to implement
                * No interraction required (server to server can't have interraction). No user consent
                * Your request will be executed under the app context, not the user (it's a pro and a cons)
            cons:
                * No user assignment. You have the appId & secret, you "impersonate" the application permission
                * hard to monitor / track on AAD sign-ins (subject to change I hope)
                * You have to store the secret somewhere
                * Your request will be executed under the app context, not the user (it's a pro and a cons)

    # DEMO
    We will create:
        * A confidential app (app registration) with the UserAuthenticationMethod.ReadWrite.All permission (application)
        * Add a secret on it
        * Play with the app and then delete it.

    In this demo, I will use the beta graph api endpoint (no V1 available at this date) to list the authetication methods a user have assigned. Then for fun,
    we wil remove one of them.

#>

throw "don't press F5"

#Use the previously created module
Import-Module "C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1"
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

#Define variable for the demo
$TenantId = '9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20'
$SubscriptionId = [Environment]::GetEnvironmentVariable('LabSubscriptionId')

#Define our app registration with only one permission "UserAuthenticationMethod.ReadWrite.All". 
# Like I see from time to time, don't add openId scope, this flow client credential flow does not generate Refresh tokens.
$Settings = @{
    displayName = "DemoManageUsersAuthMethods01"
    publicClient = @{
        redirectUris= @(
            "https://login.microsoftonline.com/common/oauth2/nativeclient"  # Array here can have multiple values
        )
    }
    requiredResourceAccess = @(
        @{
            resourceAppId = "00000003-0000-0000-c000-000000000000" #well know graph API
            resourceAccess = @(
                @{
                    id = "50483e42-d915-4231-9639-7fdb7fd190e5" # Get-APIScopesInfo -AccessToken $token -ScopeKeyword "methods" -Application to get the Id
                    type = "Role" #Role means application, Scope means delegated
                }
            )
        }
    )
}

$AppsettingsJson = Convert-SettingsToJson -TemplateSettings $Settings

# Generate an AT for the graph audience (check previous article for more info)
$token = "Bearer {0}" -f (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token

#Build App registration, we don't need a service principal because we won't role assign something on Azure. We just want to interract with Graph this time.
$AppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $AppsettingsJson -ConfidentialApp

# Create a secret automatically (valid 2 years)
$AppRegistrationCreds = Add-AppRegistrationPassword -AccessToken $token -ObjectId $AppRegistration.Id

#######################################
#    IMPORTANT
# Here you can open the portal, verify your app and grant admin consent to the app :)
##########################################

# Now let's have fun and list authentication method on a specific fresh user user where only the password has been defined
$UserObjectId = '39291a8b-0723-4468-9305-71dc3d542ddc'

#Generate an Access Token
$Splatting = @{
    Resource     = $AppRegistration.AppId
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/.default' # Here we have to specify default because no user interraction and client credential. So all scopes have to be admin consented for this app. Finaly we're running it in application mode.
    RedirectUri       = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    ClientCredentialFlow = $true
    Secret = $AppRegistrationCreds.secretText
    verbose      = $true 
}

$AccessToken = New-AccessToken @Splatting 

# We can see we received a token let's test it
$AccessToken.Substring(0,30)

$Headers = @{
    'Authorization' = $AccessToken
    "Content-Type"  = 'application/json'
}
# List method pour le user LX harcodé au dessus
Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$UserObjectId/authentication/methods" | select -ExpandProperty value

#Azure will reply this

<#
PS C:\Users\francois.leon> $LXMethods.value
@odata.type      : #microsoft.graph.passwordAuthenticationMethod
id               : 28c10230-6103-485e-b785-444c60001490
password         :
creationDateTime :
createdDateTime  :
#>

#Let's now open https://aka.ms/mfasetup with our user to define MFA methods. One done (you can verify on https://mysignins.microsoft.com/security-info) go back here.
# After adding both a phone number and configure the MS let's request the user auth methods again. This time the result is

<#

@odata.type    : #microsoft.graph.phoneAuthenticationMethod
id             : 3179e48a-750b-4751-897c-87b9720928f7
phoneNumber    : +224 606060606
phoneType      : mobile
smsSignInState : notAllowedByPolicy

@odata.type      : #microsoft.graph.passwordAuthenticationMethod
id               : 28c10230-6103-485e-b785-444c60001490
password         :
creationDateTime :
createdDateTime  :

@odata.type     : #microsoft.graph.microsoftAuthenticatorAuthenticationMethod
id              : 9fdf1057-9a82-4a73-96f2-8f725ca515fd
displayName     : ONEPLUS A5000
deviceTag       : SoftwareTokenActivated
phoneAppVersion : 6.2105.3004
createdDateTime :

#>

# Cool ! it means we can track auth methods from all users with this app instead of havin to use the old MSOL PS module. 
# Now we've created an app with the ReadWrite.all scopes, can we remove one of them and partially simulate a re-register button your can find into the portal?

# Know bug with the MS App: https://feedback.azure.com/forums/169401-azure-active-directory/suggestions/38407594-require-re-register-mfa-it-should-revoke-microsof

# Let's remove the phonemethod with the id 3179e48a-750b-4751-897c-87b9720928f7 (from previous command)
invoke-RestMethod -Method DELETE -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$UserObjectId/authentication/phoneMethods/3179e48a-750b-4751-897c-87b9720928f7"

# And reuse the previous command to list methods on the user
Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$UserObjectId/authentication/methods" | select -ExpandProperty value

<#

@odata.type      : #microsoft.graph.passwordAuthenticationMethod
id               : 28c10230-6103-485e-b785-444c60001490
password         :
creationDateTime :
createdDateTime  :

@odata.type     : #microsoft.graph.microsoftAuthenticatorAuthenticationMethod
id              : 9fdf1057-9a82-4a73-96f2-8f725ca515fd
displayName     : ONEPLUS A5000
deviceTag       : SoftwareTokenActivated
phoneAppVersion : 6.2105.3004
createdDateTime :

#>

# W00t !

<#
Summary:
    Here, because we can't do this action (manage auth methods) directly from CLI/PS we had to create a custom app registration. Now to interract with it, we've ued the client credential
    flow wich is the one we should use for server to server communication.
    I really want to start with what we find constantly on internet where you have to use a secret/cert with your app. 
    But do you think it's mandatory if you're a Global admin already? Let's find out in the following examples.
#>

#End of demo remove the app registration
Remove-AppRegistration -AccessToken $token -ObjectId $AppRegistration.Id