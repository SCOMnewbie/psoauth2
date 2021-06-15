<#
    # INTRO
    We will do the same thing has we did with 03-Script-ConfApp-Secret-Application-GraphAPI but we will explain why using certificate is better
    in most cases than using secrets. In addition, it will give us the opportunity to play with the client credential flow with certificate !

    # prerequisites

    * A keyvault
    * A resource group

    # DEMO
        We will create:
        * A an app registration account
        * Generate a self signed cert into our KV
        * Upload the public key to our app
        * Download the private key and install it on our machine. (Or store it with the PEM example)
        * Explain how client credential works with certificate
        * Play with the app with  graph and then delete it.

    In this demo, I will use the beta graph api endpoint to list the authetication method a user have assigned. Then for fun,
    we wil remove one of them.

#>

throw "don't press F5"

#Use the previously created module
Import-Module "C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1"
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

# To avoid surprises when you had generated a cache on another tenant :p
Clear-TokenCache

#Define variable for the demo
$TenantId = [Environment]::GetEnvironmentVariable('LabTenantId')
$SubscriptionId = [Environment]::GetEnvironmentVariable('LabSubscriptionId')
[string]$RGName = 'FunWithIdentity'
$VaultName = 'Funwithidentity'
$CertName = 'DemoManageUsersAuthMethodsWithCerts'

#Define our app registration with only one permission "UserAuthenticationMethod.ReadWrite.All". 
# Like I see from time to time, don't add openId scope, this flow client credential flow does not generate Refresh tokens.
$Settings = @{
    displayName = "DemoManageUsersAuthMethodsWithCerts"
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

# We won't add too many comments here. Go to 02-Script-ConfApp-Cert-AzureAssignment if you want more details.
$CertFormatChoice = 'application/x-pkcs12' #PFX
$Extension = 'pfx'

$DefaultPolicy = @"
{
    "issuerParameters": {
      "certificateTransparency": null,
      "name": "Self"
    },
    "keyProperties": {
      "curve": null,
      "exportable": true,
      "keySize": 2048,
      "keyType": "RSA",
      "reuseKey": true
    },
    "lifetimeActions": [
      {
        "action": {
          "actionType": "AutoRenew"
        },
        "trigger": {
          "daysBeforeExpiry": 90
        }
      }
    ],
    "secretProperties": {
      "contentType": `"$CertFormatChoice`"
    },
    "x509CertificateProperties": {
      "keyUsage": [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyEncipherment",
        "keyAgreement",
        "keyCertSign"
      ],
      "subject": `"CN=$CertName`",
      "validityInMonths": 12
    }
  }
"@

$DefaultPolicy | Out-File DefaultCertPolicy.json -Encoding utf8 -Force
az keyvault certificate create --vault-name $VaultName -n $CertName --policy "`@DefaultCertPolicy.json" --debug
$Cer = (az keyvault certificate show --vault-name $VaultName -n $CertName | ConvertFrom-Json).cer
az ad app credential reset --id $AppRegistration.appId --cert $Cer --append
Remove-Item "$env:temp\mycert.$Extension" -Force
az keyvault secret download --vault-name $VaultName --name $CertName --file "$env:temp\mycert.$Extension"
Start-Process "$env:temp\mycert.$Extension"

# why not
Remove-Item "$env:temp\mycert.$Extension" -Force

# Get cert thumbprint
$Thumbprint = Get-Item 'Cert:\CurrentUser\My\*' | Where-Object subject -EQ "CN=$CertName" | Select-Object -ExpandProperty Thumbprint

$Splatting = @{
    Resource             = $AppRegistration.appId
    TenantId             = $TenantId
    Scope                = 'https://graph.microsoft.com/.default' # Because our application scope is application (not delegated). I really hate this naming convention application Vs delegated...
    ClientCredentialFlow = $true
    CertificatePath      = "Cert:\CurrentUser\My\$Thumbprint"
    verbose              = $true
}

$AccessToken = New-AccessToken @Splatting
#List the first 30 characters
$AccessToken.Substring(0,30)

# Now here the new part, we don't really care about the rest, it will work the same way as before. Look at the Verbose logs:

<#
VERBOSE: New-AccessToken - Begin function                                      #
VERBOSE: Get-HomePath - Begin function                                         #
VERBOSE: Get-HomePath - Windows detected                                       #
VERBOSE: Get-HomePath - End function                                           #  
VERBOSE: Get-HomePath - Begin function                                         # ==> We just verify our cache folder
VERBOSE: Get-HomePath - Windows detected                                       #
VERBOSE: Get-HomePath - End function                                           #
VERBOSE: Folder C:\Users\francois.leon\.psoauth2 already exist                 #
VERBOSE: Create file C:\Users\francois.leon\.psoauth2\accessTokens.json        #
VERBOSE: Get-TokenFromCache - Begin function
VERBOSE: Get-HomePath - Begin function
VERBOSE: Get-HomePath - Windows detected
VERBOSE: Get-HomePath - End function
VERBOSE: Get-TokenFromCache - Read cache file                                  # Here we just verify if there is a local cache for this specific scope already
VERBOSE: Get-TokenFromCache - End function
VERBOSE: New-AccessToken - Credential flow selected
VERBOSE: New-AccessToken - No cache found or Access token expired  
VERBOSE: New-ClientCredential - Begin function
VERBOSE: New-ClientCredential - Force TLS 1.2
VERBOSE: New-ClientCredential - Certificate has been specified                # This is where the fun start with client credential and certs
VERBOSE: New-ClientCredential - Build our custom JWT                          # You have to build your own JWT (according to the docs)
VERBOSE: New-ClientCredential - Sign our custom JWT                           # And sign it with your private key. This is called assertion.
VERBOSE: New-ClientCredential - Define headers
VERBOSE: New-ClientCredential - Contact Url https://login.microsoftonline.com/e192cada-a04d-4cfc-8b90-d14338b2c7ec/oauth2/v2.0/token
VERBOSE: New-ClientCredential - Generate body with certificate
VERBOSE: New-ClientCredential - End function
VERBOSE: POST https://login.microsoftonline.com/e192cada-a04d-4cfc-8b90-d14338b2c7ec/oauth2/v2.0/token with 1090-byte payload
VERBOSE: received 1549-byte response of content type application/json
VERBOSE: Content encoding: utf-8
VERBOSE: New-AccessToken - Read local cache
VERBOSE: New-AccessToken - No context found, add new entry
#>

<#
    What does it means? The only thing you can commit is basicaly your certificate thumbprint install locally on your machine. In other words,
    we don't really care :D. Then on the wire, it's simply a sign document wich is sign with your private key, and AAD on his side with the 
    app registration simply decode the token with the public key. If AAD has his information it looking for (predifined info), Happy days!
#>

# Now the rest of the demo is what we've done with the previous demo.

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
    With this demo, it's according to me a little bit better of what you can find on Internet everywhere with the secret 
    But do you think it's mandatory if you're a Global admin already? Let's find out in the next example.
#>

#End of demo remove the app registration
Remove-AppRegistration -AccessToken $token -ObjectId $AppRegistration.Id