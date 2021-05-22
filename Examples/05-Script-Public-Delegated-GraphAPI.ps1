<#
    # INTRO
    This is where I really start to love modern authentication. Now instead of having to protect a secret, imagine you're already a global admin or someone who has already
    enough permission to do an action from the portal (we will take the same example as before). We can imagine a desktop app, a console app, or even a script you run with your
    identity instead of using the application permission. This is where the delegated scope permission comes into place.
    The goal here is to show that if you already have the permission to do an action? Why you would like to use an app and risk someone impersonate you and delete all MFA seetings
    in our case? Don't forget also that logging is "crappy" with a application permission, security team can't know that you behinf the clientId/secret you've used.

    Let's have fun! During this demo, I will authenticate using a GA account for simplicity. The cool thing is that this demo will help me to show you 2 new flows that my module
    is managing:
        - The device code flow (The one you use on your TV)
        - The auth code flow with PKCE

    And to add difficulty in this demo, we will also imagine that only specific global admins can do the job !

    # DEMO
        We will create:
        * An PUBLIC app registration account (Means all the tenant + guest accounts can log in)
            * As usual V2 endpoint enforced, single tenant enforced from my PSAADApplication module
        * Add a service principal on it (it becomes an app with an identity)
        * Require assignment on the service principal (This is where you will have to select who will be able to authenticate to your app)
        * Play with the app with  graph and then delete it.

    In this demo, I will use the beta graph api endpoint to list the authetication method a user have assigned. Then for fun,
    we wil remove one of them.

#>

throw "don't press F5"

#Use the previously created module
Import-Module 'C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1'
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

# To avoid surprises when you had generated a cache on another tenant :p
Clear-TokenCache

#Define variable for the demo
$TenantId = '9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20'

# IMPORTANT: Here compared to previous examples, we've changed the type to scope instead of role! Means delegated (on behalf of)
$Settings = @{
    displayName            = 'DemoPublicAppManageAuthMethods'
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
                    id   = 'b7887744-6746-4312-813d-72daeaee7e2d' # Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "UserAuthenticationMethod.ReadWrite.All" | % i
                    type = 'Scope' #Role means application, Scope means delegated. delegated and application does not have the same id for the same type.
                }
            )
        }
    )
}

$AppsettingsJson = Convert-SettingsToJson -TemplateSettings $Settings

# Generate an AT for the graph audience (check previous article for more info)
$token = 'Bearer {0}' -f (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token

# Compare to before, we will create a public app this time (default behaviour of the cmdlet)
$AppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $AppsettingsJson

# Let's create the service principal as usual
$ServicePrincipal = New-ServicePrincipal -AccessToken $token -AppId $AppRegistration.appId

# Let's now enforce the assignment. Only assigned people will be able to authenticate to the app.
#Make sure user requirement is mandatory now (in the Enterprise App)
Set-ServicePrincipalAppRoleAssignmentRequired -AccessToken $token -ObjectId $ServicePrincipal.id


#######################################
#    IMPORTANT
# Here you can open the portal, verify your app and grant admin consent to the app :)
##########################################

# Now let's have fun and list authentication method on a specific fresh user user where only the password has been defined
$UserObjectId = '39291a8b-0723-4468-9305-71dc3d542ddc'

<#
# Now we have to authenticate to this public app. Within Azure it exist multiple ways to authenticate to a public app:
    * Device code flow which is the one you use when you don't have a web browser on your machine. (IOT device/TV/...)
    * Auth code flow with PKCE or not. This is a way to go by default (with PKCE).
    * ROPC > run. Try to never use this flow, the user has to provide user/password during the flow dddoohhh. 
    * IWA > Integrated Windows Authenticate (not sure of the name). Pretty cool non interractive flow but your machine has be 
    domain join or enrolled in Intune.
#>

# Let's start to get our token with the device code flow (I will remove the verbose flag on this one, I will explain later why)
#Generate an Access Token
$Splatting = @{
    Resource       = $AppRegistration.AppId
    TenantId       = $TenantId
    Scope          = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All' # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri    = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    DeviceCodeFlow = $true
    verbose        = $true
    ErrorAction    = 'SilentlyContinue'

}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

$Headers = @{
    'Authorization' = $AccessToken
    'Content-Type'  = 'application/json'
}
# List method pour le user LX harcodé au dessus
Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$UserObjectId/authentication/methods" | Select-Object -ExpandProperty value

# And boom, you can case use Graph from a "semi interractive" (wait the next one we play with Refresh tokens and our module)
# WITHOUT ANY SECRETS!

#######################################
<#
    From there, instead of continuing the demo we did already, we will request another access token, but this time with the
    Auth code flow with PKCE!

    So what is Auth Code flow with PKCE?
        * The flow we should try to use by default with public/private app from console app, script, mobile, SPA, webapp ...
        * https://docs.microsoft.com/fr-fr/azure/active-directory/develop/v2-oauth2-auth-code-flow
        * This flow is interresting because:
            * better security. It's not just the web browser interraction. Once the code received, another request is made this time from a back channel call (not the browser).
    
    The way it's working (with PKCE, it's better :p):
    * You first contact the Authorize endpoint with a custom code you've created. This part is done in the browser.
    * Once AAD consider you've succeed to authentiate (conditionnal access/MFA/...) send you back a code (authorization code) AND store your previous code somewhere in his mind
    * Then you contact the token endpoint this time with the authorization code and a HASH (configure in a specific way (check RFC)). AAD "decode" your hash, check the auth code, happy days. 

    Let's see in action!
#>

$Splatting = @{
    Resource     = $AppRegistration.AppId
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All' # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
    ErrorAction  = 'SilentlyContinue'

}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

<#
    If we check what's going on:

VERBOSE: New-AccessToken - Begin function
VERBOSE: Get-HomePath - Begin function
VERBOSE: Get-HomePath - Windows detected
VERBOSE: Get-HomePath - End function
VERBOSE: Get-HomePath - Begin function                                                        # As before, it's just for caching stuff
VERBOSE: Get-HomePath - Windows detected
VERBOSE: Get-HomePath - End function
VERBOSE: Folder C:\Users\francois.leon\.psoauth2 already exist
VERBOSE: File C:\Users\francois.leon\.psoauth2\accessTokens.json already exist
VERBOSE: Get-TokenFromCache - Begin function
VERBOSE: Get-HomePath - Begin function
VERBOSE: Get-HomePath - Windows detected
VERBOSE: Get-HomePath - End function
VERBOSE: Get-TokenFromCache - Read cache file
VERBOSE: Get-TokenFromCache - Context detected                                            
VERBOSE: Get-TokenFromCache - End function
VERBOSE: New-AccessToken - Cache context found                                                # This line means a cache exist locally for this request with this scope
VERBOSE: New-AccessToken - No Refresh token found
VERBOSE: New-AccessToken - Access token is expired                                            # No refresh token detected (check next script), and Access token expired > Interractive way auth
VERBOSE: New-AccessToken - Auth code flow selected
VERBOSE: New-AccessToken - No cache found or Access token expired without available refresh token
VERBOSE: New-CodeVerifier - Begin function
VERBOSE: New-CodeVerifier - Random code generated
VERBOSE: New-CodeVerifier - End function
VERBOSE: New-AllowedCodeChallenge - Begin function
VERBOSE: New-CodeVerifier - Begin function
VERBOSE: New-CodeVerifier - Random code generated
VERBOSE: New-CodeVerifier - End function
VERBOSE: New-CodeChallenge - Begin function                                                     # Here it's a shortcut that I've done when I generate the verifier/challenge code.
VERBOSE: New-CodeChallenge - Create Hash from verifier                                          # Long sotry short, if I detect a "non supported char" (in my case), I regenerate everything until the script consider this is fine.
VERBOSE: New-CodeChallenge - End function
VERBOSE: New-AllowedCodeChallenge - None supported character detected, restart the function
VERBOSE: New-AllowedCodeChallenge - Begin function
VERBOSE: New-CodeVerifier - Begin function
VERBOSE: New-CodeVerifier - Random code generated
VERBOSE: New-CodeVerifier - End function
VERBOSE: New-CodeChallenge - Begin function
VERBOSE: New-CodeChallenge - Create Hash from verifier
VERBOSE: New-CodeChallenge - End function
VERBOSE: New-AllowedCodeChallenge - None supported character detected, restart the function
VERBOSE: New-AllowedCodeChallenge - Begin function
VERBOSE: New-CodeVerifier - Begin function
VERBOSE: New-CodeVerifier - Random code generated
VERBOSE: New-CodeVerifier - End function
VERBOSE: New-CodeChallenge - Begin function
VERBOSE: New-CodeChallenge - Create Hash from verifier
VERBOSE: New-CodeChallenge - End function
VERBOSE: New-AllowedCodeChallenge - None supported character detected, restart the function
VERBOSE: New-AllowedCodeChallenge - Begin function
VERBOSE: New-CodeVerifier - Begin function
VERBOSE: New-CodeVerifier - Random code generated
VERBOSE: New-CodeVerifier - End function
VERBOSE: New-CodeChallenge - Begin function
VERBOSE: New-CodeChallenge - Create Hash from verifier
VERBOSE: New-CodeChallenge - End function
VERBOSE: New-AllowedCodeChallenge - None supported character detected, restart the function
VERBOSE: New-AllowedCodeChallenge - Begin function
VERBOSE: New-CodeVerifier - Begin function
VERBOSE: New-CodeVerifier - Random code generated
VERBOSE: New-CodeVerifier - End function
VERBOSE: New-CodeChallenge - Begin function
VERBOSE: New-CodeChallenge - Create Hash from verifier
VERBOSE: New-CodeChallenge - End function
VERBOSE: New-AllowedCodeChallenge - None supported character detected, restart the function                         # Reminder, the code generated is a 43 chars long string :)
VERBOSE: New-AllowedCodeChallenge - Begin function
VERBOSE: New-CodeVerifier - Begin function
VERBOSE: New-CodeVerifier - Random code generated
VERBOSE: New-CodeVerifier - End function
VERBOSE: New-CodeChallenge - Begin function
VERBOSE: New-CodeChallenge - Create Hash from verifier                                                              # Now we know it will work, let's generate the hash
VERBOSE: New-CodeChallenge - End function
VERBOSE: New-AllowedCodeChallenge - End function
VERBOSE: New-AuthorizationCode - Begin function
VERBOSE: New-AuthorizationCode - Force TLS 1.2
VERBOSE: New-AuthorizationCode - Contact URL https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/oauth2/v2.0/authorize?response_type=code&client_id=1172bdc7-15c5-4f03-b922-2b912ea67898&redirect_uri=https%3a%2f%2flogin.microsoftonline.com%2fcommon%2foauth2%2fnativeclient&scope=https%3a%2f%2fgraph.microsoft.com%2fUserAuthenticationMethod.ReadWrite.All&prompt=select_account&state=rYR01wm03ad8QWRCibSauwTBFlq1GBRBE6OIm66x2V1&code_challenge=IybR7v5sQ8J3XSr33sJUHIQbVJLaPgpYV3JXEYlaSeY&code_challenge_method=S256
VERBOSE: New-AuthorizationCode - Open authentication web page
VERBOSE: New-AuthorizationCode - End function                                                                        # At this stage, the authentication is done (MFA)
VERBOSE: New-TokenFromAuthorizationCode - Begin function
VERBOSE: New-TokenFromAuthorizationCode - Contact Url https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/oauth2/v2.0/token
VERBOSE: New-TokenFromAuthorizationCode - No Secret provided create simple body                                      # Auth code flow can be used with cert/secret too if needed
VERBOSE: POST https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/oauth2/v2.0/token with 1271-byte payload
VERBOSE: received 2626-byte response of content type application/json
VERBOSE: Content encoding: utf-8
VERBOSE: New-TokenFromAuthorizationCode - End function
VERBOSE: New-AccessToken - Read the cache file
VERBOSE: New-AccessToken - Context found, update the context                                                         # Now we have our token, let store it locally to avoid hammering AAD.
#>

#And for fun, if we regenerate the token, now we will see in the logs it will go find it in the cache.

$AccessToken = New-AccessToken @Splatting

<#
...
VERBOSE: Get-TokenFromCache - Read cache file
VERBOSE: Get-TokenFromCache - Context detected
VERBOSE: Get-TokenFromCache - End function
VERBOSE: New-AccessToken - Cache context found
VERBOSE: New-AccessToken - No Refresh token found
VERBOSE: New-AccessToken - Auth code flow selected
VERBOSE: New-AccessToken - Access token not expired, go use it

happy days !
#>

# Let's go now try to get our user methods with this token!

$Headers = @{
    'Authorization' = $AccessToken
    'Content-Type'  = 'application/json'
}
# List method pour le user LX harcodé au dessus
Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/beta/users/$UserObjectId/authentication/methods" | Select-Object -ExpandProperty value

# And it's working :)

# Now for the final part, I will try to connect with another global admin account wich is not assigned the to service principal (Enterprise app).

$Splatting = @{
    Resource     =  "1172bdc7-15c5-4f03-b922-2b912ea67898" #$AppRegistration.AppId
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All' # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    WithoutCache = $true       # Here I make sure I won't look at the cache. You can also run clear-tokencache wich will nuke the cache file 
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

# And you should receive an error message like
<#
PS C:\Git\Private\psoauth2> $error.ErrorDetails.Message

{"error":"invalid_request","error_description":"AADSTS900144: The request body must contain the following parameter: 'code'.\r\nTrace ID: 32110889-4f0d-4f25-bd38-a99109585000\r\nCorrelation ID: dacc9c3d-1522-4002-93aa-4ba90963def6\r\nTimestamp: 2021-05-21 11:10:36Z","error_codes":[900144],"timestamp":"2021-05-21 11:10:36Z","trace_id":"32110889-4f0d-4f25-bd38-a99109585000","correlation_id":"dacc9c3d-1522-4002-93aa-4ba90963def6","error_uri":"https://login.microsoftonline.com/error?code=900144"}
PS C:\Git\Private\psoauth2> 

In Other words, AAD will authenticate you first, and then will verify is yes or no you're authorized to use the app

#>

# And as you can imagine, you won't receive any access token.

<#
Key takeaways:

    - Understand there is something else other than the "too famous" clientID/Secret flow for scripting.
    - Without passwords, you can't have any leak ;). Only people with access (based on the SP assignment) can access the app!
    - You can use several flows to authenticate to public application. If you have a web browser, auth code with PKCE is the solution (avoid using implicit too).
    - AAD logs will track that you did something and not an obscure service account!

Now that we can use our account directly, it's painful to have to autheticate eveytime! This is when OIDC and the offline scope 
come into place. See you into the next script

#>

#End of demo remove the app registration
Remove-AppRegistration -AccessToken $token -ObjectId $AppRegistration.Id