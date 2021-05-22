<#
.SYNOPSIS
This function helps you to get a required code to complete an authorization code flow with a S256 challenge method.
.DESCRIPTION
https://docs.microsoft.com/fr-fr/azure/active-directory/develop/v2-oauth2-auth-code-flow
WARNING: The Authorization Code flow is an interractive flow which can manage both confidential and public application.
By default Powershell is not capable of managing a webview, which is a mandatory piece in this flow, which is why we have to play with System.Windows.Forms. The goal of this webview is to listen
what Azure AD will reply to you (the code) once the authentication is done by the Identity Provider (login, password, MFA, ...).
Why this script? Because in conjunction with MSAL.PS, we will be able to receive both an Id and and Access token for the requested scopes. The Id token help you to manage authorization later in your app.
IMPORTANT: This script is working with V2 Microsoft Identity endpoint only (single tenant, Multiple tenants, Work or school and Microsoft Account).
.PARAMETER Clientid
Specify the Clientid of your confidential app.
.PARAMETER RedirectUri
Specify the RedirectUri of your backend application.
.PARAMETER Scope
Specify the Scope of your application. Default values are optional, but it's a good starting point for later usage.
.PARAMETER TenantId
Specify the TenantId
.PARAMETER Prompt
Specify the Prompt behavior
.EXAMPLE
#This cmdlet comes after Get-AuthorizationCode, a verifier and a code has to be received

# TenantId for a single tenant app or you can use common if it's a multi tenant app
#State is a security to avoid Cross site request forgery (https://tools.ietf.org/html/rfc6749#section-10.12)
#RedirectUri = native because it's a public app. If we switch to web, a secret will be required (next example)
$Splatting = @{
    Clientid = "b2f20e9d-e3a4-4676-b6aa-7dfe6a92dd61"
    RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    TenantId = "e192cada-a04d-4cfc-8b90-d14338b2c7ec"
    Scope = "openid offline_access user.read"
    verifier = $Verifier
    AuthCode = $Code.code
}

$Tokens = Get-TokenFromAuthorizationCode @Splatting
Will give you both an Id and an access token for the requested scopes for an application exposed to multiple tenants.
.NOTES
VERSION HISTORY
1.0 | 2020/10/29 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    -
#>
Function New-TokenFromAuthorizationCode {
    [cmdletbinding()]
    param(
        [guid]$Clientid,
        [string]$RedirectUri,
        [string]$Scope,
        [ValidatePattern('^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$|^common\/{0,1}$')]
        $TenantId,
        $verifier,
        $AuthCode,
        $secret
    )

    Write-Verbose "New-TokenFromAuthorizationCode - Begin function"

    # Force TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    #Let hit the token endpoint for this second call
    Write-Verbose "New-TokenFromAuthorizationCode - Contact Url https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Body    = $null
        method  = 'Post'
    }

    if($secret){

        Write-Verbose "New-TokenFromAuthorizationCode - Secret provided add it to the body"

        $BodyPayload = @{
            client_id     = $Clientid
            scope         = $Scope
            redirect_uri  = $RedirectUri
            grant_type    = "authorization_code"
            code_verifier = $verifier
            code          = $AuthCode
            client_secret = $secret
        }
    }
    else{

        Write-Verbose "New-TokenFromAuthorizationCode - No Secret provided create simple body"

        $BodyPayload = @{
            client_id     = $Clientid
            scope         = $Scope
            redirect_uri  = $RedirectUri
            grant_type    = "authorization_code"
            code_verifier = $verifier
            code          = $AuthCode
        }
    }

    $Params.Body = $BodyPayload

    $Tokens = Invoke-RestMethod @Params
    #$Tokens | Add-Member -MemberType ScriptProperty -Name expired_date_utc -Value {(get-date).AddHours(1).ToUniversalTime()}

    Write-Verbose "New-TokenFromAuthorizationCode - End function"

    return $Tokens
}