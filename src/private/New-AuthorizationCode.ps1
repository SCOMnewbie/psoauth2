<#
.SYNOPSIS
This function helps you to get a required code to complete an authorization code flow with a S256 challenge method.
.DESCRIPTION
https://docs.microsoft.com/fr-fr/azure/active-directory/develop/v2-oauth2-auth-code-flow
WARNING: The Authorization Code flow is an interractive flow which can manage both confidential and public application.
By default Powershell is not capable of managing a webview, which is a mandatory piece in this flow, which is why we have to play with System.Windows.Forms. The goal of this webview is to listen.
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
#Generate a verifier
$Verifier = New-CodeVerifier
# Generate a code challenge from the verifier
$CodeChallenge = New-CodeChallendge -Verifier $Verifier

# TenantId for a single tenant app or you can use common if it's a multi tenant app
#State is a security to avoid Cross site request forgery (https://tools.ietf.org/html/rfc6749#section-10.12)
#RedirectUri = native because it's a public app. If we switch to web, a secret will be required (next example)
$Splatting = @{
    Clientid = "c203ef22-c718-4cef-a300-dc29aafd580e"
    RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    TenantId = "6ff98e97-6f1f-433c-8a70-09ab01807ea9"
    Scope = "openid offline_access user.read"
    State = New-CodeVerifier
    CodeChallenge = $CodeChallenge
}

$Code = Get-AuthorizationCode @Splatting
Will give you both an Id and an access token for the requested scopes for an application exposed to multiple tenants.
.NOTES
VERSION HISTORY
1.0 | 2020/10/29 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    -
#>
function New-AuthorizationCode {
    [cmdletbinding()]
    param(
        [guid]$Clientid,
        [string]$RedirectUri,
        [string]$Scope,
        [ValidatePattern('^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$|^common\/{0,1}$')]
        $TenantId,
        [ValidateSet('select_account','none')]
        [string]$Prompt = "select_account",
        $State,
        $CodeChallenge
    )

    Write-Verbose 'New-AuthorizationCode - Begin function'

    # Force TLS 1.2.
    Write-Verbose 'New-AuthorizationCode - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Add-Type -AssemblyName System.Windows.Forms

    #Redirect URI and Scope require to be encoded
    #To be V5
    if((Get-Host).Version.Major -eq 5){
        # Load system.web asembly
        Add-Type -AssemblyName System.Web
    }
    $RedirectUriEncoded = [System.Web.HttpUtility]::UrlEncode($RedirectUri)
    $ScopeEncoded = [System.Web.HttpUtility]::UrlEncode($Scope)
    $CodeChallengeEncoded = [System.Web.HttpUtility]::UrlEncode($CodeChallenge)

    #Let's start by hitting the authorize endpoint
    #Response_type = code
    $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?response_type=code&client_id=$ClientID&redirect_uri=$RedirectUriEncoded&scope=$ScopeEncoded&prompt=$Prompt&state=$State&code_challenge=$CodeChallengeEncoded&code_challenge_method=S256"

    Write-Verbose "New-AuthorizationCode - Contact URL $Url"

    $Form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = 440; Height = 640 }
    $Web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = 420; Height = 600; Url = ($url -f ($Scope -join "%20")) }
    $DocComp = {
        $Global:uri = $web.Url.AbsoluteUri
        if ($Global:uri -match "error=[^&]*|code=[^&]*") { $form.Close() }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown( { $form.Activate() })
    $form.ShowDialog() | Out-Null

    Write-Verbose 'New-AuthorizationCode - Open authentication web page'

    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)

    Write-Verbose 'New-AuthorizationCode - End function'

    if ($queryOutput['state'] -eq $State) {
        [PSCustomObject]@{
            Code          = $queryOutput['code']
            session_state = $queryOutput['session_state']
            State         = $queryOutput['state']
        }
    }
    else {
        Write-Error "Wrong answer received, the state wasn't the same code"
    }
}