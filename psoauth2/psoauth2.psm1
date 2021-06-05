
class TokenExpiredException : System.Exception {
    TokenExpiredException ([string] $Message) : base($Message){
    }
}

class TokenVersionValidationFailedException : System.Exception {
    TokenVersionValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAudienceValidationFailedException : System.Exception {
    TokenAudienceValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenSignatureValidationFailedException : System.Exception {
    TokenSignatureValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAzpacrValidationFailedException : System.Exception {
    TokenAzpacrValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAzpValidationFailedException : System.Exception {
    TokenAzpValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenUnusableException : System.Exception {
    TokenUnusableException ([string] $Message) : base($Message){
    }
}

function Find-AzureX5c {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$Kid
    )

    Write-Verbose 'Find-AzureX5c - Begin function'
    $ErrorActionPreference = 'Stop'

    try{
        #According to https://docs.microsoft.com/fr-fr/azure/active-directory/develop/access-tokens#validating-tokens
        $uri = 'https://login.microsoftonline.com/common/.well-known/openid-configuration'
        $WellKnownInfo = Invoke-RestMethod -Uri $uri -Method GET
        $PublicAADKeysURI = $WellKnownInfo.jwks_uri
        Write-Verbose "Find-AzureX5c - AAD Keys URI: $PublicAADKeysURI"
        $AADPublicKeys = Invoke-RestMethod -Uri $PublicAADKeysURI -Method GET
        Write-Verbose "Find-AzureX5c - AAD Keys: $AADPublicKeys"

        #Let's see if your Kid (cert thumbprint) parameter exist in Azure. If empty means your token is a bad one. If exist, means we have to pick one of Azure pubkey.
        $UsedKey = $AADPublicKeys.keys.Kid -contains $Kid
        Write-Verbose "Find-AzureX5c - AAD Used Key: $UsedKey"

        if ($UsedKey) {
            #$X5c represent the public key that has been used to encrypt your token
            Write-Verbose "Find-AzureX5c - Get public key value"
            $x5c = $AADPublicKeys.keys | Where-Object { $_.Kid -eq $Kid } | Select-Object -ExpandProperty x5c
            Write-Verbose 'Find-AzureX5c - End function'
        }
        else {
            Write-Verbose 'Find-AzureX5c - End function'
            $x5c = $null
        }
        
        return $x5c
    }
    catch{
        New-CustomExceptionGenerator -SignatureValidationFailed
    }
}

function Get-HomePath {
    [CmdletBinding()]
    param()
    
    Write-Verbose 'Get-HomePath - Begin function'
    if($IsLinux){
        Write-Verbose 'Get-HomePath - Linux detected'
        $HOMEPath = [Environment]::GetEnvironmentVariable('HOME')
    }
    else{
        Write-Verbose 'Get-HomePath - Windows detected'
        $HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
    }

    Write-Verbose 'Get-HomePath - End function'
    return $HOMEPath
}

Function Get-TokenFromCache {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string]$Scope,
        [parameter(Mandatory)]
        [string]$resource
    )

    Write-Verbose 'Get-TokenFromCache - Begin function'

    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath

    #really psscriptAnalyzer ...
    $resource = $resource

    $FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"

    #Make sure $scope is formatted with the right format. This is how it's stored in the accesstokens.json file. Being sorted help for the search later.
    $scope = $scope -split " " | Sort-Object | Join-String  $_ -Separator " "

    if(Test-Path $FullPath){
        #File exist
        try{
            Write-Verbose 'Get-TokenFromCache - Read cache file'
            $Content = Get-Content $FullPath -Raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch{
            Write-Warning "File exist but seems corrupted, run clear-TokenCache"
            $Content = $null
        }

        #Here we should have a valid json file
        if($Content){
            #Search for couple resource / scope
            [array]$Context = $content | Where-Object{($_.scope -eq $Scope) -AND ($_.resource -eq $resource)}
            # Only one context should match. If not someone did something manually return $null
            if($Context.count -eq 1){
                Write-Verbose 'Get-TokenFromCache - Context detected'
                Write-Verbose 'Get-TokenFromCache - End function'
                return $Context
            }
            else{
                Write-Verbose "Too many context detected, run clear-TokenCache"
                Write-Verbose 'Get-TokenFromCache - End function'
                return $null
            }
        }
        else{
            Write-Verbose "File exist but seems corrupted, run clear-TokenCache"
            Write-Verbose 'Get-TokenFromCache - End function'
            return $null
        }
    }
    else{
        Write-Verbose "No Cache file exist locally"
        Write-Verbose 'Get-TokenFromCache - End function'
        return $null
    }
}

# The "problem" when when you generate a hash, some weird char can appear (+,\,/,...) and I had an issue to make it work in the URL call (even with URLencoded), so I've decided to Generate the pair
# Verifier/Code challenge until the code challenge has a "proper" format. It's a little hack to avoid wasting too much time for no real added value.
Function New-AllowedCodeChallenge {

    Write-Verbose 'New-AllowedCodeChallenge - Begin function'

    #Generate a verifier
    $verifier = New-CodeVerifier
    #Generate the associated Code Challenge
    $CodeChallenge = New-CodeChallenge -Verifier $verifier

    #Now let's validate if weird chars are in the string
    if($CodeChallenge -match '[a-zA-Z0-9]{43}'){

        Write-Verbose 'New-AllowedCodeChallenge - End function'

        [PSCustomObject]@{
            Verifier     = $verifier
            CodeChallenge = $CodeChallenge
        }
    }
    else{
        #If yes, re-execute the function
        Write-Verbose 'New-AllowedCodeChallenge - None supported character detected, restart the function'
        New-AllowedCodeChallenge
    }
}

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


<#
A Big thank you to Alex Asplund (https://adamtheautomator.com/powershell-graph-api/) who did the hardwork regarding certificate auth. I've copy/paste all his work.
#>
function New-ClientCredential {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ClientId,
        [Parameter(Mandatory = $true)]
        [guid]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [parameter(Mandatory = $true, ParameterSetName = 'Secret')]
        [string]$Secret,
        [parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateScript( {
                if ( -Not ($_ | Test-Path) ) {
                    throw 'Certificate does not exist'
                }
                return $true
            })]
        $CertificatePath  # Should be under the form "Cert:\CurrentUser\My\<cert thumbprint>"
    )

    Write-Verbose 'New-ClientCredential - Begin function'

    # Force TLS 1.2.
    Write-Verbose 'New-ClientCredential - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if ($CertificatePath) {
        Write-Verbose 'New-ClientCredential - Certificate has been specified'
        $Certificate = Get-Item $CertificatePath
        # Create base64 hash of certificate
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

        Write-Verbose 'New-ClientCredential - Build our custom JWT'
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials

        # Create JWT timestamp for expiration
        $StartDate = (Get-Date '1970-01-01T00:00:00Z' ).ToUniversalTime()
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(5)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

        # Create JWT header
        $JWTHeader = @{
            alg = 'RS256'
            typ = 'JWT'
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
        }

        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

            # Expiration timestamp
            exp = $JWTExpiration

            # Issuer = your application
            iss = $ClientId

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $ClientId
        }

        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

        $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

        # Join header and Payload with "." to create a valid (unsigned) JWT
        $null = $CustomJWT
        $CustomJWT = $EncodedHeader + '.' + $EncodedPayload

        # Get the private key object of your certificate
        $PrivateKey = $Certificate.PrivateKey

        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

        Write-Verbose 'New-ClientCredential - Sign our custom JWT'
        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($CustomJWT),$HashAlgorithm,$RSAPadding)
        ) -replace '\+','-' -replace '/','_' -replace '='

        # Join the signature to the JWT with "."
        $CustomJWT = $CustomJWT + '.' + $Signature

    }
    else{
        Write-Verbose 'New-ClientCredential - Secret has been specified'
    }

    Write-Verbose 'New-ClientCredential - Define headers'
    if($CustomJWT){
        $headers = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
            Authorization = "Bearer $CustomJWT"
        }
    }
    else{
        $headers = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
    }
    

    #Let hit the token endpoint for this second call
    Write-Verbose "New-ClientCredential - Contact Url https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Body    = $null
        method  = 'Post'
    }

    if($CertificatePath){
        Write-Verbose 'New-ClientCredential - Generate body with certificate'
        $BodyPayload = @{
            client_id = $Clientid
            client_assertion = $CustomJWT
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            scope = $Scope
            grant_type = "client_credentials"
        
        }
    }
    else{
        Write-Verbose 'New-ClientCredential - Generate body with secret'

        $BodyPayload = @{
            grant_type    = 'client_credentials'
            client_id     = $Clientid
            scope         = $Scope
            client_secret = $Secret
        }
    }
    
    $Params.Body = $BodyPayload

    Write-Verbose 'New-ClientCredential - End function'

    Invoke-RestMethod @Params
}


#Function to generate the code challenge. Based on RFC, it's a based64 encoded hash of the verifier (other function)
function New-CodeChallenge {

    Param (
        [string]
        $Verifier
    )
    Write-Verbose 'New-CodeChallenge - Begin function'
    Write-Verbose 'New-CodeChallenge - Create Hash from verifier'
    Write-Verbose 'New-CodeChallenge - End function'
    # code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Verifier))
    [System.Convert]::ToBase64String($hash).Replace('=', '')
}

<#
.SYNOPSIS
This function generate a random string with a specific number of characters.
.DESCRIPTION
This function generate a random string (Uppercase, LowerCase, Numbers) with a specific number of characters which by default is 43 characters long. This function respect the RFC https://tools.ietf.org/html/rfc7636#section-4.1
to generate a verifier.

.PARAMETER NumChar
Specify the number of characters of the generated string
.EXAMPLE
$New-CodeVerifier -NumChar 56
Will give you a 56 characters long random string
.NOTES
VERSION HISTORY
1.0 | 2021/01/07 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT

    Can improve the result to better respect the RFC
#>
function New-CodeVerifier {
    Param (
        [int] $NumChar = 43
    )
    Write-Verbose 'New-CodeVerifier - Begin function'
    Write-Verbose 'New-CodeVerifier - Random code generated'
    Write-Verbose 'New-CodeVerifier - End function'
    -join (((48..57) + (65..90) + (97..122)) * 80 | Get-Random -Count $NumChar | ForEach-Object { [char]$_ })
}

function New-CredentialCacheFolder {
    [cmdletbinding()]
    param()
    
    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath

    $FullPath = Join-Path $HOMEPath ".psoauth2"
    $ATCachePath = Join-Path $FullPath "accessTokens.json"

    if(Test-Path $FullPath){
        Write-Verbose "Folder $FullPath already exist"
    }
    else{
        Write-Verbose "Create folder $FullPath"
        $null = New-Item -ItemType Directory -Name ".psoauth2" -Path $HOMEPath -Force
    }

    if(Test-Path $ATCachePath){
        Write-Verbose "File $ATCachePath already exist"
    }
    else{
        Write-Verbose "Create file $ATCachePath"
        $null = New-Item -ItemType File -Name "accessTokens.json" -Path $FullPath -Force
    }
}

function New-CustomExceptionGenerator {
    param(
        [Parameter(Mandatory=$true,ParameterSetName='TokenExpired')]
        [switch]$TokenExpired,
        [Parameter(Mandatory=$true,ParameterSetName='VersionValidationFailed')]
        [switch]$VersionValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AudienceValidationFailed')]
        [switch]$AudienceValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='SignatureValidationFailed')]
        [switch]$SignatureValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AzpacrValidationFailed')]
        [switch]$AzpacrValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AzpValidationFailed')]
        [switch]$AzpValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='TokenUnusable')]
        [switch]$TokenUnusable
    )
    # This function is a wrapper to generate custom terminated exception from classes (look _CustomExceptions.ps1)
    $null = $MyError

    switch($PSBoundParameters.Keys){
        'TokenExpired'{
            $MyError = [TokenExpiredException]::new('Token provided is expired')
            break
        }
        'VersionValidationFailed'{
            $MyError = [TokenVersionValidationFailedException]::new('Token provided does not use the 2.0 endpoint version')
            break
        }
        'AudienceValidationFailed'{
            $MyError = [TokenAudienceValidationFailedException]::new('Token provided does target the right audience')
            break
        }
        'SignatureValidationFailed'{
            $MyError = [TokenSignatureValidationFailedException]::new('The signature of the provided token cannot be verified')
            break
        }
        'AzpacrValidationFailed'{
            $MyError = [TokenAzpacrValidationFailedException]::new('Token provided are not sent by a public application')
            break
        }
        'AzpValidationFailed'{
            $MyError = [TokenAzpValidationFailedException]::new('Token provided are not sent by a trusted application')
            break
        }
        'TokenUnusable'{
            $MyError = [TokenUnusableException]::new('Token provided are not usable')
            break
        }
    }

    throw $MyError
}

function New-DeviceCode {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    Write-Verbose 'New-DeviceCode - Begin function'

    # Force TLS 1.2.
    Write-Verbose 'New-DeviceCode - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    #Let hit the token endpoint for this second call
    Write-Verbose "New-DeviceCode - Contact Url https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
        Body    = $null
        method  = 'Post'
    }

    $BodyPayload = @{
        client_id     = $Clientid
        scope         = $Scope
    }

    $Params.Body = $BodyPayload
    
    $response  = Invoke-RestMethod @Params

    if(-not $response.device_code)
    {
        throw "Device Code Flow failed"
    }
    else{
        Write-host "$($response.message)"
    }

    Write-Verbose 'New-DeviceCode - Code received now waiting for user authentication to process'

    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Body    = $null
        method  = 'Post'
    }

    Write-Verbose 'New-DeviceCode - Define safety net to avoid infinite loop'

    $tokenResponse = $null
    $maxDate = (Get-Date).AddSeconds($response.expires_in)

    $BodyPayload = @{
        grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
        client_id = $Clientid
        device_code = $response.device_code
    }

    $Params.Body = $BodyPayload

    while (!$tokenResponse -and (Get-Date) -lt $maxDate)
    {
        $tokenResponse = Invoke-RestMethod @Params
        Write-Verbose 'New-DeviceCode - Give 5 more seconds to user to authenticate'
        start-sleep -Seconds 5
    }

    if($null -eq $tokenResponse){
        throw "New-DeviceCode - Token never received from AAD"
    }

    Write-Verbose 'New-DeviceCode - End function'

    return $tokenResponse
}

Function New-RefreshToken {
    [cmdletbinding()]
    param(
        [guid]$Clientid,
        [string]$RedirectUri,
        [string]$Scope,
        $TenantId,
        $RefreshToken,
        $secret
    )

    Write-Verbose 'New-RefreshToken - Begin function'

    # Force TLS 1.2.
    Write-Verbose 'New-RefreshToken - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }
    
    #Let hit the token endpoint for this second call
    Write-Verbose "New-RefreshToken - Contact Url https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Body    = $null
        method  = 'Post'
    }
    
    if ($secret) {

        Write-Verbose 'New-RefreshToken - Secret provided add it to the body'

        $BodyPayload = @{
            client_id     = $Clientid
            scope         = $Scope
            redirect_uri  = $RedirectUri
            grant_type    = 'refresh_token'
            refresh_token = $RefreshToken
            client_secret = $secret
        }
    }
    else {
        if ($RedirectUri) {

            Write-Verbose 'New-RefreshToken - RedirectURI provided add it to the body'

            $BodyPayload = @{
                client_id     = $Clientid
                scope         = $Scope
                redirect_uri  = $RedirectUri
                grant_type    = 'refresh_token'
                refresh_token = $RefreshToken
            }
        }
        else {
            
            Write-Verbose 'New-RefreshToken - Create simple body'

            $BodyPayload = @{
                client_id     = $Clientid
                scope         = $Scope
                grant_type    = 'refresh_token'
                refresh_token = $RefreshToken
            }
        }
    }

    $Params.Body = $BodyPayload
    
    Write-Verbose 'New-RefreshToken - End function'

    Invoke-RestMethod @Params
}

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

function New-X509FromX5c {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$x5c
    )

    $ErrorActionPreference = 'Stop'

    try {
        Write-Verbose "New-X509FromX5c - Begin function"
        $CertInBytes = [Convert]::FromBase64String($x5c)
        #Let's create a new instance of the certificate
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $CertInBytes)
        Write-Verbose "New-X509FromX5c - End function"
        return $cert
    }
    catch {
        New-CustomExceptionGenerator -SignatureValidationFailed
    }
}

function Test-JwtSignature {
<#
.SYNOPSIS
Tests cryptographic integrity of a JWT (JSON Web Token).
.DESCRIPTION
Verifies a digital signature of a JWT given a signing certificate. Assumes SHA-256 hashing algorithm. Optionally produces the original signed JSON payload.
.PARAMETER Jwt
Specifies the JWT. Mandatory string.
.PARAMETER Cert
Specifies the signing certificate. Mandatory X509Certificate2.
.INPUTS
You can pipe JWT as a string object to Test-Jwt.
.OUTPUTS
Boolean. Test-Jwt returns $true if the signature successfully verifies.
.EXAMPLE
PS Variable:> $jwt | Test-Jwt -cert $cert -Verbose
VERBOSE: Verifying JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbjEiOiJ2YWx1ZTEiLCJ0b2tlbjIiOiJ2YWx1ZTIifQ.Kd12ryF7Uuk9Y1UWsqdSk6cXNoYZBf9GBoqcEz7R5e4ve1Kyo0WmSr-q4XEjabcbaG0hHJyNGhLDMq6BaIm-hu8ehKgDkvLXP
Ch15j9AzabQB4vuvSXSWV3MQO7v4Ysm7_sGJQjrmpiwRoufFePcurc94aaHnMXx192KnJojwMR8mK-0_Q6TJ3bK8lTrQqqavnCW9vrKoWoXkqZD_4Qhv2T6vZF7sPkUrgsytgY21xABQuyFrrNLOI1g-EdBa7n1vIyeopM4n6_Uk-ttZp-U9wpi1cgg2p
RIWYV5ZT0AwZwy0QyPPx8zjh7EVRpgAKXDAg
VERBOSE: Using certificate with subject: CN=jwt_signing_test
True
.LINK
https://github.com/SP3269/posh-jwt
.LINK
https://jwt.io/
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$jwt,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    
    begin{
        Write-Verbose "Test-JwtSignature - Begin function"
        $ErrorActionPreference = 'Stop'
    }

    process{
        try {

            Write-Verbose "Test-JwtSignature - Verifying JWT: $jwt"
            Write-Verbose "Test-JwtSignature - Using certificate with subject: $($Cert.Subject)"
    
            $parts = $jwt.Split('.')
    
            $SHA256 = New-Object Security.Cryptography.SHA256Managed
            $computed = $SHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($parts[0] + "." + $parts[1])) # Computing SHA-256 hash of the JWT parts 1 and 2 - header and payload
        
            $signed = $parts[2].replace('-', '+').replace('_', '/') # Decoding Base64url to the original byte array
            $mod = $signed.Length % 4
            switch ($mod) {
                0 { $signed = $signed }
                1 { $signed = $signed.Substring(0, $signed.Length - 1) }
                2 { $signed = $signed + "==" }
                3 { $signed = $signed + "=" }
            }
            $bytes = [Convert]::FromBase64String($signed) # Conversion completed
    
            return $cert.PublicKey.Key.VerifyHash($computed, $bytes, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1) # Returns True if the hash verifies successfully
        }
        catch {
            New-CustomExceptionGenerator -SignatureValidationFailed
        }
    }

    end{
        Write-Verbose "Test-JwtSignature - End function"
    }
}

Function Clear-TokenCache {
    <#
    .SYNOPSIS
    This function will delete the cache file that the module uses to store credentials.
    .DESCRIPTION
    This function will delete the cache file that the module uses to store credentials.
    .EXAMPLE
    PS> Clear-TokenCache
    
    "will delete the local cache from the disk"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/05/05 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        - Delete a specific item instead of the whole file.
    #>
    param()
    
    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath
    $FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"

    if(Test-Path $FullPath){
        Remove-Item -Path $FullPath -Force
    }
}

function ConvertFrom-Jwt {

    <#
    Big thank you to both Darren Robinson (https://github.com/darrenjrobinson/JWTDetails/blob/master/JWTDetails/1.0.0/JWTDetails.psm1) and
    Mehrdad Mirreza in the comment of the blog post (https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell)
    I've used both article for inspiration because:
    Darren does not have header wich is a mandatory peace according to me and Mehrdad does not have signature which is also a mandatory piece.
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    Write-Verbose 'ConvertFrom-Jwt - Begin function'

    $ErrorActionPreference = 'Stop'

    try {

        # Validate as per https://tools.ietf.org/html/rfc7519
        # Access and ID tokens are fine, Refresh tokens will not work
        if (!$Token.Contains('.') -or !$Token.StartsWith('eyJ')) { Write-Error 'Invalid token' -ErrorAction Stop }

        # Extract header and payload
        $tokenheader, $tokenPayload, $tokensignature = $Token.Split('.').Replace('-', '+').Replace('_', '/')[0..2]

        # Fix padding as needed, keep adding '=' until string length modulus 4 reaches 0
        while ($tokenheader.Length % 4) { Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenheader += '=' }
        while ($tokenPayload.Length % 4) { Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenPayload += '=' }
        while ($tokenSignature.Length % 4) { Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenSignature += '=' }

        Write-Verbose "ConvertFrom-Jwt - Base64 encoded (padded) header:`n$tokenheader"
        Write-Verbose "ConvertFrom-Jwt - Base64 encoded (padded) payoad:`n$tokenPayload"
        Write-Verbose "ConvertFrom-Jwt - Base64 encoded (padded) payoad:`n$tokenSignature"

        # Convert header from Base64 encoded string to PSObject all at once
        $header = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json

        # Convert payload to string array
        $tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))

        # Convert from JSON to PSObject
        $tokobj = $tokenArray | ConvertFrom-Json

        # Convert Expiry time to PowerShell DateTime
        $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
        $timeZone = Get-TimeZone
        $utcTime = $orig.AddSeconds($tokobj.exp)
        $hoursOffset = $timeZone.GetUtcOffset($(Get-Date)).hours #Daylight saving needs to be calculated
        $localTime = $utcTime.AddHours($hoursOffset)     # Return local time,

        # Time to Expiry
        $timeToExpiry = ($localTime - (get-date))

        Write-Verbose 'ConvertFrom-Jwt - End function'
        [pscustomobject]@{
            Tokenheader         = $header
            TokenPayload        = $tokobj
            TokenSignature      = $tokenSignature
            TokenExpiryDateTime = $localTime
            TokentimeToExpiry   = $timeToExpiry
        }
    }
    catch {
        New-CustomExceptionGenerator -TokenUnusable
    }
}

Function New-AccessToken {
    <#
        .SYNOPSIS
        This function will help you to generate tokens (Access/Refresh/Id) with multiple OAUTH2 flows.
        .DESCRIPTION
        This function will help you to generate tokens (Access/Refresh/Id) with multiple OAUTH2 flows. This command is an abstraction of the complexity
        generated by the multiple flows. This function will check is a cache exist and use it except if you decide to use the withoucache parameter.
        In addition, you can decide to use this function in conjunction with secret.
        WARNING: This module is mainly for learning OAUTH/OIDC purpose. You should consider using the MSAL.PS module if you plan to do OAUTH in production.
        .PARAMETER Resource
        Specify the resource you try to reach (clientId)
        .PARAMETER Scope
        Specify the scope
        .PARAMETER RedirectUri
        Specify the RedirectUri of the application
        .PARAMETER TenantId
        Specify the tenantId (with guid)
        .PARAMETER Secret
        Specify the secret of the clientId
        .PARAMETER CertificatePath
        Specify the certificate to use for the authentication. Should come from a installed pfx under the form "Cert:\CurrentUser\My\<cert thumbprint>"
        .PARAMETER WithoutCache
        Specify you don't want to use the local cache
        .PARAMETER AuthCodeFlow
        Specify you want to authenticate using the AuthCodeFlow
        .PARAMETER DeviceCodeFlow
        Specify you want to authenticate using the DeviceCodeFlow
        .PARAMETER ClientCredentialFlow
        Specify you want to authenticate using the ClientCredentialFlow
        .EXAMPLE
        PS> $ClientId = 'd3537907-7a6f-54be-8a83-601d70feec72'
            $TenantId = 'e192cada-b64d-4cfc-8b90-d14338b2c7ec'

            $Splatting = @{
                Resource     = $ClientId
                TenantId     = $TenantId
                Scope        = 'https://graph.microsoft.com/.default openid offline_access'
                RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
                AuthCodeFlow = $true
                verbose      = $true
            }
        
        "will authenticate using the auth code flow."
        .EXAMPLE
        PS> $ClientId = 'd3537907-7a6f-54be-8a83-601d70feec72'
            $TenantId = 'e192cada-b64d-4cfc-8b90-d14338b2c7ec'

            $Splatting = @{
                Resource     = $ClientId
                TenantId     = $TenantId
                Scope        = 'https://graph.microsoft.com/.default openid offline_access'
                RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
                Secret       = 'mysecret'
                AuthCodeFlow = $true
                verbose      = $true
            }
        
        "will authenticate using the auth code flow."
        .NOTES
        VERSION HISTORY
        1.0 | 2021/05/05 | Francois LEON
            initial version
        POSSIBLE IMPROVEMENT
            - Add Certificate authentication
        #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [guid]$Resource,
        [parameter(Mandatory = $true)]
        [string]$Scope,
        [string]$RedirectUri,
        [parameter(Mandatory = $true)]
        [guid]$TenantId,
        [parameter(Mandatory, ParameterSetName = 'AuthCodeFlow')]
        [switch]$AuthCodeFlow,
        [switch]$WithoutCache,
        [parameter(ParameterSetName = 'AuthCodeFlow')]
        [parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowSecret')]
        [string]$Secret,
        [parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowCert')]
        $CertificatePath,  # Should be under the form "Cert:\CurrentUser\My\<cert thumbprint>"
        [parameter(Mandatory, ParameterSetName = 'DeviceCodeFlow')]
        [switch]$DeviceCodeFlow,
        [parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowSecret')]
        [parameter(Mandatory, ParameterSetName = 'ClientCredentialFlowCert')]
        [switch]$ClientCredentialFlow
    )
    # TenantId for a single tenant app or you can use common if it's a multi tenant app
    Write-Verbose 'New-AccessToken - Begin function'

    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath
    $FullPath = Join-Path -Path $HOMEPath -ChildPath '.psoauth2' -AdditionalChildPath 'accessTokens.json'

    #In case of an issue with the cache folder
    New-CredentialCacheFolder

    #Should return $null or a context
    #Because AAD does not return exactly what we've asked for scopes I have to change the way I write it in cache
    $InterrestingScopes = ($($scope.replace('https://graph.microsoft.com/', '')) -split ' ').where( { $_ -notin @('email', 'openid', 'profile', 'offline_access') }) | Join-String -Separator ' ' | Sort-Object
    $Cache = Get-TokenFromCache -Scope $InterrestingScopes -resource $Resource

    $NoRT = $false
    $IsATExpired = $false
    if ($Cache) {
        # Here means there is a context detected in the cache but we want to check if a RT exist
        Write-Verbose 'New-AccessToken - Cache context found'
        if ($null -eq $Cache.refreshToken) {
            Write-Verbose 'New-AccessToken - No Refresh token found'
            $NoRT = $true
        }

        #Check AT expiration
        $CurrentUTCDate = (Get-Date).ToUniversalTime()
        #Convert string to specific format for comparison
        $ContextCacheUTCDate = [datetime]::parseexact($($Cache.Expired_date_utc), 'yyyyMMddHHmmss', $null)
        #We want to know when the AT will expire. If it's less than a minute, renew it
        [int]$TimespanInSeconds = (New-TimeSpan -Start $CurrentUTCDate -End $ContextCacheUTCDate).TotalSeconds

        if ($TimespanInSeconds -lt 60) {
            Write-Verbose 'New-AccessToken - Access token is expired'
            $IsATExpired = $true
        }
    }

    if ($AuthCodeFlow) {
        Write-Verbose 'New-AccessToken - Auth code flow selected'
        #if #No cache or expired AT without RT
        if ($WithoutCache) {
            Write-Verbose 'New-AccessToken - Execute without cache has been selected (no cache used or generated)'
            # Here we just want to generate a token without any trace and without using the cache
            # FORCE INTERRACTIVE LOGIN
            #IMPORTANT HOW TO MANAGE S+CONFIDENTIAL APP

            #Generate a verifier for the state (just a random 43 char string)
            #State is a security to avoid Cross site request forgery (https://tools.ietf.org/html/rfc6749#section-10.12)
            $State = New-CodeVerifier
            # Generate a pair verifier/ Code challenge
            $CodeChallenge = New-AllowedCodeChallenge

            $Splatting = @{
                Clientid      = $Resource
                RedirectUri   = $RedirectUri
                TenantId      = $TenantId
                Scope         = $scope
                State         = $State
                CodeChallenge = $CodeChallenge.CodeChallenge
            }

            #Web view should pop. Enter your creds.
            $Code = New-AuthorizationCode @Splatting
            
            $Splatting = @{
                Clientid    = $Resource
                RedirectUri = $RedirectUri
                TenantId    = $TenantId
                Scope       = $scope
                verifier    = $CodeChallenge.Verifier
                AuthCode    = $Code.code
                Secret      = (($null -ne $secret) ? $secret : $null)
            }

            #Here we should have at least AT. If OIDC AT+ID + If offline AT+ID+RT
            $Tokens = New-TokenFromAuthorizationCode @Splatting
            return $tokens.access_token
        }
        elseif (($null -eq $cache) -OR (($IsATExpired -eq $true) -AND ($NoRT -eq $true))) {

            Write-Verbose 'New-AccessToken - No cache found or Access token expired without available refresh token'
            # FORCE INTERRACTIVE LOGIN

            #Generate a verifier for the state (just a random 43 char string)
            #State is a security to avoid Cross site request forgery (https://tools.ietf.org/html/rfc6749#section-10.12)
            $State = New-CodeVerifier
            # Generate a pair verifier/ Code challenge
            $CodeChallenge = New-AllowedCodeChallenge

            $Splatting = @{
                Clientid      = $Resource
                RedirectUri   = $RedirectUri
                TenantId      = $TenantId
                Scope         = $scope
                State         = $State
                CodeChallenge = $CodeChallenge.CodeChallenge
            }

            #Web view should pop. Enter your creds.
            $Code = New-AuthorizationCode @Splatting

            $Splatting = @{
                Clientid    = $Resource
                RedirectUri = $RedirectUri
                TenantId    = $TenantId
                Scope       = $scope
                verifier    = $CodeChallenge.Verifier
                AuthCode    = $Code.code
                Secret      = (($null -ne $secret) ? $secret : $null)
            }

            #Here we should have at least AT. If OIDC AT+ID + If offline AT+ID+RT
            $Tokens = New-TokenFromAuthorizationCode @Splatting

            #Access Token will be expired 1 hour later
            $Obj = [pscustomobject]@{
                TokenType        = 'Bearer'
                idToken          = $Tokens.id_token
                scope            = $InterrestingScopes
                resource         = $Resource
                refreshToken     = $Tokens.refresh_token
                accessToken      = $Tokens.access_token
                Expired_date_utc = (Get-Date).addhours(1).ToUniversalTime().ToString('yyyyMMddHHmmss')
                Secret           = (($null -ne $secret) ? $secret : $null)
            }
        
            #Read current cache issue if file does not exist (IMPORTANT)
            Write-Verbose 'New-AccessToken - Read the cache file'
            [array]$CurrentTokenCache = Get-Content $FullPath -Raw | ConvertFrom-Json
            if ($cache) {
                #A context has been detected update the file
                Write-Verbose 'New-AccessToken - Context found, update the context'
                $UpdatedTokenCache = $CurrentTokenCache | Where-Object { ($_.resource -ne $Resource) -AND ($_.scope -ne $InterrestingScopes) }
                $UpdatedTokenCache += $obj
                $UpdatedTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8
            }
            else {
                #No context add a new entry
                Write-Verbose 'New-AccessToken - No context found, add a new entry in the cache'
                $CurrentTokenCache += $obj
                $CurrentTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8
            }

            return $Tokens.access_token
        }
        else {
            # NON INTERRACTIVE PART
            #Here means: a context exist in cache with a RT
            if ($IsATExpired) {
                Write-Verbose 'New-AccessToken - Access token is expired and a refresh token is found in the cache, go use it'
                $refreshToken = $Cache.refreshToken
                $Splatting = @{
                    Clientid     = $Resource
                    RedirectUri  = $RedirectUri
                    TenantId     = $TenantId
                    Scope        = $scope
                    RefreshToken = $refreshToken
                    Secret       = (($null -ne $secret) ? $cache.secret : $null)
                }

                $Tokens = New-RefreshToken @Splatting

                #AT will be expired one hour later.
                $Obj = [pscustomobject]@{
                    TokenType        = 'Bearer'
                    idToken          = $Tokens.id_token
                    scope            = $InterrestingScopes
                    resource         = $Resource
                    refreshToken     = $Tokens.refresh_token
                    accessToken      = $Tokens.access_token
                    Expired_date_utc = (Get-Date).addhours(1).ToUniversalTime().ToString('yyyyMMddHHmmss')
                    Secret           = (($null -ne $secret) ? $cache.secret : $null)
                }

                #A context has been detected update the file
                Write-Verbose 'New-AccessToken - update the context in the cache'
                $UpdatedTokenCache = $CurrentTokenCache | Where-Object { ($_.resource -ne $Resource) -AND ($_.scope -ne $InterrestingScopes) }
                $UpdatedTokenCache += $obj
                $UpdatedTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8

                return $Tokens.access_token
            }
            else {
                # AT not expired yet, let's use the cache
                Write-Verbose 'New-AccessToken - Access token not expired, go use it'
                return $Cache.accessToken
            }
        }
    }
    elseif ($DeviceCodeFlow) {
        Write-Verbose 'New-AccessToken - Device code flow selected'
        # Full public flow. Try to add a secret and you will have an error
        if ($WithoutCache) {
            Write-Verbose 'New-AccessToken - Execute without cache has been selected (no cache used or generated)'
            $Splatting = @{
                Clientid = $Resource
                TenantId = $TenantId
                Scope    = $scope
            }

            #Here we should have at least AT. If OIDC AT+ID + If offline AT+ID+RT
            $Tokens = New-DeviceCode @Splatting
            return $Tokens.access_token
            
        }
        elseif (($null -eq $cache) -OR (($IsATExpired -eq $true) -AND ($NoRT -eq $true))) {
            Write-Verbose 'New-AccessToken - No cache found or Access token expired without available refresh token'
            #No cache found or expired or no RT, INTERRACTIVE LOGIN
            $Splatting = @{
                Clientid = $Resource
                TenantId = $TenantId
                Scope    = $scope
            }

            #Here we should have at least AT. If OIDC AT+ID + If offline AT+ID+RT
            $Tokens = New-DeviceCode @Splatting

            #Access Token will be expired 1 hour later
            $Obj = [pscustomobject]@{
                TokenType        = 'Bearer'
                idToken          = $Tokens.id_token
                scope            = $InterrestingScopes
                resource         = $Resource
                refreshToken     = $Tokens.refresh_token
                accessToken      = $Tokens.access_token
                Expired_date_utc = (Get-Date).addhours(1).ToUniversalTime().ToString('yyyyMMddHHmmss')
                Secret           = (($null -ne $secret) ? $secret : $null)
            }
        
            #Read current cache issue if file does not exist (IMPORTANT)
            [array]$CurrentTokenCache = Get-Content $FullPath -Raw | ConvertFrom-Json
            Write-Verbose 'New-AccessToken - Read the cache file'
            if ($cache) {
                #A context has been detected update the file
                Write-Verbose 'New-AccessToken - Context found, update the context'
                $UpdatedTokenCache = $CurrentTokenCache | Where-Object { ($_.resource -ne $Resource) -AND ($_.scope -ne $InterrestingScopes) }
                $UpdatedTokenCache += $obj
                $UpdatedTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8
            }
            else {
                #No context add a new entry
                Write-Verbose 'New-AccessToken - No context found, add new entry'
                $CurrentTokenCache += $obj
                $CurrentTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8
            }

            return $Tokens.access_token
        }
        else {
            # NON INTERRACTIVE PART
            #Here means: a context exist in cache with a RT
            if ($IsATExpired) {
                Write-Verbose 'New-AccessToken - Access token expired, use refresh token'
                $refreshToken = $Cache.refreshToken
                $Splatting = @{
                    Clientid     = $Resource
                    Scope        = $scope
                    RefreshToken = $refreshToken
                }

                $Tokens = New-RefreshToken @Splatting

                #AT will be expired one hour later.
                $Obj = [pscustomobject]@{
                    TokenType        = 'Bearer'
                    idToken          = $Tokens.id_token
                    scope            = $InterrestingScopes
                    resource         = $Resource
                    refreshToken     = $Tokens.refresh_token
                    accessToken      = $Tokens.access_token
                    Expired_date_utc = (Get-Date).addhours(1).ToUniversalTime().ToString('yyyyMMddHHmmss')
                    Secret           = (($null -ne $secret) ? $cache.secret : $null)
                }

                #A context has been detected update the file
                Write-Verbose 'New-AccessToken - Context found, update the context'
                $UpdatedTokenCache = $CurrentTokenCache | Where-Object { ($_.resource -ne $Resource) -AND ($_.scope -ne $InterrestingScopes) }
                $UpdatedTokenCache += $obj
                $UpdatedTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8

                return $Tokens.access_token
            }
            else {
                # AT not expired yet, let's use the cache
                Write-Verbose 'Access token (not expired) returned from local cache directly'
                return $Cache.accessToken
            }
        }
    }
    elseif ($ClientCredentialFlow) {
        Write-Verbose 'New-AccessToken - Credential flow selected'
        # This is a confidential flow. No Interractive flow is allowed in this flow. Refresh Token is not possible in this flow.
        if ($WithoutCache) {
            Write-Verbose 'New-AccessToken - Execute without cache has been selected (no cache used or generated)'
            if ($Secret) {
                $Splatting = @{
                    Clientid = $Resource
                    TenantId = $TenantId
                    Scope    = $scope
                    Secret   = $Secret
                }
            }
            else {
                # Means certificate instead of secret
                $Splatting = @{
                    Clientid        = $Resource
                    TenantId        = $TenantId
                    Scope           = $scope
                    CertificatePath = $CertificatePath
                }
            }
            

            $Tokens = New-ClientCredential @Splatting
            return $Tokens.access_token
        }
        elseif (($null -eq $cache) -OR ($IsATExpired -eq $true)) {
            Write-Verbose 'New-AccessToken - No cache found or Access token expired'
            #No cache found or expired
            if ($Secret) {
                $Splatting = @{
                    Clientid = $Resource
                    TenantId = $TenantId
                    Scope    = $scope
                    Secret   = $Secret
                }
            }
            else {
                # Means certificate instead of secret
                $Splatting = @{
                    Clientid        = $Resource
                    TenantId        = $TenantId
                    Scope           = $scope
                    CertificatePath = $CertificatePath
                }
            }

            $Tokens = New-ClientCredential @Splatting

            #Access Token will be expired 1 hour later
            if ($Secret) {
                $Obj = [pscustomobject]@{
                    TokenType        = 'Bearer'
                    idToken          = $null
                    scope            = $InterrestingScopes
                    resource         = $Resource
                    refreshToken     = $null
                    accessToken      = $Tokens.access_token
                    Expired_date_utc = (Get-Date).addhours(1).ToUniversalTime().ToString('yyyyMMddHHmmss')
                    Secret           = $Secret
                }
            }
            else {
                $Obj = [pscustomobject]@{
                    TokenType        = 'Bearer'
                    idToken          = $null
                    scope            = $InterrestingScopes
                    resource         = $Resource
                    refreshToken     = $null
                    accessToken      = $Tokens.access_token
                    Expired_date_utc = (Get-Date).addhours(1).ToUniversalTime().ToString('yyyyMMddHHmmss')
                    CertificatePath  = $CertificatePath
                }
            }
        
            #Read current cache issue if file does not exist (IMPORTANT)
            Write-Verbose 'New-AccessToken - Read local cache'
            [array]$CurrentTokenCache = Get-Content $FullPath -Raw | ConvertFrom-Json
            if ($cache) {
                #A context has been detected update the file
                Write-Verbose 'New-AccessToken - Context found, update context'
                $UpdatedTokenCache = $CurrentTokenCache | Where-Object { ($_.resource -ne $Resource) -AND ($_.scope -ne $InterrestingScopes) }
                $UpdatedTokenCache += $obj
                $UpdatedTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8
            }
            else {
                #No context add a new entry
                Write-Verbose 'New-AccessToken - No context found, add new entry'
                $CurrentTokenCache += $obj
                $CurrentTokenCache | ConvertTo-Json | Out-File -FilePath $FullPath -Encoding UTF8
            }

            return $Tokens.access_token
        }
        else {
            # AT not expired yet, let's use the cache
            Write-Verbose 'Access token (none expired) returned from local cache directly'
            return $Cache.accessToken
        }
    }
}


<#
A Big thank you to Alex Asplund (https://adamtheautomator.com/powershell-graph-api/) who did the hardwork regarding certificate auth. I've copy/paste all his work.
#>
function New-AzureFunctionClientCredential {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ClientId,
        [Parameter(Mandatory = $true)]
        [guid]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [parameter(Mandatory = $true, ParameterSetName = 'Secret')]
        [string]$Secret,
        [parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateScript( {
                if ( -Not ($_ | Test-Path) ) {
                    throw 'Certificate does not exist'
                }
                return $true
            })]
        $CertificatePath  # Should be under the form "Cert:\CurrentUser\My\<cert thumbprint>"
    )

    Write-Verbose 'New-ClientCredential - Begin function'

    # Force TLS 1.2.
    Write-Verbose 'New-ClientCredential - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if ($CertificatePath) {
        Write-Verbose 'New-ClientCredential - Certificate has been specified'
        $Certificate = Get-Item $CertificatePath
        # Create base64 hash of certificate
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

        Write-Verbose 'New-ClientCredential - Build our custom JWT'
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials

        # Create JWT timestamp for expiration
        $StartDate = (Get-Date '1970-01-01T00:00:00Z' ).ToUniversalTime()
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(5)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

        # Create JWT header
        $JWTHeader = @{
            alg = 'RS256'
            typ = 'JWT'
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
        }

        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

            # Expiration timestamp
            exp = $JWTExpiration

            # Issuer = your application
            iss = $ClientId

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $ClientId
        }

        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

        $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

        # Join header and Payload with "." to create a valid (unsigned) JWT
        $null = $CustomJWT
        $CustomJWT = $EncodedHeader + '.' + $EncodedPayload

        # Get the private key object of your certificate
        $PrivateKey = $Certificate.PrivateKey

        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

        Write-Verbose 'New-ClientCredential - Sign our custom JWT'
        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($CustomJWT),$HashAlgorithm,$RSAPadding)
        ) -replace '\+','-' -replace '/','_' -replace '='

        # Join the signature to the JWT with "."
        $CustomJWT = $CustomJWT + '.' + $Signature

    }
    else{
        Write-Verbose 'New-ClientCredential - Secret has been specified'
    }

    Write-Verbose 'New-ClientCredential - Define headers'
    if($CustomJWT){
        $headers = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
            Authorization = "Bearer $CustomJWT"
        }
    }
    else{
        $headers = @{
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
    }
    

    #Let hit the token endpoint for this second call
    Write-Verbose "New-ClientCredential - Contact Url https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Body    = $null
        method  = 'Post'
    }

    if($CertificatePath){
        Write-Verbose 'New-ClientCredential - Generate body with certificate'
        $BodyPayload = @{
            client_id = $Clientid
            client_assertion = $CustomJWT
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            scope = $Scope
            grant_type = "client_credentials"
        
        }
    }
    else{
        Write-Verbose 'New-ClientCredential - Generate body with secret'

        $BodyPayload = @{
            grant_type    = 'client_credentials'
            client_id     = $Clientid
            scope         = $Scope
            client_secret = $Secret
        }
    }
    
    $Params.Body = $BodyPayload

    Write-Verbose 'New-ClientCredential - End function'

    (Invoke-RestMethod @Params).access_token
}

<#
.SYNOPSIS
This function will revoke all refresh tokens of a specific users. According to MS docs, it can take several minutes to revoke all tokens.
.DESCRIPTION
This function will revoke all refresh tokens of a specific users. According to MS docs, it can take several minutes to revoke all tokens.
.PARAMETER ObjectId
Specify the objectId of the user.
.PARAMETER AccessToken
Specify the token to use to do the action.
.EXAMPLE

# Generate an AT for the graph audience
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token

Revoke-RefreshTokens -ObjectId "55eb8a9a-e9fc-4781-9c98-56dd3393d5f4" -AccessToken $Token

Will revoke all refresh token for the user with the ObjectId 55eb8a9a-e9fc-4781-9c98-56dd3393d5f4

.NOTES
VERSION HISTORY
1.0 | 2020/01/04 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    - add UPN as parameter instead of just objectId
.LINK
https://docs.microsoft.com/en-us/graph/api/user-revokesigninsessions
#>
function Revoke-RefreshTokens {
    <#
    .SYNOPSIS
    This function will revoke all refresh tokens from a specific user.
    .DESCRIPTION
    This function will revoke all refresh tokens from a specific user.
    .PARAMETER ObjectId
    Specify the objectId of a specific user
    .PARAMETER AccessToken
    Specify the access token to do the action
    .EXAMPLE
    PS> $token = "Bearer {0}" -f (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token
    PS> Revoke-RefreshTokens -ObjectId $ObjId -AccessToken $token
    
    "will revoke all RT from the user ObjId"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/05/05 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [guid] $ObjectId, #ObjectId of the user
        [parameter(Mandatory)]
        [string] $AccessToken
    )
    $Headers = @{
        'Authorization' = $("Bearer $AccessToken")
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/users/$ObjectId/revokeSignInSessions,"
        Body        = $null
        StatusCodeVariable = 'StatusCode'
        Method      = 'POST'
    }

    try{
        Invoke-RestMethod @Params
        if($statusCode -ne 204){
            throw "didn't receid the 204 status code"
        }
    }
    catch{
        $_.Exception
    }
}

function Test-AADToken {
    <#
    .SYNOPSIS
    This function will verify the token we provide is valid according to our criteria.
    .DESCRIPTION
    This function will verify the token we provide is valid according to our criteria. For our demo, we will validate the token is sign by AAD
    and the value inside the token respect our requirement. This is pretty agressive for the demo.
    .PARAMETER Aud
    Specify the audience of the request like https://graph.microsoft.com/ or api://myapi
    .PARAMETER Azp
    Specify the azp of the request. In our case, the clientId from where the request has been sent (desktop app).
    .PARAMETER Azpacr
    Specify the azpacr of the request. By default it's 0 for the demo.
    .PARAMETER Ver
    Specify the version of the AAD endpoint used to generate the token. In the demo it's 2.0
    .PARAMETER AccessToken
    Specify the access token to do the action
    .EXAMPLE
    PS> Test-AADToken -aud $audience -azp $azp -AccessToken $token
    
    "will validate if the token should be consummed by the api"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/05/05 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param(
        [Parameter(Mandatory = $true)][String]$AccessToken,
        [Parameter(Mandatory = $true)][String]$Aud,
        [Parameter(Mandatory = $true)][String]$azp,
        [String]$ver = '2.0'
    )

    begin{
        $ErrorActionPreference = 'Stop'
    }

    process{
        try{
            #Create an object from the Token received
            $DecodedToken = ConvertFrom-Jwt -Token $AccessToken
            #$CurrentDate = get-date -AsUTC  >> 7.1
            $CurrentDate = (get-date).ToUniversalTime()
            $iat = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds($DecodedToken.TokenPayload.iat))
            $nbf = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds($DecodedToken.TokenPayload.nbf))
            $exp = (Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds($DecodedToken.TokenPayload.exp))
    
            #Get the public key used to encrypt (multiple available and rotate from time to time)
            $x5c = Find-AzureX5c -Kid $($Decodedtoken.Tokenheader.kid)
    
            #Generate 509 certificate from bytes[]
            $cert = New-X509FromX5c -x5c $x5c
    
            #Validate signature from token received ($true is good)
            $null = Test-JwtSignature -jwt $AccessToken -Cert $cert
    
            #Is Token expired?
            if ((New-TimeSpan -Start $CurrentDate -End $exp).TotalSeconds -lt 0) {
                New-CustomExceptionGenerator -TokenExpired
            }

            if ((New-TimeSpan -Start $CurrentDate -End $iat).TotalSeconds -gt 0) {
                New-CustomExceptionGenerator -$TokenUnusable
            }

            if ((New-TimeSpan -Start $CurrentDate -End $nbf).TotalSeconds -gt 0) {
                New-CustomExceptionGenerator -$TokenUnusable
            }

            # ver before aud because we will check only the id, not the uniqueURI
            if ($Decodedtoken.TokenPayload.ver -ne $ver) {
                New-CustomExceptionGenerator -VersionValidationFailed
            }
    
            if ($Decodedtoken.TokenPayload.aud -ne $Aud) {
                New-CustomExceptionGenerator -AudienceValidationFailed
            }

            if ($Decodedtoken.TokenPayload.azp -ne $azp) {
                New-CustomExceptionGenerator -AzpValidationFailed
            }
        }
        catch [TokenUnusableException]{
            Write-Error "Unusabled token"
        }
        catch [TokenSignatureValidationFailedException]{
            Write-Error "Unable to validate the signature"
        }

        return $true
    }
}

Export-ModuleMember -Function 'Clear-TokenCache', 'ConvertFrom-Jwt', 'New-AccessToken', 'New-AzureFunctionClientCredential', 'Revoke-RefreshTokens', 'Test-AADToken'
