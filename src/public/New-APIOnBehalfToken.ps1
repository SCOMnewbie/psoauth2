function New-APIOnBehalfToken {
    <#
    .SYNOPSIS
    This function will try an On Behalf Of (server to server with incoming user access token > generate delegated access token).
    .DESCRIPTION
    This function will try an On Behalf Of (server to server with incoming user access token > generate delegated access token). This function is not added
    to new-accesstoken because I start to be tired and because it's not a end user function. You should use it from backend api only.
    .PARAMETER ClientId
        Specify the clientId of your application
    .PARAMETER TenantId
    Specify the TenantId of your application
    .PARAMETER Scope
    Specify the scope the intermediate request will request. By default ./default on Graph
    .PARAMETER Secret
    Specify the secret of your backend appId to do the request
    .PARAMETER Assertion
    Specify the access token of the incoming request.
    .EXAMPLE
    PS> $Splating @{
        ClientId = "<your backend appId>"
        TenantId = "<your TenantId>"
        Secret = <Generated app secret>
        Assertion = <caller access token>
    }
    
    New-APIOnBehalfToken @splating
    
    "will generate a delegated access token"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/07/06 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        - Add certificate
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ClientId,
        [Parameter(Mandatory = $true)]
        [guid]$TenantId,
        [Parameter(Mandatory = $false)]
        [string]$Scope = "https://graph.microsoft.com/.default",
        [parameter(Mandatory = $true, ParameterSetName = 'Secret')]
        [string]$Secret,
        [string]$Assertion # Access token received from the caller
    )

    Write-Verbose "New-APIOnBehalfToken - Begin function"

    # Force TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   
    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    $Params = @{
        Headers = $headers
        uri     = $Url
        Body    = $null
        method  = 'Post'
    }

    $BodyPayload = @{
        grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assertion = $Assertion
        requested_token_use = "on_behalf_of"
        client_id = $ClientID
        scope = $Scope
        client_secret = $secret
    }

    $Params.Body = $BodyPayload

    Write-Verbose 'New-APIOnBehalfToken - End function'

    Invoke-RestMethod @Params
}