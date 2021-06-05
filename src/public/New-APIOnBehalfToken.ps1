function New-APIOnBehalfToken {
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
        $CertificatePath,  # Should be under the form "Cert:\CurrentUser\My\<cert thumbprint>"
        [string]$Assertion # Access toekn received from the caller
    )

    Write-Verbose "New-APIOnBehalfToken - Begin function"

    # Force TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
   
    #$Assertion = $Assertion.replace("Bearer ","") # Just in case
    #$Assertion = [System.Web.HttpUtility]::UrlEncode($Assertion)
    #$Scope = [System.Web.HttpUtility]::UrlEncode($Scope)

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    #TO DO Decotek token received to eventually drop it

    if($secret){
        $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    }
    else{
        #Certificate path
        Write-Error "Not managed yet"
    }
    
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

$ClientId = "825388eb-37d5-4b0d-8e09-05ab16c52492"
$TenantId = '9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20'
$Password = "o~0-wQ8w_ppCN8z"
$Scope = "https://graph.microsoft.com/.default"
$Assertion = "eyJ0ey00ZjNmLMcExmcFVnMjetLhs7yhkIA"

$OBOToken = New-APIOnBehalfToken -TenantId $TenantId -Scope $Scope -Secret $Password -Assertion $Assertion -ClientId $ClientId