using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Variables to defined (Should be fetch from another place but ok for demo)
$FrontEndAppId = '<your frontend AppId>'    # Client AppId
$BackendAppId = '<your bckend AppId>' # This Application
$TenantId = 'Your tenantId'
$Myappsecret = $env:MyAppSecret # Secret added in the config file or better solution, System MSI + Keyvault + reference link
$AuthorizedRoles = @('Read.Access','Admin.Access')      # App roles defined in your backend API app registration

# Script variable
$Authorized = $false
$null = $CustomError

#This module has to be imported in the function (your function should be deployed with CI/CD pipeline)
Import-Module psoauth2

try {
    # Extract the token from the request
    [String]$RequestAccessToken = $Request.Headers.Authorization
    if($RequestAccessToken){
        # Here we will check the signature, audience, the request comes from our frontend and that our token is a V2.
        $null = Test-AADToken -AccessToken $RequestAccessToken -Aud $BackendAppId -azp $FrontEndAppId
    }
    else{
        throw
    }
}
catch {
    $CustomError = $_.Exception
}

if ($null -eq $CustomError) {
    # Here means the token has been validated
    $DecodedToken = ConvertFrom-Jwt -Token $RequestAccessToken
    
    # Decode access token and check assigned roles
    [array]$Roles = $DecodedToken.TokenPayload.roles
    $Roles.ForEach({if($_ -in $AuthorizedRoles){$Authorized = $true}})

    if ($Authorized) {
        # Means user has proper permission to execute the function

        #Remove Bearer word from the received access token
        $RequestAccessTokenWithoutHeader = $RequestAccessToken.replace('Bearer ','')

        $OBOToken = (New-APIOnBehalfToken -TenantId $TenantId -Secret $Myappsecret -Assertion $RequestAccessTokenWithoutHeader -ClientId $BackendAppId).access_token

        # Should have a better token validation here
        if($OBOToken){
            $Headers = @{
            'Authorization' = $OBOToken
            "Content-Type"  = 'application/json'
            }

            # What better than /me to validate a delegated token :)
            $Data = Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/me"

            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Data
            })
        }
        else{        
              
            Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::ServiceUnavailable
                Body       = "Bad intermediate request"
            })
        }
    }
    else {
        # Unauthorized
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::UNAUTHORIZED
                Body       = $CustomError
            })
    }
}
else {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::Forbidden
            Body       = $CustomError
        })
}