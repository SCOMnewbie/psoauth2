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
        [String]$ver = '2.0',
        [int]$azpacr = 0
    )

    begin{
        $ErrorActionPreference = 'Stop'
    }

    process{
        try{
            #Create an object from the Token received
            $DecodedToken = ConvertFrom-Jwt -Token $AccessToken
    
            #Get the public key used to encrypt (multiple available and rotate from time to time)
            $x5c = Find-AzureX5c -Kid $($Decodedtoken.Tokenheader.kid)
    
            #Generate 509 certificate from bytes[]
            $cert = New-X509FromX5c -x5c $x5c
    
            #Validate signature from token received ($true is good)
            $null = Test-JwtSignature -jwt $AccessToken -Cert $cert
    
            #Is Token expired?
            if ($Decodedtoken.TokentimeToExpiry -lt 0) {
                New-CustomExceptionGenerator -TokenExpired
            }
    
            if ($Decodedtoken.TokenPayload.aud -ne $Aud) {
                New-CustomExceptionGenerator -AudienceValidationFailed
            }

            if ($Decodedtoken.TokenPayload.azpacr -ne $azpacr) {
                New-CustomExceptionGenerator -AzpacrValidationFailed
            }

            if ($Decodedtoken.TokenPayload.azp -ne $azp) {
                New-CustomExceptionGenerator -AzpValidationFailed
            }

            if ($Decodedtoken.TokenPayload.ver -ne $ver) {
                New-CustomExceptionGenerator -VersionValidationFailed
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