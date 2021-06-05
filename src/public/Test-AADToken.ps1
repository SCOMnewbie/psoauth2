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