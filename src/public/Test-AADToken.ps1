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
    .PARAMETER Iss
    Specify the issuer authorized by your application.
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
        [String[]]$azp,
        [String[]]$iss,
        [String]$ver = '2.0'
    )

    begin{
        $ErrorActionPreference = 'Stop'
        # To avoid issue when we activate Azure func auth
        $AccessToken = $AccessToken.Replace('Bearer ','')
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

            # Can authorize several authorized client
            If ($PSBoundParameters.ContainsKey('azp')) {
                if ($Decodedtoken.TokenPayload.azp -notin $azp) {
                    New-CustomExceptionGenerator -AzpValidationFailed
                }
            }

            # Can authorize several issuer
            If ($PSBoundParameters.ContainsKey('iss')) {
                if ($Decodedtoken.TokenPayload.iss -notin $iss) {
                    New-CustomExceptionGenerator -IssuerValidationFailed
                }
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

$AccessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Im5PbzNaRHJPRFhFSzFqS1doWHNsSFJfS1hFZyJ9.eyJhdWQiOiI0M2E4NTEwNi1hYTM1LTQ3NmUtOWRmYS0xZjY1YWU0NmNjNzkiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vZTE5MmNhZGEtYTA0ZC00Y2ZjLThiOTAtZDE0MzM4YjJjN2VjL3YyLjAiLCJpYXQiOjE2MjQ2MzE5MDMsIm5iZiI6MTYyNDYzMTkwMywiZXhwIjoxNjI0NjM1ODAzLCJhaW8iOiJBVFFBeS84VEFBQUFDSVJXQUNSaG5jSks5NUhxaE16UnUvcmZyU3pVUnZrRnVVcFZ3WGZNdTFhZjFWYUJSQ2d5a0JJZXhBOXZjWVBiIiwiYXpwIjoiNDJlMzQ5YWMtM2M0Yi00ZmVjLWI5NzctNzg4ZTZhMzAzYzljIiwiYXpwYWNyIjoiMCIsIm5hbWUiOiJ1c2VyMDIiLCJvaWQiOiI0MWE2YjlkMy1jOWVlLTQyY2MtODViYi1iYmFhZTlmYjQzOWEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2VyMDJAZnJhbmNvaXNsZW9udWJpc29mdC5vbm1pY3Jvc29mdC5jb20iLCJyaCI6IjAuQVVjQTJzcVM0VTJnX0V5TGtORkRPTExIN0t4SjQwSkxQT3hQdVhkNGptb3dQSnhIQUs4LiIsInJvbGVzIjpbIlJlYWQuQWNjZXNzIl0sInNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInN1YiI6IjZiWXJJeUZnOHpkaXdVYXRIWi1RWi0xdVh1V2lSSXc5bmowVUFVcm5FT00iLCJ0aWQiOiJlMTkyY2FkYS1hMDRkLTRjZmMtOGI5MC1kMTQzMzhiMmM3ZWMiLCJ1dGkiOiJ2c0xZNEFESmlVcVRrMTJ2T2xJY0FBIiwidmVyIjoiMi4wIn0.IXhIgZtfysD_B_B4q4bic2qP8ZNSGQSEeajpAyKtKsoQMMDKYS_nkaClbhp_sb4nyNyomtCEsVHJvwSsjr-eujvR9NUd80BtgNtS8mMIrHRKpDfuPHJhvXhopxC7H4HCm802gmFH43gkZMhjRNpMIg5LqHk5EWGIhEouExjcPelo5Sr0oQxpmtvApVyjJT49OAn3RD7BTBOE5f3EL7_9_JZZRkFyY04CfLO8R9ahdEPYQ2MyTPc-VNG3ywB9GzsOTd1ofjjU2UZ1QBC6YlhGGKnW9m_3EbD3Bgu-SZB67rzVkFsHPLz4YZfZpsXbPyDIFesiTWwabfBgA8KBrTZrXA"
$Aud = "43a85106-aa35-476e-9dfa-1f65ae46cc79"
#"iss": "https://sts.windows.net/fa15d692-e9c7-4460-a743-29f29522229/"
$iss = @("https://sts.windows.net/fa15d692-e9c7-4460-a743-29f29522229/","https://login.microsoftonline.com/e192cada-a04d-4cfc-8b90-d14338b2c7ec/v2.0")

#Notazp
remove-module psoauth2
import-module "C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1"
Test-AADToken -AccessToken $AccessToken -Aud $Aud -iss $iss