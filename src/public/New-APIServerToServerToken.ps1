
<#
A Big thank you to Alex Asplund (https://adamtheautomator.com/powershell-graph-api/) who did the hardwork regarding certificate auth. I've copy/paste all his work.
#>
function New-APIServerToServerToken {
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