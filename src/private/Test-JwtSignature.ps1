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