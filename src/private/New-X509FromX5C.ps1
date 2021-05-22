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