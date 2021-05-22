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