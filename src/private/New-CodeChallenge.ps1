#Function to generate the code challenge. Based on RFC, it's a based64 encoded hash of the verifier (other function)
function New-CodeChallenge {

    Param (
        [string]
        $Verifier
    )
    Write-Verbose 'New-CodeChallenge - Begin function'
    Write-Verbose 'New-CodeChallenge - Create Hash from verifier'
    Write-Verbose 'New-CodeChallenge - End function'
    # code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Verifier))
    [System.Convert]::ToBase64String($hash).Replace('=', '')
}