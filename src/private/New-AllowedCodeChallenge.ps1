# The "problem" when when you generate a hash, some weird char can appear (+,\,/,...) and I had an issue to make it work in the URL call (even with URLencoded), so I've decided to Generate the pair
# Verifier/Code challenge until the code challenge has a "proper" format. It's a little hack to avoid wasting too much time for no real added value.
Function New-AllowedCodeChallenge {

    Write-Verbose 'New-AllowedCodeChallenge - Begin function'

    #Generate a verifier
    $verifier = New-CodeVerifier
    #Generate the associated Code Challenge
    $CodeChallenge = New-CodeChallenge -Verifier $verifier

    #Now let's validate if weird chars are in the string
    if($CodeChallenge -match '[a-zA-Z0-9]{43}'){

        Write-Verbose 'New-AllowedCodeChallenge - End function'

        [PSCustomObject]@{
            Verifier     = $verifier
            CodeChallenge = $CodeChallenge
        }
    }
    else{
        #If yes, re-execute the function
        Write-Verbose 'New-AllowedCodeChallenge - None supported character detected, restart the function'
        New-AllowedCodeChallenge
    }
}