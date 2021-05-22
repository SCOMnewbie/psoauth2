<#
.SYNOPSIS
This function generate a random string with a specific number of characters.
.DESCRIPTION
This function generate a random string (Uppercase, LowerCase, Numbers) with a specific number of characters which by default is 43 characters long. This function respect the RFC https://tools.ietf.org/html/rfc7636#section-4.1
to generate a verifier.

.PARAMETER NumChar
Specify the number of characters of the generated string
.EXAMPLE
$New-CodeVerifier -NumChar 56
Will give you a 56 characters long random string
.NOTES
VERSION HISTORY
1.0 | 2021/01/07 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT

    Can improve the result to better respect the RFC
#>
function New-CodeVerifier {
    Param (
        [int] $NumChar = 43
    )
    Write-Verbose 'New-CodeVerifier - Begin function'
    Write-Verbose 'New-CodeVerifier - Random code generated'
    Write-Verbose 'New-CodeVerifier - End function'
    -join (((48..57) + (65..90) + (97..122)) * 80 | Get-Random -Count $NumChar | ForEach-Object { [char]$_ })
}