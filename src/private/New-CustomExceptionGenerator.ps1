function New-CustomExceptionGenerator {
    param(
        [Parameter(Mandatory=$true,ParameterSetName='TokenExpired')]
        [switch]$TokenExpired,
        [Parameter(Mandatory=$true,ParameterSetName='VersionValidationFailed')]
        [switch]$VersionValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AudienceValidationFailed')]
        [switch]$AudienceValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='SignatureValidationFailed')]
        [switch]$SignatureValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AzpacrValidationFailed')]
        [switch]$AzpacrValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AzpValidationFailed')]
        [switch]$AzpValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='TokenUnusable')]
        [switch]$TokenUnusable
    )
    # This function is a wrapper to generate custom terminated exception from classes (look _CustomExceptions.ps1)
    $null = $MyError

    switch($PSBoundParameters.Keys){
        'TokenExpired'{
            $MyError = [TokenExpiredException]::new('Token provided is expired')
            break
        }
        'VersionValidationFailed'{
            $MyError = [TokenVersionValidationFailedException]::new('Token provided does not use the 2.0 endpoint version')
            break
        }
        'AudienceValidationFailed'{
            $MyError = [TokenAudienceValidationFailedException]::new('Token provided does target the right audience')
            break
        }
        'SignatureValidationFailed'{
            $MyError = [TokenSignatureValidationFailedException]::new('The signature of the provided token cannot be verified')
            break
        }
        'AzpacrValidationFailed'{
            $MyError = [TokenAzpacrValidationFailedException]::new('Token provided are not sent by a public application')
            break
        }
        'AzpValidationFailed'{
            $MyError = [TokenAzpValidationFailedException]::new('Token provided are not sent by a trusted application')
            break
        }
        'TokenUnusable'{
            $MyError = [TokenUnusableException]::new('Token provided are not usable')
            break
        }
    }

    throw $MyError
}