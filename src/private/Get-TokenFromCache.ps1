Function Get-TokenFromCache {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string]$Scope,
        [parameter(Mandatory)]
        [string]$resource
    )

    Write-Verbose 'Get-TokenFromCache - Begin function'

    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath

    #really psscriptAnalyzer ...
    $resource = $resource

    $FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"

    #Make sure $scope is formatted with the right format. This is how it's stored in the accesstokens.json file. Being sorted help for the search later.
    $scope = $scope -split " " | Sort-Object | Join-String  $_ -Separator " "

    if(Test-Path $FullPath){
        #File exist
        try{
            Write-Verbose 'Get-TokenFromCache - Read cache file'
            $Content = Get-Content $FullPath -Raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch{
            Write-Warning "File exist but seems corrupted, run clear-TokenCache"
            $Content = $null
        }

        #Here we should have a valid json file
        if($Content){
            #Search for couple resource / scope
            [array]$Context = $content | Where-Object{($_.scope -eq $Scope) -AND ($_.resource -eq $resource)}
            # Only one context should match. If not someone did something manually return $null
            if($Context.count -eq 1){
                Write-Verbose 'Get-TokenFromCache - Context detected'
                Write-Verbose 'Get-TokenFromCache - End function'
                return $Context
            }
            else{
                Write-Verbose "Too many context detected, run clear-TokenCache"
                Write-Verbose 'Get-TokenFromCache - End function'
                return $null
            }
        }
        else{
            Write-Verbose "File exist but seems corrupted, run clear-TokenCache"
            Write-Verbose 'Get-TokenFromCache - End function'
            return $null
        }
    }
    else{
        Write-Verbose "No Cache file exist locally"
        Write-Verbose 'Get-TokenFromCache - End function'
        return $null
    }
}