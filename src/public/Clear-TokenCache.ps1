Function Clear-TokenCache {
    <#
    .SYNOPSIS
    This function will delete the cache file that the module uses to store credentials.
    .DESCRIPTION
    This function will delete the cache file that the module uses to store credentials.
    .EXAMPLE
    PS> Clear-TokenCache
    
    "will delete the local cache from the disk"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/05/05 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        - Delete a specific item instead of the whole file.
    #>
    param()
    
    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath
    $FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"

    if(Test-Path $FullPath){
        Remove-Item -Path $FullPath -Force
    }
}