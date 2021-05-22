function New-CredentialCacheFolder {
    [cmdletbinding()]
    param()
    
    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath

    $FullPath = Join-Path $HOMEPath ".psoauth2"
    $ATCachePath = Join-Path $FullPath "accessTokens.json"

    if(Test-Path $FullPath){
        Write-Verbose "Folder $FullPath already exist"
    }
    else{
        Write-Verbose "Create folder $FullPath"
        $null = New-Item -ItemType Directory -Name ".psoauth2" -Path $HOMEPath -Force
    }

    if(Test-Path $ATCachePath){
        Write-Verbose "File $ATCachePath already exist"
    }
    else{
        Write-Verbose "Create file $ATCachePath"
        $null = New-Item -ItemType File -Name "accessTokens.json" -Path $FullPath -Force
    }
}