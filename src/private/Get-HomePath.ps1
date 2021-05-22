function Get-HomePath {
    [CmdletBinding()]
    param()
    
    Write-Verbose 'Get-HomePath - Begin function'
    if($IsLinux){
        Write-Verbose 'Get-HomePath - Linux detected'
        $HOMEPath = [Environment]::GetEnvironmentVariable('HOME')
    }
    else{
        Write-Verbose 'Get-HomePath - Windows detected'
        $HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
    }

    Write-Verbose 'Get-HomePath - End function'
    return $HOMEPath
}