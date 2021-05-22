[CmdletBinding()]
param(
    [Parameter(
        Mandatory,
        ParameterSetName = 'Analyze')
    ]
    [switch] $Analyze,
    [Parameter(
        Mandatory,
        ParameterSetName = 'Compile')
    ]
    [switch] $Compile,
    [Parameter(
        Mandatory,
        ParameterSetName = 'Compile')
    ]
    [ValidateNotNullOrEmpty()]
    [version] $BuildVersion,
    [Parameter(
        Mandatory,
        ParameterSetName = 'Test')
    ]
    [switch] $Test,
    [Parameter(
        Mandatory,
        ParameterSetName = 'Doc')
    ]
    [switch] $Doc,
    [Parameter(
        Mandatory,
        ParameterSetName = 'Release')
    ]
    [switch] $Release,
    [Parameter(
        Mandatory,
        ParameterSetName = 'Release')
    ]
    [ValidateNotNullOrEmpty()]
    [string] $NuGetKey,
    [Parameter(Mandatory)]
    [string]$ModuleName

)

#To plan the cross-platform
# Nice article: https://powershell.org/2019/02/tips-for-writing-cross-platform-powershell-code/
$DS = [io.path]::DirectorySeparatorChar

# Analyze step
if ($PSBoundParameters.ContainsKey('Analyze')) {
    if (-not (Get-Module -Name PSScriptAnalyzer -ListAvailable)) {
        Write-Warning "Module 'PSScriptAnalyzer' is missing or out of date. Installing 'PSScriptAnalyzer' ..."
        Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
    }

    #Invoke-ScriptAnalyzer -Path .\src -Recurse -EnableExit -ExcludeRule 'C:\Git\Private\psoauth2\src\'
    Invoke-ScriptAnalyzer -Path $PSScriptRoot -Recurse -ExcludeRule 'C:\Git\Private\psoauth2\src\','PSUseToExportFieldsInManifest'
}

# Test step
if ($PSBoundParameters.ContainsKey('Test')) {
    if (-not (Get-Module -Name Pester -ListAvailable) -or (Get-Module -Name Pester -ListAvailable)[0].Version -eq [Version]'3.4.0') {
        Write-Warning "Module 'Pester' is missing. Installing 'Pester' ..."
        Install-Module -Name Pester -Scope CurrentUser -Force
    }

    if (Get-Module $ModuleName) {
        Remove-Module $ModuleName -Force
    }

    #".\$ModuleName\$ModuleName.psd1"
    $TempPath = "{0}$DS{1}$DS{2}{3}" -f $PSScriptRoot,$ModuleName,$ModuleName,'.psd1'
    if (-not (Test-Path $TempPath)) {
        Throw "Compile your module first before testing it"
    }

    #".\$ModuleName\$ModuleName.psm1"
    $TempPath = "{0}$DS{1}$DS{2}{3}" -f $PSScriptRoot,$ModuleName,$ModuleName,'.psd1'
    import-module $TempPath

    $TempPath = Join-Path $PSScriptRoot 'test'
    & "$TempPath\pester.ps1"
    <#
    $Result = Invoke-Pester -Script @{Path = $TempPath; Parameters = @{ModuleName = "$ModuleName" } } -OutputFormat NUnitXml -OutputFile TestResults.xml -PassThru

    if ($Result.FailedCount -gt 0) {
        throw "$($Result.FailedCount) tests failed."
    }
    #>
}

# Compile step
if ($PSBoundParameters.ContainsKey('Compile')) {
    if (Get-Module $ModuleName) {
        Remove-Module $ModuleName -Force
    }

    $TempPath = Join-Path $PSScriptRoot $ModuleName
    if ((Test-Path $TempPath)) {
        Remove-Item -Path $TempPath -Recurse -Force
    }

    if (-not (Test-Path $TempPath)) {
        $null = New-Item -Path $TempPath -ItemType Directory
    }

    $TempPath = "{0}$DS{1}$DS{2}" -f $PSScriptRoot,'src','private'
    if ((Test-Path $TempPath)) {
        $TempPath = "{0}$DS{1}$DS{2}$DS{3}" -f $PSScriptRoot,'src','private','*.ps1'
        $TempPath2= "{0}$DS{1}$DS{2}{3}" -f $PSScriptRoot,$ModuleName,$ModuleName,'.psm1'
        Get-ChildItem -Path $TempPath -Recurse | Get-Content -Raw | ForEach-Object {"`r`n$_"} | Add-Content $TempPath2
    }

    Copy-Item -Path $(Join-Path $PSScriptRoot 'README.md') -Destination $(Join-Path $PSScriptRoot $ModuleName) -Force
    Copy-Item -Path "$ModuleName.psd1" -Destination $(Join-Path $PSScriptRoot $ModuleName) -Force

    ## Update build version in manifest
    $TempPath = "{0}$DS{1}$DS{2}{3}" -f $PSScriptRoot,$ModuleName,$ModuleName,'.psd1'
    $manifestContent = Get-Content -Path $TempPath -Raw
    $manifestContent -replace "ModuleVersion = '<ModuleVersion>'", "ModuleVersion = '$BuildVersion'" | Set-Content -Path $TempPath

    $TempPath = "{0}$DS{1}$DS{2}$DS{3}" -f $PSScriptRoot,'src','public','*.ps1'
    $Public = @( Get-ChildItem -Path $TempPath -ErrorAction SilentlyContinue )

    $TempPath = "{0}$DS{1}$DS{2}{3}" -f $PSScriptRoot,$ModuleName,$ModuleName,'.psm1'
    $Public | Get-Content -Raw | ForEach-Object {"`r`n$_"} | Add-Content $TempPath

    "`r`nExport-ModuleMember -Function '$($Public.BaseName -join "', '")'" | Add-Content $TempPath
}

# Doc step
if ($PSBoundParameters.ContainsKey('Doc')) {
    if (-not (Get-Module -Name PlatyPS -ListAvailable)) {
        Write-Warning "Module 'PlatyPS' is missing. Installing 'PlatyPS' ..."
        Install-Module -Name PlatyPS -Scope CurrentUser -Force
    }

    if (Get-Module $ModuleName) {
        Remove-Module $ModuleName -Force
    }

    $TempPath = "{0}$DS{1}$DS{2}{3}" -f $PSScriptRoot,$ModuleName,$ModuleName,'.psd1'
    if (-not (Test-Path $TempPath)) {
        Throw "Compile your module first before testing it"
    }
    import-module $TempPath

    # Regenerate all fresh docs
    Try {
        Remove-Item -Path $(Join-Path $PSScriptRoot 'docs') -Recurse -Force
        #Generate the doc
        $null = New-MarkdownHelp -Module $ModuleName -OutputFolder $(Join-Path $PSScriptRoot 'docs') -Force
    }
    Catch {
        throw $_
    }
}

# Release step
if ($PSBoundParameters.ContainsKey('Release')) {
    # Release Module to PowerShell Gallery
    Try {
        $Splat = @{
            Path        = "$([Environment]::PIPELINE_WORKSPACE)\$ModuleName"
            NuGetApiKey = $NuGetKey
            ErrorAction = 'Stop'
        }
        Publish-Module @Splat

        Write-Output "$ModuleName PowerShell Module published to the PowerShell Gallery"
    }
    Catch {
        throw $_
    }
}
