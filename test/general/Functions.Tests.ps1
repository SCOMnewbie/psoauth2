$ModuleName = "psoauth2"
$CommandPath = @(
    "$global:testroot\..\src\public"
    #"C:\Git\Private\PSAADApplication\PSAADApplication\src\public"
)

[array]$includedNames = foreach ($path in $CommandPath) { (Get-ChildItem $path -Recurse -File | Where-Object Name -like "*.ps1").BaseName }
$commandTypes = @('Cmdlet', 'Function')
$commands = Get-Command -Module (Get-Module $ModuleName) -CommandType $commandTypes
$AllowedVerbs = (Get-Verb).verb

foreach ($includedName in $includedNames) {
    $IsExist = $includedName -in $commands.name
    $IsFormatValid = $includedName -match '^.*-.*$'
    Describe "Test function $includedName" {

        It "should be in Export-ModuleMember list" -TestCases @{ IsExist = $IsExist} {
            $IsExist | Should -Be $true
        }  

        It "should have a valid format verb-noun" -TestCases @{ IsFormatValid = $IsFormatValid} {
            $IsFormatValid | Should -Be $true
        } 
    }
}

