
Function Add-AppRegistrationLogo {
    <#
    .SYNOPSIS
    This function add a logo to an app registration.

    .DESCRIPTION
    This function add a logo to an app registration.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER ObjectId
    Specify the GUID of the App registration

    .PARAMETER LogoPath
    Specify the path of the logo you want to upload

    .EXAMPLE
    PS> Add-AppRegistrationLogo -AccessToken "Bearrer ..." -ObjectId <Guid> -LogoPath '.\logo.png'
    
    "Will upload a logo to the App registration"

    .LINK
    https://docs.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [guid]$ObjectId, # Of the App registration
        [parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [string]$LogoPath
    )
    
    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'image/png'
    }

    $Params = @{
        ErrorAction = "Stop"
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/applications/$ObjectId/logo"
        Body        = $null
        Infile      = $LogoPath
        method      = 'Put'
    }

    Invoke-RestMethod @Params
}

Function Add-AppRegistrationPassword {
    <#
    .SYNOPSIS
    This function generate a password to an confidential app registration.

    .DESCRIPTION
    This function generate a password to an confidential app registration.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER ObjectId
    Specify the GUID of the App registration

    .EXAMPLE
    PS>Add-AppRegistrationPassword -AccessToken "Bearrer ..." -ObjectId <Guid>

    "Will generate a 2 years secrets and return it in the output."
    
    .LINK
    https://docs.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        - Manage other datetime. The code it already commented.
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [guid]$ObjectId # Of the App registration
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction = "Stop"
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/applications/$ObjectId/addPassword"
        Body        = $null
        method      = 'Post'
    }

    <#
    # If you want to do never expire
    $passwordCredential = @{
        displayName =  "Password friendly name3" #By default 2 years
        endDateTime = '2042-01-01T00:00:00Z' #like a never
    }

    $BodyPayload = @{
        passwordCredential = $passwordCredential
    }

    $Params.Body = $BodyPayload | ConvertTo-Json -Depth 20
    #>

    Invoke-RestMethod @Params
}

Function Convert-SettingsToJson {
    <#
    .SYNOPSIS
    This function will compile and convert your app settings in a json file.

    .DESCRIPTION
    This function will compile and convert your app settings in a json file. The goal here is mainly to generate displayname and GUID on the fly.

    .PARAMETER TemplateSettings
    Specify the template to convert in Json

    .PARAMETER OutputFolder
    Specify where the json will be generated if specified

    .EXAMPLE
    PS> $BackendSettings = @{<app settings>}
    $BackendSettingInJson = Convert-SettingsToJson -TemplateSettings $BackendSettings
    
    "Will transform the hashtable into a json object"

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    1.1 | 2021/04/13 | Francois LEON
        - Change the function to avoid having to copy/paste template in the function.
        Instead we just provide the template (Hashtable) directly into a variable
        - Now the function can either return raw json into the console or out-file into a folder
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [ValidateScript( { Test-Path $_ })]
        [string]$OutputFolder,
        [parameter(Mandatory = $true)]
        [ValidateScript( { -not [string]::IsNullOrEmpty($_.DisplayName) })]
        [System.Collections.Hashtable]$TemplateSettings #Displayname can't be null or empty in the settings. This is the only mandatory parameter
    )

    if ($OutputFolder) {
        $TemplateSettings | ConvertTo-Json -Depth 99 | Out-File -FilePath $(Join-Path -Path $OutputFolder -ChildPath "$($TemplateSettings.DisplayName).json")
    }
    else {
        $TemplateSettings | ConvertTo-Json -Depth 99
    }
}

Function Get-APIScopesInfo {
    <#
    .SYNOPSIS
    This function will return either delegated or applications available scopes  for the Graph API app.

    .DESCRIPTION
    This function will return either delegated or applications permission for specific scopes. By default it will use the Graph API app. You can filter on a specific keyword if you want to filter.
    You can extract from this cmdlet the required Id.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER ScopeKeyword
    Specify a word to apply filter

    .PARAMETER Deleguated
    Specify you look for delegated permissions

    .PARAMETER Application
    Specify you look for application permissions

    .EXAMPLE
    PS> Get-APIScopesInfo -AccessToken "Bearrer ..." -ScopeKeyword "group" -Deleguated

    "Will return all available scopes with the word group in both value and description with delegated permission."

    .EXAMPLE
    PS> Get-APIScopesInfo -AccessToken "Bearrer ..." -ScopeKeyword "group" -Application
    
    "Will return all available scopes with the word group in both value and description with application permission."

    .EXAMPLE
    PS> Get-APIScopesInfo -AccessToken "Bearrer ..." -ScopeKeyword "group" -Application -AppId f6eb2883-3454-4520-860c-222f796bd929
    
    "Will return all available scopes from your app Id"

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    1.1 | 2021/03/29 | Francois LEON
        added both delegated and application available scopes
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true, ParameterSetName = 'Deleguated')]
        [parameter(Mandatory = $true, ParameterSetName = 'Application')]
        [string]$AccessToken,
        [Parameter(ParameterSetName = 'Deleguated')]
        [Parameter(ParameterSetName = 'Application')]
        [string]$ScopeKeyword,
        [parameter(Mandatory = $true, ParameterSetName = 'Deleguated')]
        [switch]$Deleguated,
        [parameter(Mandatory = $true, ParameterSetName = 'Application')]
        [switch]$Application,
        [string]$AppId = '00000003-0000-0000-c000-000000000000' #By default graph API
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction = "Stop"
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'"
        Body        = $null
        method      = 'Get'
    }

    foreach ($Key in $PSBoundParameters.Keys) {
        switch ($Key) {
            'Deleguated' { $results = (Invoke-RestMethod @Params).value.oauth2PermissionScopes; break }
            'Application' { $results = (Invoke-RestMethod @Params).value.appRoles; break }
        }
    }

    if ([string]::IsNullOrEmpty($ScopeKeyword)) {
        $results
    }
    else {
        $results | Where-Object { ($_.value -like "*$ScopeKeyword*") -or ($_.description -like "*$ScopeKeyword*") }
    }
}

Function Get-AppRegistrationProperties {
    <#
    .SYNOPSIS
    This function will return your application properties from it's objectId.

    .DESCRIPTION
    You can create multiple application with the same name, but only one with the same identifierUris. This property can be set only when a service principal is enabled
    for a specific App Registration.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER ObjectId
    Specify the GUID of the App registration

    .EXAMPLE
    PS> Get-AppRegistrationProperties -AccessToken "Bearrer ..." -ObjectId "<guid>"
    
    "will return your application properties"
    
    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [guid]$ObjectId # Of the App registration
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction = "Stop"
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/applications/$ObjectId" #ObjectId
        Body        = $null
        method      = 'Get'
    }

    Invoke-RestMethod @Params
}

Function Get-AppRegistrationPropertiesFromIdentifierUris {
    <#
    .SYNOPSIS
    This function will return your application information if the identifierUris has been defined.

    .DESCRIPTION
    You can create multiple application with the same name, but only one with the same identifierUris. This property can be set only when a service principal is enabled
    for a specific App Registration.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER IdentifierUris
    Specify the IdentifierUris of the App registration

    .EXAMPLE
    PS> Get-AppRegistrationPropertiesFromIdentifierUris -AccessToken "Bearrer ..." -IdentifierUris "api://<guid>"
    
    "will return something only if your application has been declared."

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [string]$IdentifierUris
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction       = "Stop"
        Headers           = $Headers
        uri               = "https://graph.microsoft.com/v1.0/applications?`$filter=identifierUris/any(c:c eq `'$IdentifierUris`')"
        Body              = $null
        method            = 'Get'
    }

    (Invoke-RestMethod @Params).value
}

Function New-AppRegistration {
    <#
    .SYNOPSIS
    This function will create an app registration based on a provided template file.

    .DESCRIPTION
    This function will create an app registration based on a provided template file. Because there is so much possibilities, we have to use a template file or variable to build our app.
    To avoid mistakes, this function define "hardcode" few parameters like the apiToken Version, and the singletenant parameter. This part won't necessary fit your need.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER InputWithFile
    Specify a json template with the confiiguration of your app registration through a file

    .PARAMETER InputWithVariable
    Specify a json template with the confiiguration of your app registration through a variable

    .PARAMETER ConfidentialApp
    Specify if you want to create a confidential app (RBAC + Web App) instead of the default public one.

    .EXAMPLE
    New-AppRegistration -AccessToken "Bearrer ..." -ConfigFilePath -ConfigFilePath ".\Output\MyWebApp01.json" -ConfidentialApp

    "Will create a confidential, single tenant application based on the provided template."
    
    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true, ParameterSetName = "InputWithFile")]
        [ValidateScript( {
                if (Get-Content $_ -Raw | ConvertFrom-Json -ErrorAction Stop) {
                    $true
                }
                else {
                    throw "$_ is  and invalid json file"
                }
            })]
        $InputWithFile,
        [parameter(Mandatory = $true, ParameterSetName = "InputWithVariable")]
        [ValidateScript( {
                if ($_ | ConvertFrom-Json -ErrorAction Stop) {
                    $true
                }
                else {
                    throw "$_ is  and invalid json file"
                }
            })]
        $InputWithVariable,
        [switch]$ConfidentialApp
    )

    if ($InputWithFile) {
        #Load template
        $ConfigData = Get-Content $InputWithFile -raw | ConvertFrom-Json -Depth 20
    }
    else {
        #Means input with variable
        $ConfigData = $InputWithVariable | ConvertFrom-Json -Depth 20
    }

    #Get all properties names that we won't set manually and skip the ones we may use later.
    $ignoredProperties = @("api", "isFallbackPublicClient", "signInAudience")
    $Keys = $ConfigData | Get-Member -MemberType NoteProperty | Where-Object { $_.name -notin $ignoredProperties } | Select-Object -ExpandProperty name

    #Generic values for all the app I will generate.
    $api = @{requestedAccessTokenVersion = "2" } # We always require tokens generated by V2 endpoint
    $isFallbackPublicClient = 'true' # Only RBAC and web app/api are confidential app
    $signInAudience = 'AzureADMyOrg' #AzureADMultipleOrgs for multi tenant app

    if ($ConfidentialApp) {
        $isFallbackPublicClient = 'false'
    }

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction = "Stop"
        Headers     = $Headers
        uri         = 'https://graph.microsoft.com/v1.0/applications'
        Body        = $null
        method      = 'Post'
    }

    #Start to build our payload dynamically
    $BodyPayload = @{}

    $MandatoryArrayProp = @("identifierUris", "requiredResourceAccess", "appRoles")
    foreach ($Key in $Keys) {
        if ($Key -in $MandatoryArrayProp) {
            #Schema require an array for those values
            [array]$BodyPayload[$Key] = $($ConfigData.$Key)
        }
        else {
            $BodyPayload[$Key] = $($ConfigData.$Key)
        }
    }

    $BodyPayload.add('api', $api)
    $BodyPayload.add("isFallbackPublicClient", $isFallbackPublicClient )
    $BodyPayload.add("signInAudience", $signInAudience)

    $Params.Body = $BodyPayload | ConvertTo-Json -Depth 99

    Invoke-RestMethod @Params
}

Function New-ServicePrincipal {
    <#
    .SYNOPSIS
    This function will create a service principal and link it to your app registration.

    .DESCRIPTION
    This function will create a service principal and link it to your app registration.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER AppId
    Specify the GUID of the App registration

    .EXAMPLE
    PS> New-ServicePrincipal -AccessToken "Bearrer ..." -AppId <GUID>

    "Will create a SP and link t to your previously created app registration."

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [guid]$AppId #Of the App registration
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction = "Stop"
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/servicePrincipals"
        Body        = $null
        method      = 'Post'
    }

    $BodyPayload = @{
        appId = $AppId
    }

    $Params.Body = $BodyPayload | ConvertTo-Json
    Invoke-RestMethod @Params
}

Function Remove-AppRegistration {
    <#
    .SYNOPSIS
    This function will delete your app registration.

    .DESCRIPTION
    This function will delete your app registration. Will also delete SP if there is one.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER ObjectId
    Specify the GUID of the App registration

    .EXAMPLE
    PS> Remove-AppRegistration -AccessToken "Bearrer ..." -ObjectId <GUID>
    
    "Will delete the app registration and SP associated if there is one."

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [guid]$ObjectId # Of the App registration
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction = "Stop"
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/applications/$ObjectId" #ObjectId
        Body        = $null
        method      = 'Delete'
    }

    Invoke-RestMethod @Params
}

Function Set-AppRegistrationidentifierUris {
    <#
    .SYNOPSIS
    This function will specify a identifierUris to an app registration.

    .DESCRIPTION
    This function will specify a identifierUris to an app registration. The function hardcode the result with a api://<guid> which is how azure create it by default.
    Service Principal is required to enable this attribute.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER ObjectId
    Specify the GUID of the App registration

    .PARAMETER AppId
    Specify the GUID of the App registration

    .EXAMPLE
    PS> Set-AppRegistrationidentifierUris -AccessToken "Bearrer ..." -AppId <GUID> -ObjectId <GUID>

    "Will add a identifierUris to your app registration."

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [guid]$ObjectId, #Of the App registration
        [parameter(Mandatory = $true)]
        [guid]$AppId #Of the App registration
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction       = "Stop"
        Headers           = $Headers
        uri               = "https://graph.microsoft.com/v1.0/applications/$ObjectId"
        Body              = $null
        method            = 'Patch'
    }

    $BodyPayload = @{
        identifierUris = @("api://$AppId")
    }

    $Params.Body = $BodyPayload | ConvertTo-Json
    Invoke-RestMethod @Params
}

Function Set-AppRegistrationoauth2PermissionScopes {
    <#
    .SYNOPSIS
    This function will populate the scopes you plan to expose with your application.

    .DESCRIPTION
    This function will populate the scopes you plan to expose with your application. We can find them under the Expose an API menu in the app registration.
    This function is using the same template used in the New-AppRegistration command, but this time will focus only on the oauth2PermissionScopes properties.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER InputWithFile
    Specify a json template with the confiiguration of your app registration through a file

    .PARAMETER InputWithVariable
    Specify a json template with the confiiguration of your app registration through a variable

    .PARAMETER ObjectId
    Specify the GUID of the App registration

    .EXAMPLE
    PS> Set-AppRegistrationoauth2PermissionScopes -AccessToken "Bearrer ..." -ConfigFilePath -ConfigFilePath ".\Output\MyWebApp01.json" -ObjectId

    "Will expose scopes to a specific custom API."

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true, ParameterSetName = "InputWithFile")]
        [ValidateScript( {
                if (Get-Content $_ -Raw | ConvertFrom-Json -ErrorAction Stop) {
                    $true
                }
                else {
                    throw "$_ is  and invalid json file"
                }
            })]
        $InputWithFile,
        [parameter(Mandatory = $true, ParameterSetName = "InputWithVariable")]
        [ValidateScript( {
                if ( $_ | ConvertFrom-Json -ErrorAction Stop) {
                    $true
                }
                else {
                    throw "$_ is  and invalid json file"
                }
            })]
        $InputWithVariable,
        $ObjectId # From app registration
    )

    if ($InputWithFile) {
        #Load template
        $ConfigData = Get-Content $InputWithFile -raw | ConvertFrom-Json -Depth 20
    }
    else {
        #Means input with variable
        $ConfigData = $InputWithVariable | ConvertFrom-Json -Depth 20
    }

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction       = "Stop"
        Headers           = $Headers
        uri               = "https://graph.microsoft.com/v1.0/applications/$ObjectId"
        Body              = $null
        method            = 'Patch'
    }

    #Oauth2Permission has to be an array!
    $BodyPayload = @{
        api = $($ConfigData.api)
    }

    $Params.Body = $BodyPayload | ConvertTo-Json -Depth 99
    Invoke-RestMethod @Params
}

Function Set-ServicePrincipalAppRoleAssignmentRequired {
    <#
    .SYNOPSIS
    This function will permit you to configure your Service Princiapl to force the AppRoleAssignment.

    .DESCRIPTION
    When you create a ervice principal, by default, everyone from your tenant can access you application. This parameter force people to be assigned to get their access toekns.

    .PARAMETER AccessToken
    Specify token you use to run the query

    .PARAMETER Required
    Specify if yes or no assignment must be assign. By default it's true.

    .PARAMETER ObjectId
    Specify the GUID of the App registration

    .EXAMPLE
    PS> Set-ServicePrincipalAppRoleAssignmentRequired -AccessToken "Bearrer ..."  -ObjectId <GUID>

    "Will configure your SP to make sure people has to be assign to get an AT"

    .NOTES
    VERSION HISTORY
    1.0 | 2021/03/22 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$AccessToken,
        [parameter(Mandatory = $true)]
        [guid]$ObjectId, #Of the Enterprise App (Service Principal)
        [bool]$Required = $true
    )

    $Headers = @{
        'Authorization' = $AccessToken
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        ErrorAction       = "Stop"
        Headers           = $Headers
        uri               = "https://graph.microsoft.com/v1.0/servicePrincipals/$ObjectId"
        Body              = $null
        method            = 'Patch'
    }

    #The body is waiting string values
    if($Required){
        $RequiredString = "true"
    }
    else{
        $RequiredString = "false"
    }
    $BodyPayload = @{
        appRoleAssignmentRequired = $RequiredString
    }

    $Params.Body = $BodyPayload | ConvertTo-Json
    Invoke-RestMethod @Params
}

Export-ModuleMember -Function 'Add-AppRegistrationLogo', 'Add-AppRegistrationPassword', 'Convert-SettingsToJson', 'Get-APIScopesInfo', 'Get-AppRegistrationproperties', 'Get-AppRegistrationPropertiesFromIdentifierUris', 'New-AppRegistration', 'New-ServicePrincipal', 'Remove-AppRegistration', 'Set-AppRegistrationIdentifierUris', 'Set-AppRegistrationoauth2PermissionScopes', 'Set-ServicePrincipalAppRoleAssignmentRequired'
