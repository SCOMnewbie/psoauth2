<#
    # INTRO
    The goal of this demo will be to show and explain the On behalf Flow. It will be far quicker than 07 because all the app creation is already done. 


    # DEMO
        Now that our backend app are already protected with user assignment, the demo will consist of simply try our backend API without the role assigned and then re-execute with the
        role assigned. The most interresting part of this demo is in fact located into the New-APIOnBehalfToken function that will be executed from the backend api. Long story short, contrary to the previous demo,
        the backend api will do a query to something (in this case graph with the /me endpoint) on behald of our user context. Not 100% sure about how context should work here (the doc is not clear enough).

        You can find the application backend function app in the folder: 08-Script-MultiTiers-AzureFunc-Delegated/FunctionApp/run.ps1

        Because we won't create any app in this demo, we will have to define variables on top of our script...
#>

        throw "don't press F5"


$FunctionURL = 'https://funwithidentity2.azurewebsites.net/api/DemoBackendAPI-Delegated?code=VNyapWMhCZ5zrg4E3CyYk0EWdOTXVTu7c9ewytLmA=='   # Replace with your delegated function URL
$FrontEndAppId = '<your frontendapi app id>'
$BackendAppId = '<your backendapi appId>'
$TenantId = '<your tenantId>'


# Let's generate a new AT without cache for now. Becaus our user do not have the Read.Access role, we should receive a Token but our api should drop us. Let's try
Clear-TokenCache #Just in case
$Splatting = @{
    Resource     = $FrontEndAppId
    TenantId     = $TenantId
    Scope        = "api://$BackendAppId/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    WithoutCache = $true
    verbose      = $true
}

$AccessToken = New-AccessToken @Splatting

# Let's call our delegated API
$Headers = @{
    'Authorization' = $("Bearer " + $AccessToken)
    'Content-Type'  = 'application/json'
}

$Params = @{
    Headers = $headers
    uri     = $FunctionURL
    Body    = $null
    method  = 'Get'
}

Invoke-RestMethod @Params

# And you should received a 401. Let's now add the user to admin/Read.Access role in the Entperise app...

# Go request a new token to fetch the new role claims!

$Splatting = @{
    Resource     = $FrontEndAppId
    TenantId     = $TenantId
    Scope        = "api://$BackendAppId/user_impersonation OpenId offline_access profile" # Now we use delegated, .default can work but now it's not mandatory compare to client credential.
    RedirectUri  = 'http://localhost' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

$AccessToken = New-AccessToken @Splatting

# Let's call our delegated API
$Headers = @{
    'Authorization' = $("Bearer " + $AccessToken)
    'Content-Type'  = 'application/json'
}

$Params = @{
    Headers = $headers
    uri     = $FunctionURL
    Body    = $null
    method  = 'Get'
}

Invoke-RestMethod @Params

# And boom you get your /me information not comming from graph directly but from your backend api.

<#
Key takeaways:

    - OBO (on behalf can be interresting) when you want to execute from user context requests.
    - Nothing happend on the client side. Only the backend should execute this flow.
    - A secret/certificate is required with this flow.
    
#>