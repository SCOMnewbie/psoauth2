<#
    # INTRO
    This is the most basic type of access (more or less what you will see on internet when you want to run a script). An RBAC account you create to give access to something in your Azure tenant. It can be an account for your AzDo pipeline, 
    to give permission to something in your Azure subscription, to have an account to upload files on your storage account, ...
    We will rely on the Powershell module (and so MSAL) to authenticate.
    We will use the client credential flow credential through the connect-azaccount cmdlet but for now, we are talking about a "dummy" RBAC account without
    any permission on graph or any other backend api.

    pros:
        * Simple to implement
        * No interraction required (server to server can't have interraction). No user consent (there is no user interraction :p)
    cons:
        * No user assignment. You have the appId & secret, you "impersonate" the application permission
        * hard to monitor / track on AAD sign-ins (subject to change I hope - Maybe changed already)
        * You have to store the secret somewhere

    # DEMO
    We will create:
        * A Simple account
        * Add a secret to it
        * Generate an identity for it (Enterprise app/ Service principal)
        * Assign Azure permission to a resource group
        * Read resources within
        * Delete the app

#>

#Use the previously created module pasted in the example folder
import-module .\PSAADApplication.psd1

#Define variable for the demo
$TenantId = [Environment]::GetEnvironmentVariable('LabTenantId')
$SubscriptionId = [Environment]::GetEnvironmentVariable('LabSubscriptionId')
[string]$RGName = "FunWithIdentity"


#Define your settings
$RBACsettings = @{
    displayName = "DemoRBAC01"
}

$RBACsettingsJson = Convert-SettingsToJson -TemplateSettings $RBACsettings

# Generate an AT for the graph audience (check previous article for more info)
$token = "Bearer {0}" -f (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token

#To validate we have a token and avoid doxing
$token.Length

#Build App registration
$RBAC01AppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $RBACsettingsJson  -ConfidentialApp
# Create a secret automatically (valid 2 years)
$RBAC01AppRegistrationCreds = Add-AppRegistrationPassword -AccessToken $token -ObjectId $RBAC01AppRegistration.Id
# Create an identity for our App to allow the assignment (we need an identity)
$RBAC01ServicePrincipal = New-ServicePrincipal -AccessToken $token -AppId $RBAC01AppRegistration.appId

# Now we can use it for role assignment (may wait few seconds for AAD replication to occur)
New-AzRoleAssignment  -RoleDefinitionName Reader -ResourceGroupName $RGName -ApplicationId $RBAC01AppRegistration.appId

#Connect with the SP
$Secret = ConvertTo-SecureString $RBAC01AppRegistrationCreds.secretText -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($RBAC01AppRegistration.appId,$Secret)
Connect-AzAccount -Tenant $TenantID -Subscription $SubscriptionId -Credential $creds -ServicePrincipal

# Validate the access
Get-AzContext
# And here you should see only one RG
Get-AzResourceGroup

#Let's now create a new VM (we should have an error, normal we're reader)
New-AzVM

#End of demo
Remove-AppRegistration -AccessToken $token -ObjectId $RBAC01AppRegistration.id

# Let's now read again resources (error message, normal no more identity available)
Get-AzResourceGroup

#End of demo for secret



