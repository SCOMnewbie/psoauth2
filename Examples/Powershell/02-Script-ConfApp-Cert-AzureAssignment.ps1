<#
    # INTRO
    We will do the same thing as before with secrets, but this time with certificates. I'm far to be a guru in certificates topic, but I'm sure on few things:
    - Using certificates can generate far more frustration than secrets. I've decided to rely on Keyvault (more information later on my experience...) for this demo.
    - But the end result is far better than secrets in term of security except if you commit your private key (dooh). 
        - If you commit/expose your public key/ certificate thumbprint, we don't really care.
        - When we will do the client credential flow, you just sign a "predefine" JWT you create with your private key and then your app registration will be able to decrypt 
        and validate the request comes from you (if you've previously uploaded the public key). In other words, if someone sniff your network, we don't really care either.
        - If you have a proper certificate management in your company, having the possibility to use your PKI infra to allow specific user by magic is pretty cool.

    pros:
        * More secure than secrets
        * No interraction required (server to server can't have interraction). No user consent (there is no user interraction :p)
        * In this demo, you just have to focus on who can download the private key from your KV
        * If you decide to use self-signed cert or digicert, pretty easy to create/manage your cert once you "understand" how it's working
    cons:
        * No user assignment. You have the appId & secret, you "impersonate" the application permission
        * hard to monitor / track on AAD sign-ins (subject to change I hope - Maybe changed already)
        * Careful with self-signed, someone can share the private key to a none allowed user. Wthout crl, the only option will be to roll to keys.
    
    # prerequisites

    * A keyvault
    * A resource group

    # DEMO
    We will create:
        * A Simple account
        * Generate a self signed cert into our KV
        * Upload the public key to our app
        * Download the private key and install it on our machine. (Or store it locally with the PEM file)
        * Generate an identity for it (Enterprise app/ Service principal)
        * Assign Azure permission to a resource group
        * Read resources within
        * Delete the app

    # Side Notes

    I don't know if this is just me, but god this part took me a while ... Like any other commands, I wanted to create a REST wrapper to help adding/removing certs to our app, or
    simply create a new cert in my Keyvault. The result? The doc is awful, with Powershell you have to write a lot of "none understandable" piece of code to manager certs or you
    receive some weird error message from the fabric itself ... Then I've used CLI and it took me one line to do what I need to do. It's not exactly true, I've seen this stupid bug,
    but I've loved the answer: https://github.com/Azure/azure-cli/issues/4626. The official help is designed for bash, not Powershell cya ... 
    Anyway, interresting but far more complicated than secret to move on.

    Now let's play!
#>

throw "don't press F5"

#Use the previously created module
Import-Module "C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1"
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

#Define variable for the demo
$TenantId = [Environment]::GetEnvironmentVariable('LabTenantId')
$SubscriptionId = [Environment]::GetEnvironmentVariable('LabSubscriptionId')
[string]$RGName = 'FunWithIdentity'
$VaultName = 'Funwithidentity'
$CertName = 'DemoRBACwithCertAuthPFX'


#Define your settings
$RBACsettings = @{
    displayName = 'DemoRBACwithCertAuth'
}

$RBACsettingsJson = Convert-SettingsToJson -TemplateSettings $RBACsettings


# Generate an AT for the graph audience (check previous article for more info)
$token = 'Bearer {0}' -f (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token

#Build App registration
$RBACAppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $RBACsettingsJson -ConfidentialApp

# Create an identity for our App (to permit the role assignment)
$RBACServicePrincipal = New-ServicePrincipal -AccessToken $token -AppId $RBACAppRegistration.appId

# Where adding a secret is simple, there is more steps for certificates authentications
# Validate you're connected (az login)
az account show

# You have choice here:
# - PEM format to authenticate with CLI for example (using the file directly)
# - PFX if you plan to connect with Powershell/Client credential flow (using the thumbprint)

#Let's start with PFX
#$CertFormatChoice = 'application/x-pem-file' #PEM
$CertFormatChoice = 'application/x-pkcs12' #PFX
#$Extension = 'pem'
$Extension = 'pfx'

# Here we will use a here string to simplify the demo. Long story short you have to define a policy to your Keyvault to generate certificates.
# --scaffold argument help you to use the right propoerty
$DefaultPolicy = @"
{
    "issuerParameters": {
      "certificateTransparency": null,
      "name": "Self"
    },
    "keyProperties": {
      "curve": null,
      "exportable": true,
      "keySize": 2048,
      "keyType": "RSA",
      "reuseKey": true
    },
    "lifetimeActions": [
      {
        "action": {
          "actionType": "AutoRenew"
        },
        "trigger": {
          "daysBeforeExpiry": 90
        }
      }
    ],
    "secretProperties": {
      "contentType": `"$CertFormatChoice`"
    },
    "x509CertificateProperties": {
      "keyUsage": [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyEncipherment",
        "keyAgreement",
        "keyCertSign"
      ],
      "subject": `"CN=$CertName`",
      "validityInMonths": 12
    }
  }
"@

# Stupid encoding bug. We can't read from the variable, we have to dump the variable into a UTF8 file.
$DefaultPolicy | Out-File DefaultCertPolicy.json -Encoding utf8 -Force

# Let's now create our certificate.
# WARNING: It takes some time, the Keyvault contact his "own PKI" to generate the self-sign (add --debug if you want to see what is going on)
# Don't forget to escape the @ sign if you use Powershell
az keyvault certificate create --vault-name $VaultName -n $CertName --policy "`@DefaultCertPolicy.json" --debug

# Extract the public key
$Cer = (az keyvault certificate show --vault-name $VaultName -n $CertName | ConvertFrom-Json).cer

# Add it to our app registration
# It's maybe not the smart choice, but it's working. If somone know how to do it with REST please poke me.
az ad app credential reset --id $RBACAppRegistration.appId --cert $Cer --append

# Download the private key locally
Remove-Item "$env:temp\mycert.$Extension" -Force
az keyvault secret download --vault-name $VaultName --name $CertName --file "$env:temp\mycert.$Extension"

# Install the certificate locally (can automate it too, but the GUI help to explain here)
# I will store it in my currentUser path
Start-Process "$env:temp\mycert.$Extension"

# why not
Remove-Item "$env:temp\mycert.$Extension" -Force

# Select the Thumbprint 
$Thumbprint = Get-Item 'Cert:\CurrentUser\My\*' | Where-Object subject -EQ "CN=$CertName" | Select-Object -ExpandProperty Thumbprint

# Now we can use it for role assignment (may wait few seconds)
New-AzRoleAssignment -RoleDefinitionName Reader -ResourceGroupName $RGName -ApplicationId $RBACAppRegistration.appId

#At this stage, we have a new cert generated in KV, an app registration with the public key uploded and his related SP, a role assignment, 
# a private key installed on our local cert store. Let's now connect with the cert Thumprint.
$splatting = @{
    ApplicationId         = $RBACAppRegistration.appId
    CertificateThumbprint = $Thumbprint
    Tenant                = $TenantId
    Subscription          = $SubscriptionId
    ServicePrincipal      = $true
}
Connect-AzAccount @splatting

# And here you should see only one RG
Get-AzResourceGroup

# Here for fun (far more fun later), let's start to use our new module to generate an access token with client credential flow.

$Splatting = @{
    Resource             = $RBACAppRegistration.appId
    TenantId             = $TenantId
    Scope                = 'https://graph.microsoft.com/.default'
    ClientCredentialFlow = $true
    CertificatePath      = "Cert:\CurrentUser\My\$Thumbprint"
    verbose              = $true
}

$AccessToken = New-AccessToken @Splatting
#List the first 30 characters
$AccessToken.Substring(0,30)

#To validate this is a valid token, let's call graph default assignment
$Headers = @{
    'Authorization' = $AccessToken
    "Content-Type"  = 'application/json'
}
Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/me"

# We receive an error whoch is normal, we've just created a RBAC account without any API permission. Let's play with it later. we have at least a token

# Now let's generate a new cert (PEM) this time, assign the new key to the app registration and try to authenticate using the CLI.

# Here we will have to redo previous steps. Let's first change few variables
$CertFormatChoice = 'application/x-pem-file' #instead of PFX
$Extension = 'pem'
$CertName = 'DemoRBACwithCertAuthPEM' # New name for the subject too

# IMPORTANT HERE
# Redo fun stuff from line 72 regenerate the here string with new variables (defaultpolicy) until line 128 download the pem file locally. Then come back.

test-path "$env:temp\mycert.$Extension"

# Now we should have our app with 2 public keys declared. Let's use the new one with our PEM cert.
az login --service-principal -u $RBACAppRegistration.appId -p "$env:temp\mycert.$Extension" --tenant $TenantId

# not enough permission
az group create -l westus -n MyResourceGroup

# good to go
az group list

# Now we have 2 certs who can login to our app

# Then remove a certificate to do the complete flow
# Select the specific certificate you want to remove
$keyid = (az ad app show --id $RBACAppRegistration.appId | ConvertFrom-Json | select -ExpandProperty keyCredentials).keyId
# Then delete the public key
az ad app credential delete --id $RBACAppRegistration.appId --key-id $keyid --cert

#End of demo remove the app registration
Remove-AppRegistration -AccessToken $token -ObjectId $RBACAppRegistration.Id