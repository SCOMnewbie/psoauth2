
Import-Module -Name Pode
Import-Module './usr/psoauth2.psm1' # Not comming from the gallery
Import-Module PSWSMAN

#IMPORTANT: This command comes from the PSWSMAN module and require to be executed in the user context not the dockerfile. Not sure to understand why...
Disable-WSManCertVerification -All

# Get environment variable from WebApp/Keyvault
$Myappsecret = $env:Myappsecret
#Local account credential to access the psremoting session
$UserName = $Env:ServiceAccountUserName
$Password = ConvertTo-SecureString -String $($Env:ServiceAccountPassword) -AsPlainText -Force

# App Roles my API will validate
$WriteAccessRoles = @('Write.Access','Admin.Access') #Admin has access to both roles
$ReadAccessRoles = @('Read.Access','Admin.Access') #Admin has access to both roles

Start-PodeServer {
     #Declare global Middleware (mainly because GCP and Cloud Run does not allow you to allow specific CORS from the portal)
     Add-PodeMiddleware -Name 'MandatoryAuthorizationHeader' -ScriptBlock {
        Add-PodeHeader -Name 'Access-Control-Allow-Origin' -Value '*'  # * Because it's a POC, use your specific frontend URL here
        Add-PodeHeader -Name 'Access-Control-Allow-Methods' -Value 'GET, OPTIONS'
        Add-PodeHeader -Name 'Access-Control-Allow-Headers' -Value 'Content-Type,Authorization'
        
        return $true
    }

    # Allow the option method in each route
    Add-PodeRoute -Method Options -Path * -ScriptBlock {
        return $true
    }

    #Redirect errors to terminal. Cool to have logs redirected to containers logs for tracking
    New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging
    
    # Configure Pode to listen on 8080 in HTTP (with localhost, you "break" Docker)
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

    # Get App setting from psd1 files (can't be located outside Start-PodeServer)
    # Depending if there is an exposed environment variable called PODE_ENVIRONMENT with dev, it will take server.psd1 by default
    # https://badgerati.github.io/Pode/Tutorials/Configuration/#environments

    $Config = Get-PodeConfig # Gather Audience, TenantId, Allowed issuers

    #############################
    # Declare Middleware for roles
    #############################

    # You have to be authenticated
    $AuthenticationRequired = {
        # Require a Authorization header
        $EmptyAuthorizationHeader = [string]::IsNullOrWhiteSpace($WebEvent.Request.Headers.Authorization)
        if ($EmptyAuthorizationHeader) {
            Set-PodeResponseStatus -Code 403
            return $false
        }#If no authorization in the header > 403

        # Verify it's a valid JWT format (Avoid 500 error with try catch > Terminal logs for more info)
        try{
            $RequestAccessToken = $WebEvent.Request.Headers.Authorization
            $DecodedToken = ConvertFrom-Jwt -Token $RequestAccessToken
        }
        catch{
            Set-PodeResponseStatus -Code 403
            return $false
        }#If we can't decode token (like bad JWT) > 403

        try{
            $Configs = $using:Config
            $Aud = $Configs['Audience']
            $Iss = $Configs['Issuers']  # Warning: Array

            Test-AADToken -AccessToken $RequestAccessToken -Aud $Aud -iss $Iss
        }
        catch{

            Set-PodeResponseStatus -Code 403
            $_ | Write-PodeErrorLog
            return $false
        }# If token not compliant with exp, nbf, iat, ver, aud and iss > 403
        
        # allow the next custom middleware or the route itself to run
        return $true
    }

    # You need to be authenticated AND have a role declared in the $WriteAccessRoles array
    $WriteAccessRequired = {
        # Same as above
        $EmptyAuthorizationHeader = [string]::IsNullOrWhiteSpace($WebEvent.Request.Headers.Authorization)
        if ($EmptyAuthorizationHeader) {
            Set-PodeResponseStatus -Code 403
            return $false
        }

        try{
            $Configs = $using:Config
            $Aud = $Configs['Audience']
            $Iss = $Configs['Issuers']  # Warning: Array

            $RequestAccessToken = $WebEvent.Request.Headers.Authorization
            $DecodedToken = ConvertFrom-Jwt -Token $RequestAccessToken
            Test-AADToken -AccessToken $RequestAccessToken -Aud $Aud -iss $Iss
        }
        catch{

            Set-PodeResponseStatus -Code 403
            $_ | Write-PodeErrorLog
            return $false
        }

        # Now token and authentication has been validated, let's validate the role
        $Authorized = $false
        [array]$Roles = $DecodedToken.TokenPayload.roles
        $Roles.ForEach({if($_ -in $using:WriteAccessRoles){$Authorized = $true}})
        if(-not $Authorized){
            Set-PodeResponseStatus -Code 401
            return $false
        } # You don't have the app role in the access token > 401

        return $true
    }

    # You need to be authenticated AND have a role declared in the $ReadAccessRoles array (same as above, but for read role)
    $ReadAccessRequired = {
        # Require a Authorization header
        $EmptyAuthorizationHeader = [string]::IsNullOrWhiteSpace($WebEvent.Request.Headers.Authorization)
        if ($EmptyAuthorizationHeader) {
            Set-PodeResponseStatus -Code 403
            return $false
        }

        try{
            $Configs = $using:Config
            $Aud = $Configs['Audience']
            $Iss = $Configs['Issuers']  # Warning: Array

            $RequestAccessToken = $WebEvent.Request.Headers.Authorization
            $DecodedToken = ConvertFrom-Jwt -Token $RequestAccessToken
            Test-AADToken -AccessToken $RequestAccessToken -Aud $Aud -iss $Iss
        }
        catch{

            Set-PodeResponseStatus -Code 403
            $_ | Write-PodeErrorLog
            return $false
        }

        # Now token and authentication has been validated, let's validate the role
        $Authorized = $false
        $RequestAccessToken = $WebEvent.Request.Headers.Authorization
        $DecodedToken = ConvertFrom-Jwt -Token $RequestAccessToken
        [array]$Roles = $DecodedToken.TokenPayload.roles
        $Roles.ForEach({if($_ -in $using:ReadAccessRoles){$Authorized = $true}})
        if(-not $Authorized){
            Set-PodeResponseStatus -Code 401
            return $false
        }
        

        # allow the next custom middleware or the route itself to run
        return $true
    }

    ####################################
    # End Middleware configuration
    ####################################

    Add-PodeRoute -Method Get -Path '/api/readfromhybrid' -Middleware $ReadAccessRequired -ScriptBlock {
        
        #Get the query parameter from the query (require more error handling as usual)
        $SamAccountName = $WebEvent.Query['samaccountname']

        $Script = {
            param($SamAccountName)
            # AES key that has been generated from the target machine (hardcoded for this POC)
            [Byte[]]$Key = @(214,234,128,193,229,128,66,17,101,143,108,66,153,101,6,206,34,149,225,88,255,29,161,70,47,47,99,224,230,46,4,73)
            # Rehydrate the PSCredential with hardcoded myorgaccount (use your AD service account here) and the encrypted password file located on the remote host
            $OrgCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'myorgaccount', (Get-Content 'C:\TEMP\secret.txt' | ConvertTo-SecureString -Key $Key)
            #Then do a simple get AD user with a query parameter
            get-aduser $SamAccountName -Credential $OrgCreds
        }

        # Use the local remote local creds to generate a pssession and send the scriptblock script trough the HTTPS listener
        $creds = [system.management.automation.pscredential]::new($Using:UserName,$Using:Password)
        $Data = invoke-command -ComputerName "<Hybrid Endpoint Name (machine name)>" -Authentication Basic -Credential $creds -Port 5986 -UseSSL -ScriptBlock $Script -ArgumentList $SamAccountName
        
        # Should have a better token validation here
        Write-PodeJsonResponse -Value $Data
    }
}