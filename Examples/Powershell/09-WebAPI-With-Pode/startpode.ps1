
Import-Module -Name Pode
Import-Module './usr/psoauth2.psm1' # Not comming from the gallery

# Get environment variable from WebApp/Keyvault
$Myappsecret = $env:Myappsecret
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

    # This is an anonymous route
    Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ 'hello' = 'world'}
    }

    # This route require to be authenticated
    Add-PodeRoute -Method Get -Path '/api/machinename' -Middleware $AuthenticationRequired -ScriptBlock {
        $Computername = hostname   # Should work on Linux too
        Write-PodeJsonResponse -Value @{ 'MachineName' = $Computername }
    }

    # This route require to be authenticated AND have the write.access or Admin.Access permission
    Add-PodeRoute -Method Get -Path '/api/authorizationheaderwithwriteaccess' -Middleware $WriteAccessRequired  -ScriptBlock {
        
        # Get info from config file
        $Configs = $using:Config
        $Aud = $Configs['Audience']
        $TenantId = $Configs['TenantId']

        $Splatting = @{
            ClientId             = $Aud                                    # Define in server.psd1
            TenantId             = $TenantId                               # Define in server.psd1
            Scope                = 'https://graph.microsoft.com/.default'
            secret               = $using:Myappsecret                      # Define in top of this script from environement variable (using: runspace)
            verbose              = $true
        }

        # Let's request a server to server token (should be cached and track in a DB to avoid hammering AAD)
        $Apptoken = New-APIServerToServerToken @Splatting

        #Let's now read all users tenant with this new token
        $uri = 'https://graph.microsoft.com/v1.0/users'
        $Users = Invoke-RestMethod -ContentType 'application/json' -Headers @{'Authorization' = "Bearer $Apptoken" } -Uri $uri -Method get

        Write-PodeJsonResponse -Value $Users
    }

    Add-PodeRoute -Method Get -Path '/api/authorizationheaderwithreadaccess' -Middleware $ReadAccessRequired  -ScriptBlock {
        
        # Get info from config file
        $Configs = $using:Config
        $Aud = $Configs['Audience']
        $TenantId = $Configs['TenantId']

        #Remove Bearer word from the received access token (forward user token with OBO)
        $RequestAccessToken = $WebEvent.Request.Headers.Authorization
        $RequestAccessTokenWithoutHeader = $RequestAccessToken.replace('Bearer ','')
        $OBOToken = (New-APIOnBehalfToken -TenantId $TenantId -Secret $using:Myappsecret -Assertion $RequestAccessTokenWithoutHeader -ClientId $Aud).access_token

        # Should have a better token validation here
        if($OBOToken){
            $Headers = @{
            'Authorization' = $OBOToken
            "Content-Type"  = 'application/json'
            }

            # What better than /me to validate a delegated token :)
            $Data = Invoke-RestMethod -Method get -Headers $Headers -Uri "https://graph.microsoft.com/v1.0/me"
            Write-PodeJsonResponse -Value $Data
        }
        else{        
            Set-PodeResponseStatus -Code 404
        }
    }
}