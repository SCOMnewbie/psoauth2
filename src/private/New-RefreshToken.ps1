Function New-RefreshToken {
    [cmdletbinding()]
    param(
        [guid]$Clientid,
        [string]$RedirectUri,
        [string]$Scope,
        $TenantId,
        $RefreshToken,
        $secret
    )

    Write-Verbose 'New-RefreshToken - Begin function'

    # Force TLS 1.2.
    Write-Verbose 'New-RefreshToken - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }
    
    #Let hit the token endpoint for this second call
    Write-Verbose "New-RefreshToken - Contact Url https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Body    = $null
        method  = 'Post'
    }
    
    if ($secret) {

        Write-Verbose 'New-RefreshToken - Secret provided add it to the body'

        $BodyPayload = @{
            client_id     = $Clientid
            scope         = $Scope
            redirect_uri  = $RedirectUri
            grant_type    = 'refresh_token'
            refresh_token = $RefreshToken
            client_secret = $secret
        }
    }
    else {
        if ($RedirectUri) {

            Write-Verbose 'New-RefreshToken - RedirectURI provided add it to the body'

            $BodyPayload = @{
                client_id     = $Clientid
                scope         = $Scope
                redirect_uri  = $RedirectUri
                grant_type    = 'refresh_token'
                refresh_token = $RefreshToken
            }
        }
        else {
            
            Write-Verbose 'New-RefreshToken - Create simple body'

            $BodyPayload = @{
                client_id     = $Clientid
                scope         = $Scope
                grant_type    = 'refresh_token'
                refresh_token = $RefreshToken
            }
        }
    }

    $Params.Body = $BodyPayload
    
    Write-Verbose 'New-RefreshToken - End function'

    Invoke-RestMethod @Params
}