function New-DeviceCode {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    Write-Verbose 'New-DeviceCode - Begin function'

    # Force TLS 1.2.
    Write-Verbose 'New-DeviceCode - Force TLS 1.2'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    #Let hit the token endpoint for this second call
    Write-Verbose "New-DeviceCode - Contact Url https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"
        Body    = $null
        method  = 'Post'
    }

    $BodyPayload = @{
        client_id     = $Clientid
        scope         = $Scope
    }

    $Params.Body = $BodyPayload
    
    $response  = Invoke-RestMethod @Params

    if(-not $response.device_code)
    {
        throw "Device Code Flow failed"
    }
    else{
        Write-host "$($response.message)"
    }

    Write-Verbose 'New-DeviceCode - Code received now waiting for user authentication to process'

    $Params = @{
        Headers = $headers
        uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        Body    = $null
        method  = 'Post'
    }

    Write-Verbose 'New-DeviceCode - Define safety net to avoid infinite loop'

    $tokenResponse = $null
    $maxDate = (Get-Date).AddSeconds($response.expires_in)

    $BodyPayload = @{
        grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
        client_id = $Clientid
        device_code = $response.device_code
    }

    $Params.Body = $BodyPayload

    while (!$tokenResponse -and (Get-Date) -lt $maxDate)
    {
        $tokenResponse = Invoke-RestMethod @Params
        Write-Verbose 'New-DeviceCode - Give 5 more seconds to user to authenticate'
        start-sleep -Seconds 5
    }

    if($null -eq $tokenResponse){
        throw "New-DeviceCode - Token never received from AAD"
    }

    Write-Verbose 'New-DeviceCode - End function'

    return $tokenResponse
}