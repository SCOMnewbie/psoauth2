<#
.SYNOPSIS
This function will revoke all refresh tokens of a specific users. According to MS docs, it can take several minutes to revoke all tokens.
.DESCRIPTION
This function will revoke all refresh tokens of a specific users. According to MS docs, it can take several minutes to revoke all tokens.
.PARAMETER ObjectId
Specify the objectId of the user.
.PARAMETER AccessToken
Specify the token to use to do the action.
.EXAMPLE

# Generate an AT for the graph audience
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token

Revoke-RefreshTokens -ObjectId "55eb8a9a-e9fc-4781-9c98-56dd3393d5f4" -AccessToken $Token

Will revoke all refresh token for the user with the ObjectId 55eb8a9a-e9fc-4781-9c98-56dd3393d5f4

.NOTES
VERSION HISTORY
1.0 | 2020/01/04 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    - add UPN as parameter instead of just objectId
.LINK
https://docs.microsoft.com/en-us/graph/api/user-revokesigninsessions
#>
function Revoke-RefreshTokens {
    <#
    .SYNOPSIS
    This function will revoke all refresh tokens from a specific user.
    .DESCRIPTION
    This function will revoke all refresh tokens from a specific user.
    .PARAMETER ObjectId
    Specify the objectId of a specific user
    .PARAMETER AccessToken
    Specify the access token to do the action
    .EXAMPLE
    PS> $token = "Bearer {0}" -f (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token
    PS> Revoke-RefreshTokens -ObjectId $ObjId -AccessToken $token
    
    "will revoke all RT from the user ObjId"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/05/05 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [guid] $ObjectId, #ObjectId of the user
        [parameter(Mandatory)]
        [string] $AccessToken
    )
    $Headers = @{
        'Authorization' = $("Bearer $AccessToken")
        "Content-Type"  = 'application/json'
    }

    $Params = @{
        Headers     = $Headers
        uri         = "https://graph.microsoft.com/v1.0/users/$ObjectId/revokeSignInSessions,"
        Body        = $null
        StatusCodeVariable = 'StatusCode'
        Method      = 'POST'
    }

    try{
        Invoke-RestMethod @Params
        if($statusCode -ne 204){
            throw "didn't receid the 204 status code"
        }
    }
    catch{
        $_.Exception
    }
}