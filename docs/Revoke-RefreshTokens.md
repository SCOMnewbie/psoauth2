---
external help file: PsOauth2-help.xml
Module Name: psoauth2
online version: https://docs.microsoft.com/en-us/graph/api/user-revokesigninsessions
schema: 2.0.0
---

# Revoke-RefreshTokens

## SYNOPSIS
This function will revoke all refresh tokens of a specific users.
According to MS docs, it can take several minutes to revoke all tokens.

## SYNTAX

```
Revoke-RefreshTokens [-ObjectId] <Guid> [-AccessToken] <String> [<CommonParameters>]
```

## DESCRIPTION
This function will revoke all refresh tokens of a specific users.
According to MS docs, it can take several minutes to revoke all tokens.

## EXAMPLES

### EXAMPLE 1
```
# Generate an AT for the graph audience
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token
```

Revoke-RefreshTokens -ObjectId "55eb8a9a-e9fc-4781-9c98-56dd3393d5f4" -AccessToken $Token

Will revoke all refresh token for the user with the ObjectId 55eb8a9a-e9fc-4781-9c98-56dd3393d5f4

## PARAMETERS

### -ObjectId
Specify the objectId of the user.

```yaml
Type: Guid
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AccessToken
Specify the token to use to do the action.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
VERSION HISTORY
1.0 | 2020/01/04 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    - add UPN as parameter instead of just objectId

## RELATED LINKS

[https://docs.microsoft.com/en-us/graph/api/user-revokesigninsessions](https://docs.microsoft.com/en-us/graph/api/user-revokesigninsessions)

