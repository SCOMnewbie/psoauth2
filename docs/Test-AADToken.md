---
external help file: PsOauth2-help.xml
Module Name: psoauth2
online version: https://docs.microsoft.com/en-us/graph/api/user-revokesigninsessions
schema: 2.0.0
---

# Test-AADToken

## SYNOPSIS
This function will verify the token we provide is valid according to our criteria.

## SYNTAX

```
Test-AADToken [-AccessToken] <String> [-Aud] <String> [-azp] <String> [[-ver] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function will verify the token we provide is valid according to our criteria.
For our demo, we will validate the token is sign by AAD
and the value inside the token respect our requirement.
This is pretty agressive for the demo.

## EXAMPLES

### EXAMPLE 1
```
Test-AADToken -aud $audience -azp $azp -AccessToken $token
```

"will validate if the token should be consummed by the api"

## PARAMETERS

### -AccessToken
Specify the access token to do the action

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Aud
Specify the audience of the request like https://graph.microsoft.com/ or api://myapi

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

### -azp
Specify the azp of the request.
In our case, the clientId from where the request has been sent (desktop app).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ver
Specify the version of the AAD endpoint used to generate the token.
In the demo it's 2.0

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: 2.0
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Boolean
## NOTES
VERSION HISTORY
1.0 | 2021/05/05 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    -

## RELATED LINKS
