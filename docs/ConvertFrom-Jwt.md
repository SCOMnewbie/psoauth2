---
external help file: PsOauth2-help.xml
Module Name: psoauth2
online version:
schema: 2.0.0
---

# ConvertFrom-Jwt

## SYNOPSIS
This function will decode a base64 JWT token.

## SYNTAX

```
ConvertFrom-Jwt [-Token] <String> [<CommonParameters>]
```

## DESCRIPTION
Big thank you to both Darren Robinson (https://github.com/darrenjrobinson/JWTDetails/blob/master/JWTDetails/1.0.0/JWTDetails.psm1) and
Mehrdad Mirreza in the comment of the blog post (https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell)
I've used both article for inspiration because:
Darren does not have header wich is a mandatory peace according to me and Mehrdad does not have signature which is also a mandatory piece.

## EXAMPLES

### EXAMPLE 1
```
ConvertFrom-Jwt -Token "ey...."
```

"will decode the token"

## PARAMETERS

### -Token
Specify the access token you want to decode

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
VERSION HISTORY
1.0 | 2021/07/06 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    -

## RELATED LINKS
