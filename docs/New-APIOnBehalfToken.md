---
external help file: PsOauth2-help.xml
Module Name: psoauth2
online version:
schema: 2.0.0
---

# New-APIOnBehalfToken

## SYNOPSIS
This function will try an On Behalf Of (server to server with incoming user access token \> generate delegated access token).

## SYNTAX

```
New-APIOnBehalfToken -ClientId <Guid> -TenantId <Guid> [-Scope <String>] -Secret <String> [-Assertion <String>]
 [<CommonParameters>]
```

## DESCRIPTION
This function will try an On Behalf Of (server to server with incoming user access token \> generate delegated access token).
This function is not added
to new-accesstoken because I start to be tired and because it's not a end user function.
You should use it from backend api only.

## EXAMPLES

### EXAMPLE 1
```
$Splating @{
    ClientId = "<your backend appId>"
    TenantId = "<your TenantId>"
    Secret = <Generated app secret>
    Assertion = <caller access token>
}
```

New-APIOnBehalfToken @splating

"will generate a delegated access token"

## PARAMETERS

### -ClientId
Specify the clientId of your application

```yaml
Type: Guid
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TenantId
Specify the TenantId of your application

```yaml
Type: Guid
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Scope
Specify the scope the intermediate request will request.
By default ./default on Graph

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Https://graph.microsoft.com/.default
Accept pipeline input: False
Accept wildcard characters: False
```

### -Secret
Specify the secret of your backend appId to do the request

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Assertion
Specify the access token of the incoming request.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
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
    - Add certificate

## RELATED LINKS
