---
external help file: PsOauth2-help.xml
Module Name: psoauth2
online version:
schema: 2.0.0
---

# New-APIServerToServerToken

## SYNOPSIS
This function is the same as the one in new-AccessToken without trying to write on disk caching.

## SYNTAX

### Secret
```
New-APIServerToServerToken -ClientId <Guid> -TenantId <Guid> [-Scope <String>] -Secret <String>
 [<CommonParameters>]
```

### Certificate
```
New-APIServerToServerToken -ClientId <Guid> -TenantId <Guid> [-Scope <String>] -CertificatePath <Object>
 [<CommonParameters>]
```

## DESCRIPTION
This function is the same as the one in new-AccessToken without trying to write on disk caching.
Just a copy paste because this POC start to take too long...

## EXAMPLES

### EXAMPLE 1
```
New-APIServerToServerToken -ClientId $ClientId -TenantId $TenantId -Secret 'secret'
```

"will request a server to server access token"

## PARAMETERS

### -ClientId
Specify the clientId

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
Specify the TenantId

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
Specify the scope.
Should always be ./default with this flow.

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
Specify the secret

```yaml
Type: String
Parameter Sets: Secret
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CertificatePath
Specify the CertificatePath

```yaml
Type: Object
Parameter Sets: Certificate
Aliases:

Required: True
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
    -

## RELATED LINKS
