
<#
    # INTRO

    So now we can access our app without any secrets, how can can we avoid having to type your password at every authentications?
    This is where OIDC permissions comes into place. Under the app registration/Api permissions/delegated, you can find:
    * email > Giver permission to the app to read your primary email information
    * offline_access > Return Refresh Token 
    * openid > Return the Id Token. Like the [cmdletbinding], this scope permit us to use other parameter (email, offline_access, profile)
    * profile > expose your basic profile

    To make it short, an access token is not for your client application. You SHOULD NOT USE IT within your client app. For your application, you can rely on the Id Token to see
    who is currently authenticated to your app. It's a JWT that you can decode to use the information inside. 
    More information here: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc

    In this demo, we will re-use the auth code PKCE flow to get our refresh token and see what happen when we change the scopes!
    All flows does not have refresh tokens available: https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-authentication-flows#how-each-flow-emits-tokens-and-codes

    # DEMO
        For simplicity, we will create 4 applications and see in parallel what are the differences:
        We will create 5:
        * An PUBLIC app registration account (Means all the tenant + guest accounts can log in)
            * As usual V2 endpoint enforced, single tenant enforced from my PSAADApplication module
        * Add a service principal on it (it becomes an app with an identity)
        * I won't enforce the assignment this time (too painful for the demo :p)
        * And create a new app called joker. (Add a logo to the app because why not > Fail the logo is on the other repo, but you can use Add-AppRegistrationLogo)
        * Play with OIDC scopes
        * Delete the apps

    In this demo, I will use the beta graph api endpoint to list the authetication method a user have assigned.

    Notes: To get the Id you have to use in your app registration manifest, you can use:
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id
    Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "openid" | % id


#>

throw "don't press F5"

#Use the previously created module
Import-Module 'C:\Git\Private\psoauth2\Examples\PSAADApplication.psd1'
Import-Module 'C:\Git\Private\psoauth2\psoauth2\psoauth2.psd1'

# To avoid surprises when you had generated a cache on another tenant :p
Clear-TokenCache

#Define variable for the demo
$TenantId = '9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20'

# This time we need our token right away!
$token = 'Bearer {0}' -f (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token

$Apps = @('openid','offline_access','email','profile','joker')
foreach ($App in $Apps) {
    switch ($App) {
        'openid' {
            $SettingsOpenId = @{
                displayName            = 'DemoPublicAppOpenId'
                publicClient           = @{
                    redirectUris = @(
                        'https://login.microsoftonline.com/common/oauth2/nativeclient'  # Array here can have multiple values
                    )
                }
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
                        resourceAccess = @(
                            @{
                                id   = 'b7887744-6746-4312-813d-72daeaee7e2d' # Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "UserAuthenticationMethod.ReadWrite.All" | % i
                                type = 'Scope' #Role means application, Scope means delegated. delegated and application does not have the same id for the same type.
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'openid' | ForEach-Object id) # OpenId permission Id
                                type = 'Scope'
                            }
                        )
                    }
                )
            }
            break
        }
        'offline_access' {
            $SettingsOfflineAccess = @{
                displayName            = 'DemoPublicAppOfflineAccess'
                publicClient           = @{
                    redirectUris = @(
                        'https://login.microsoftonline.com/common/oauth2/nativeclient'  # Array here can have multiple values
                    )
                }
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
                        resourceAccess = @(
                            @{
                                id   = 'b7887744-6746-4312-813d-72daeaee7e2d' # Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "UserAuthenticationMethod.ReadWrite.All" | % i
                                type = 'Scope' #Role means application, Scope means delegated. delegated and application does not have the same id for the same type.
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'openid' | ForEach-Object id) # OpenId permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'offline_access' | ForEach-Object id) # delegated offline-access permission Id
                                type = 'Scope'
                            }
                        )
                    }
                )
            }
            break
        }
        'email' {
            $SettingsEmail = @{
                displayName            = 'DemoPublicAppEmail'
                publicClient           = @{
                    redirectUris = @(
                        'https://login.microsoftonline.com/common/oauth2/nativeclient'  # Array here can have multiple values
                    )
                }
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
                        resourceAccess = @(
                            @{
                                id   = 'b7887744-6746-4312-813d-72daeaee7e2d' # Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "UserAuthenticationMethod.ReadWrite.All" | % i
                                type = 'Scope' #Role means application, Scope means delegated. delegated and application does not have the same id for the same type.
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'openid' | ForEach-Object id) # OpenId permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'offline_access' | ForEach-Object id) # delegated offline-access permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'email' | ForEach-Object id) # delegated email permission Id
                                type = 'Scope'
                            }
                        )
                    }
                )
            }
            break
        }
        'profile' {
            $SettingsProfile = @{
                displayName            = 'DemoPublicAppProfile'
                publicClient           = @{
                    redirectUris = @(
                        'https://login.microsoftonline.com/common/oauth2/nativeclient'  # Array here can have multiple values
                    )
                }
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
                        resourceAccess = @(
                            @{
                                id   = 'b7887744-6746-4312-813d-72daeaee7e2d' # Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "UserAuthenticationMethod.ReadWrite.All" | % i
                                type = 'Scope' #Role means application, Scope means delegated. delegated and application does not have the same id for the same type.
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'openid' | ForEach-Object id) # OpenId permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'offline_access' | ForEach-Object id) # delegated offline-access permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'email' | ForEach-Object id) # delegated email permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'profile' | Where-Object value -ne 'OnPremisesPublishingProfiles.ReadWrite.All' | ForEach-Object id) # delegated profile permission Id. And yes 2 API has the word profile so I have to escape the wrong one.
                                type = 'Scope'
                            }
                        )
                    }
                )
            }
            break
        }
        'joker' {
            $SettingsJoker = @{
                displayName            = 'DemoPublicAppJoker'
                publicClient           = @{
                    redirectUris = @(
                        'https://login.microsoftonline.com/common/oauth2/nativeclient'  # Array here can have multiple values
                    )
                }
                requiredResourceAccess = @(
                    @{
                        resourceAppId  = '00000003-0000-0000-c000-000000000000' #well know graph API
                        resourceAccess = @(
                            @{
                                id   = 'b7887744-6746-4312-813d-72daeaee7e2d' # Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword "UserAuthenticationMethod.ReadWrite.All" | % i
                                type = 'Scope' #Role means application, Scope means delegated. delegated and application does not have the same id for the same type.
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'openid' | ForEach-Object id) # OpenId permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'offline_access' | ForEach-Object id) # delegated offline-access permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'email' | ForEach-Object id) # delegated email permission Id
                                type = 'Scope'
                            },
                            @{
                                id   = $(Get-APIScopesInfo -AccessToken $token -Deleguated -ScopeKeyword 'profile' | Where-Object value -NE 'OnPremisesPublishingProfiles.ReadWrite.All' | ForEach-Object id) # delegated profile permission Id. And yes 2 API has the word profile so I have to escape the wrong one.
                                type = 'Scope'
                            }
                        )
                    }
                )
                groupMembershipClaims  = 'SecurityGroup' # Add information into groups property into the ClientId token. Value can be: none/all (both SG and DL)/SecurityGroup
                optionalClaims         = @{
                    idToken = @(
                        @{
                            name = 'ipaddr' #Will add the client ip address in the IDToken (not available by default)
                        }
                    )
                }
            }
            break
        }
    }
}

#Now that all our settings are defined, let's create all the app
$FutureNuke = @()
Foreach ($Settings in @($SettingsOpenId,$SettingsOfflineAccess,$SettingsEmail,$SettingsProfile,$SettingsJoker)) {
    #Convert settings into Json
    $AppsettingsJson = Convert-SettingsToJson -TemplateSettings $Settings
    #Crete the app registration
    $AppRegistration = New-AppRegistration -AccessToken $token -InputWithVariable $AppsettingsJson
    # Save for later nuke (array)
    $FutureNuke += $AppRegistration

}

#######################################
#    IMPORTANT
# Here you can open the portal, for demo purpose, still grant admin consent :) / At least in the openId one.
##########################################

<#
# Now our apps are created, let's recap what we have:

* DemoPublicAppOpenId:
    * API Permission: openId
* DemoPublicAppOfflineAccess:
    * API Permission: openId,offline_access
* DemoPublicAppEmail:
    * API Permission: openId,offline_access, email
* DemoPublicAppProfile:
    * API Permission: openId,offline_access, email, profile
* DemoPublicAppJoker:
    * API Permission: openId,offline_access, email, profile
    * Token config:
        * Optionnal claims: ipaddr
        * Group claims : Security groups
#>

# Let's work on DemoPublicAppOpenId first and see what do we have into our JWT tokens (Access Tokken + Id Token).

$Splatting = @{
    Resource     = $($FutureNuke | where displayname -eq 'DemoPublicAppOpenId' | % AppId)
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All OpenId' # IMPORTANT, we have to change the scope here (add openId) ! 
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting

# Paste the accestoekn in to JWT.ms website
# Don't forget this is just for demo purpose
$AccessToken | clip

#Now check the interesting part, the ID Token
# If you're on Linux, use this instead: $HOMEPath = [Environment]::GetEnvironmentVariable('HOME')

# Let's read the cache, this is where we can find the Tokens information
$HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
$FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"
$Cache = Get-Content $FullPath -Raw | ConvertFrom-Json | where resource -eq $($FutureNuke | where displayname -eq 'DemoPublicAppOpenId' | % AppId)

#Let's now copy/paste the Id Token in JWT.ms
$Cache.idToken | clip

<#
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg"
}.{
  "aud": "2edd9158-1055-4bd2-9798-8a0e19b83890",
  "iss": "https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/v2.0",
  "iat": 1621603519,
  "nbf": 1621603519,
  "exp": 1621607419,
  "rh": "0.AVwAQIDEn4y9P0-3s_8Xy_BLIFiR3S5VENJLl5iKDhm4OJBcAKo.",
  "sub": "KJQIbgwRO2t1S0iDB2C8PFsFkHfMLX2Du00sbqtcpZU",
  "tid": "9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20",
  "uti": "wnBhcT0B00eesOW6JquBAA",
  "ver": "2.0"
}.[Signature]
#>

# No refresh token yet :)

# Let's switch to the SettingsOfflineAccess app (add more scope)
Clear-TokenCache

$Splatting = @{
    Resource     = $($FutureNuke | where displayname -eq 'DemoPublicAppOfflineAccess' | % AppId)
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All OpenId offline_access' # IMPORTANT, we have to change the scope here (add openId) ! 
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting
# REad cache
$HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
$FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"
$Cache = Get-Content $FullPath -Raw | ConvertFrom-Json | where resource -eq $($FutureNuke | where displayname -eq 'DemoPublicAppOfflineAccess' | % AppId)

# LLet's compare the id token
$Cache.idToken | clip

# Basically, this is the same thing ... 
# Keep an eye on the sub claim, this is a part of what you can use in your app. Go check online stuff if you need more info

# And now we have a Refresh Token too ! What is that !

<#
Access token are short lived token (usually 1 hour). Once the AT is expired, you have to either re-authenticate to AAD interractively or you can use Refresh token (RT). 
Both RT and AT are considered as secret values and should be comitted into a repo.
When you use the RT, a query is made to AAD. You won't be able to use your RT if AAD consider you have to re-authenticate interractively (MFA, admin kill your sessions, E5 features...).
Otherwise, you can use it indefinitely to silently re-authenticate. Let's try.

Note: When you will re-authentate with RT, you will receive both a new AT (to do your request) and a new RT. Store the 2 and remove the older one.

#>

# The new-accesstoken function manage both expired and  non expired token. Let's wait one hour and see ... Yeah I know 
$Splatting = @{
    Resource     = $($FutureNuke | where displayname -eq 'DemoPublicAppOfflineAccess' | % AppId)
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All OpenId offline_access' # IMPORTANT, we have to change the scope here (add openId) ! 
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}
$AccessToken = New-AccessToken @Splatting

<#
If token not expired, you should receive:
...
VERBOSE: Get-TokenFromCache - Read cache file
VERBOSE: Get-TokenFromCache - Context detected
VERBOSE: Get-TokenFromCache - End function
VERBOSE: New-AccessToken - Cache context found
VERBOSE: New-AccessToken - Auth code flow selected
VERBOSE: New-AccessToken - Access token not expired, go use it


And when the token will be expired:
...
VERBOSE: New-AccessToken - Access token is expired and a refresh token is found in the cache, go use it
VERBOSE: New-RefreshToken - Force TLS 1.2
VERBOSE: New-RefreshToken - Contact Url https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/oauth2/v2.0/token 
VERBOSE: New-RefreshToken - RedirectURI provided add it to the body
VERBOSE: POST https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/oauth2/v2.0/token with 1432-byte payload
VERBOSE: New-AccessToken - update the context in the cache

This is where I generate both AT/ID tokens and re-generate the context in my cache file.
#>


# During this time, let's work on the 3 other applications
# We've seen that when we add offline_access, the difference is "only" the RT. If we now add the email scope

$Splatting = @{
    Resource     = $($FutureNuke | where displayname -eq 'DemoPublicAppEmail' | % AppId)
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All OpenId offline_access email' # IMPORTANT, we have to change the scope here (add email) ! 
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting
# REad cache
$HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
$FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"
$Cache = Get-Content $FullPath -Raw | ConvertFrom-Json | where resource -eq $($FutureNuke | where displayname -eq 'DemoPublicAppEmail' | % AppId)

# LLet's compare the id token
$Cache.idToken | clip

# And we can see we have the email field/claim into the Id Token
<#
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg"
}.{
  "aud": "8c39ce1b-a6c8-4d26-8191-5fca676dcfd3",
  "iss": "https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/v2.0",
  "iat": 1621625248,
  "nbf": 1621625248,
  "exp": 1621629148,
  "email": "scomnewbie@mytenant.onmicrosoft.com",
  "rh": "0.AVwAQIDEn4y9P0-3s_8Xy_BLIBvOOYzIpiZNgZFfymdtz9NcAKo.",
  "sub": "ar0DD-aeJnMq42jei3UTWTqN2k_NgpaBne9qEUL9IFs",
  "tid": "9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20",
  "uti": "bd4tlmBoLUOcwlPyh56fAA",
  "ver": "2.0"
}.[Signature]
#>

# Now with profile

$Splatting = @{
    Resource     = $($FutureNuke | where displayname -eq 'DemoPublicAppProfile' | % AppId)
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All OpenId offline_access email profile' # IMPORTANT, we have to change the scope here (add email) ! 
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting
# REad cache
$HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
$FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"
$Cache = Get-Content $FullPath -Raw | ConvertFrom-Json | where resource -eq $($FutureNuke | where displayname -eq 'DemoPublicAppProfile' | % AppId)

# LLet's compare the id token
$Cache.idToken | clip

# And we should see
<#
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg"
}.{
  "aud": "759d26e8-1d85-47bf-acae-776dab36de58",
  "iss": "https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/v2.0",
  "iat": 1621625496,
  "nbf": 1621625496,
  "exp": 1621629396,
  "email": "scomnewbie@mytenant.onmicrosoft.com",
  "name": "Francois LEON",
  "oid": "b45950e0-2c89-4a1f-9ac4-9c6ddbb42db4",
  "preferred_username": "scomnewbie@mytenant.onmicrosoft.com",
  "rh": "0.AVwAQIDEn4y9P0-3s_8Xy_BLIOgmnXWFHb9HrK53bas23lhcAKo.",
  "sub": "9VW92O9W0XL2ZborbszXoC9DR7QXocpp80SyReOZj44",
  "tid": "9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20",
  "uti": "8g2L1Q2GX0KQa6mCzr-CAA",
  "ver": "2.0"
}.[Signature]
#>


# INTERRESTING FACTS !
<#
    Adding the profile scopes add few other claims. But here the important thing to know:
    * sub: Is a unique id for your user per app
    * oid: Is the unique id for your user per tenant (useful for multitenant app)

    Good practice: Do a contatenation in your app to be 100% sure to have a unique id for a user cross app/tenant

    Now and this is the Joker app: What if I want to add more claims to my Id token. You can customize the id token (and maybe access). Check the app definition above.
#>

# Let's connect to the app and the the result.


$Splatting = @{
    Resource     = $($FutureNuke | where displayname -eq 'DemoPublicAppJoker' | % AppId)
    TenantId     = $TenantId
    Scope        = 'https://graph.microsoft.com/UserAuthenticationMethod.ReadWrite.All OpenId offline_access email profile' # IMPORTANT, .default won't give you RT and co.
    RedirectUri  = 'https://login.microsoftonline.com/common/oauth2/nativeclient' # RedirectURI defined on the app
    AuthCodeFlow = $true
    verbose      = $true
}

# Follow what the console will ask you like open a browser,  paste the code and authenticate.
$AccessToken = New-AccessToken @Splatting
# REad cache
$HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
$FullPath = Join-Path -Path $HOMEPath -ChildPath ".psoauth2" -AdditionalChildPath "accessTokens.json"
$Cache = Get-Content $FullPath -Raw | ConvertFrom-Json | where resource -eq $($FutureNuke | where displayname -eq 'DemoPublicAppJoker' | % AppId)

# LLet's compare the id token
$Cache.idToken | clip

# An now we can see:
<#
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "nOo3ZDrODXEK1jKWhXslHR_KXEg"
}.{
  "aud": "43204a4c-e924-47fc-bb57-529b95f256d8",
  "iss": "https://login.microsoftonline.com/9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20/v2.0",
  "iat": 1621626353,
  "nbf": 1621626353,
  "exp": 1621630253,
  "email": "scomnewbie@mytenant.onmicrosoft.com",
  "groups": [
    "ad65bf4a-01ae-4e42-b55f-8ba90c4285c1"
  ],
  "ipaddr": "185.143.28.98",
  "name": "Francois LEON",
  "oid": "b45950e0-2c89-4a1f-9ac4-9c6ddbb42db4",
  "preferred_username": "scomnewbie@mytenant.onmicrosoft.com",
  "rh": "0.AVwAQIDEn4y9P0-3s_8Xy_BLIExKIEMk6fxHu1dSm5XyVthcAKo.",
  "sub": "9RkEeAtO52HQqnGrLrnMqLQImUQ2gXQ0tzHksdQZJSA",
  "tid": "9fc48040-bd8c-4f3f-b7b3-ff17cbf04b20",
  "uti": "C1pJE0hRDEykkXDvf92oAA",
  "ver": "2.0"
}.[Signature]
#>

# Of course now we can query the auth methods and blablabla ...

<#
Key takeaways:

    - You can have an RT only if you specify at least the openid and the offline_access scopes.
    - You will receive both the oid and sub with the profile scope
    - We can reuse the RT (no interraction) until AAD consider we have to interractively authenticate
    - Still no password required :)
    - Don't hesitate to use the PSAADApplication module to create several app in //. Soon we will create a frontend that will create a backend API !
    - The .default (client credential flows only?) does not work anymore. You will receive an AT, but no RT/Idtoken

I think we now have enough demo for simple apps. Let's now play with multiple tiers app :D.

#>

#End of demo remove the app registration
#Just in case
$token = 'Bearer {0}' -f (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/').Token
$FutureNuke.Id.ForEach({Remove-AppRegistration -AccessToken $token -ObjectId $_})