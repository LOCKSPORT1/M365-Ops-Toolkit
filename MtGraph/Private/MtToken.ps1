function Get-MtServiceEndpoint {
    <#
    .SYNOPSIS
        Base URI for a service in this context's cloud.

    .DESCRIPTION
        Graph and Azure Resource Manager are different audiences. A token
        minted for graph.microsoft.com is rejected by management.azure.com,
        which is why the context caches one token per service rather than one
        token overall.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph'
    )

    if ($Service -eq 'ResourceManager') {
        return [string]$Context.Endpoints.ResourceManager
    }

    return [string]$Context.Endpoints.Graph
}

function Get-MtTokenSlot {
    <#
    .SYNOPSIS
        Returns (creating if needed) the token cache entry for one service.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph'
    )

    if (-not $Context.Tokens.ContainsKey($Service)) {
        $Context.Tokens[$Service] = @{
            AccessToken  = ''
            RefreshToken = ''
            AcquiredOn   = $null
            ExpiresOn    = $null
        }
    }

    return $Context.Tokens[$Service]
}

function Get-MtAnyRefreshToken {
    <#
    .SYNOPSIS
        Finds a refresh token already held for any service.

    .DESCRIPTION
        In the delegated flows a refresh token is not audience-bound: one
        obtained for Graph can be redeemed for an Azure Resource Manager access
        token. Reusing it means the operator signs in once per session rather
        than once per service.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    foreach ($key in @($Context.Tokens.Keys)) {
        $candidate = [string]$Context.Tokens[$key].RefreshToken
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return $candidate
        }
    }

    return ''
}

function Get-MtTokenEndpoint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Context
    )

    return ('{0}/{1}/oauth2/v2.0/token' -f $Context.Endpoints.Login, $Context.TenantId)
}

function Set-MtToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [object]$Payload,

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph'
    )

    $slot = Get-MtTokenSlot -Context $Context -Service $Service
    $expiresIn = [int](Get-MtProperty -InputObject $Payload -Name 'expires_in' -Default 3600)

    $slot.AccessToken = [string](Get-MtProperty -InputObject $Payload -Name 'access_token' -Default '')
    $slot.AcquiredOn = [DateTimeOffset]::UtcNow
    $slot.ExpiresOn = ([DateTimeOffset]::UtcNow).AddSeconds($expiresIn)

    $refresh = Get-MtProperty -InputObject $Payload -Name 'refresh_token' -Default $null
    if (-not [string]::IsNullOrWhiteSpace([string]$refresh)) {
        $slot.RefreshToken = [string]$refresh
    }

    if ([string]::IsNullOrWhiteSpace($slot.AccessToken)) {
        throw "Token endpoint returned no access_token for tenant '$($Context.TenantId)' (service $Service)."
    }
}

function Resolve-MtOAuthError {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Response
    )

    $code = [string](Get-MtProperty -InputObject $Response.Object -Name 'error' -Default '')
    $description = [string](Get-MtProperty -InputObject $Response.Object -Name 'error_description' -Default '')

    if ([string]::IsNullOrWhiteSpace($code) -and [string]::IsNullOrWhiteSpace($description)) {
        return $Response.Text
    }

    # error_description is multi-line and carries the correlation id; keep the
    # first line for the message and let the run log hold the rest.
    $firstLine = ($description -split "`r?`n")[0]
    return ('{0}: {1}' -f $code, $firstLine).Trim(': ')
}

function Request-MtDeviceCodeToken {
    <#
    .SYNOPSIS
        Delegated interactive sign-in. Useful for GDAP work where the operator's
        own permissions, not an app identity, should carry the action.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph'
    )

    $deviceCodeUri = '{0}/{1}/oauth2/v2.0/devicecode' -f $Context.Endpoints.Login, $Context.TenantId
    $tokenUri = Get-MtTokenEndpoint -Context $Context
    $scope = '{0}/.default offline_access' -f (Get-MtServiceEndpoint -Context $Context -Service $Service)

    $startBody = ConvertTo-MtFormBody -Fields @{
        client_id = $Context.ClientId
        scope     = $scope
    }

    $start = Invoke-MtHttp -Uri $deviceCodeUri -Method 'POST' -Body $startBody -ContentType 'application/x-www-form-urlencoded'

    if (-not $start.Success) {
        $detail = Resolve-MtOAuthError -Response $start
        throw "Device code request failed for tenant '$($Context.TenantId)' (HTTP $($start.StatusCode)): $detail"
    }

    $message = [string](Get-MtProperty -InputObject $start.Object -Name 'message' -Default 'Complete sign-in in your browser.')
    Write-Host ''
    Write-Host $message -ForegroundColor Cyan
    Write-Host ''

    $interval = [int](Get-MtProperty -InputObject $start.Object -Name 'interval' -Default 5)
    $expiresIn = [int](Get-MtProperty -InputObject $start.Object -Name 'expires_in' -Default 900)
    $deviceCode = [string](Get-MtProperty -InputObject $start.Object -Name 'device_code' -Default '')
    $deadline = (Get-Date).AddSeconds($expiresIn)

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval

        $pollBody = ConvertTo-MtFormBody -Fields @{
            client_id   = $Context.ClientId
            grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
            device_code = $deviceCode
        }

        $poll = Invoke-MtHttp -Uri $tokenUri -Method 'POST' -Body $pollBody -ContentType 'application/x-www-form-urlencoded'

        if ($poll.Success) {
            Set-MtToken -Context $Context -Payload $poll.Object -Service $Service
            return (Get-MtTokenSlot -Context $Context -Service $Service)
        }

        $errorCode = [string](Get-MtProperty -InputObject $poll.Object -Name 'error' -Default '')

        # Deliberately if/elseif rather than switch: 'continue' inside a switch
        # continues the switch, not the enclosing while loop.
        if ($errorCode -eq 'authorization_pending') {
            continue
        }
        elseif ($errorCode -eq 'slow_down') {
            $interval = $interval + 5
            continue
        }
        else {
            $detail = Resolve-MtOAuthError -Response $poll
            throw "Device code authentication failed for tenant '$($Context.TenantId)': $detail"
        }
    }

    throw "Device code authentication timed out for tenant '$($Context.TenantId)'."
}

function Request-MtToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph'
    )

    $tokenUri = Get-MtTokenEndpoint -Context $Context
    $scope = '{0}/.default' -f (Get-MtServiceEndpoint -Context $Context -Service $Service)
    $slot = Get-MtTokenSlot -Context $Context -Service $Service
    $fields = $null

    if ($Context.AuthMode -eq 'Certificate') {
        $assertion = New-MtClientAssertion -Certificate $Context.Auth.Certificate -ClientId $Context.ClientId -Audience $tokenUri
        $fields = @{
            client_id             = $Context.ClientId
            scope                 = $scope
            grant_type            = 'client_credentials'
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $assertion
        }
    }
    elseif ($Context.AuthMode -eq 'ClientSecret') {
        $fields = @{
            client_id     = $Context.ClientId
            scope         = $scope
            grant_type    = 'client_credentials'
            client_secret = (ConvertFrom-MtSecureString -Secure $Context.Auth.ClientSecret)
        }
    }
    elseif ($Context.AuthMode -eq 'DeviceCode') {
        # A refresh token held for any service can be redeemed for this one,
        # so a second audience does not mean a second sign-in prompt.
        $refreshToken = [string]$slot.RefreshToken
        if ([string]::IsNullOrWhiteSpace($refreshToken)) {
            $refreshToken = Get-MtAnyRefreshToken -Context $Context
        }

        if ([string]::IsNullOrWhiteSpace($refreshToken)) {
            return (Request-MtDeviceCodeToken -Context $Context -Service $Service)
        }

        $fields = @{
            client_id     = $Context.ClientId
            scope         = ('{0} offline_access' -f $scope)
            grant_type    = 'refresh_token'
            refresh_token = $refreshToken
        }
    }
    else {
        throw "Unsupported AuthMode '$($Context.AuthMode)' on context '$($Context.Name)'."
    }

    $response = Invoke-MtHttp -Uri $tokenUri -Method 'POST' -Body (ConvertTo-MtFormBody -Fields $fields) -ContentType 'application/x-www-form-urlencoded'

    if (-not $response.Success) {
        # A stale refresh token should fall back to interactive rather than hard fail.
        if ($Context.AuthMode -eq 'DeviceCode') {
            Write-Verbose 'Refresh token rejected; restarting device code flow.'
            $slot.RefreshToken = ''
            return (Request-MtDeviceCodeToken -Context $Context -Service $Service)
        }

        $detail = Resolve-MtOAuthError -Response $response
        throw "Token request failed for tenant '$($Context.TenantId)' service $Service (HTTP $($response.StatusCode)): $detail"
    }

    Set-MtToken -Context $Context -Payload $response.Object -Service $Service
    return (Get-MtTokenSlot -Context $Context -Service $Service)
}

function Get-MtValidToken {
    <#
    .SYNOPSIS
        Returns a live access token for one service, refreshing inside a five
        minute skew window.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph',

        [switch]$Force
    )

    $slot = Get-MtTokenSlot -Context $Context -Service $Service
    $skew = [TimeSpan]::FromMinutes(5)
    $needsToken = $true

    if (-not $Force) {
        $hasToken = -not [string]::IsNullOrWhiteSpace([string]$slot.AccessToken)
        if ($hasToken -and $null -ne $slot.ExpiresOn) {
            $remaining = ([DateTimeOffset]$slot.ExpiresOn) - [DateTimeOffset]::UtcNow
            if ($remaining -gt $skew) {
                $needsToken = $false
            }
        }
    }

    if ($needsToken) {
        $null = Request-MtToken -Context $Context -Service $Service
    }

    return [string]$slot.AccessToken
}
