function New-MtGraphErrorRecord {
    <#
    .SYNOPSIS
        Builds an ErrorRecord carrying the Graph error code, correlation id and
        request id, so a failure in a ticket is actionable without a repro.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.ErrorRecord])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [object]$Response,

        [int]$Attempt = 1
    )

    $graphError = Get-MtProperty -InputObject $Response.Object -Name 'error' -Default $null
    $code = [string](Get-MtProperty -InputObject $graphError -Name 'code' -Default '')
    $message = [string](Get-MtProperty -InputObject $graphError -Name 'message' -Default '')

    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = $Response.Text
    }

    $requestId = [string]$Response.Headers['request-id']
    $clientRequestId = [string]$Response.Headers['client-request-id']
    $date = [string]$Response.Headers['Date']

    $text = 'Graph {0} {1} failed for tenant "{2}" after {3} attempt(s). HTTP {4} {5}: {6} [request-id: {7}]' -f `
        $Method, $Url, $Context.Name, $Attempt, $Response.StatusCode, $code, $message, $requestId

    $details = @{
        tenant          = $Context.Name
        tenantId        = $Context.TenantId
        method          = $Method
        url             = $Url
        statusCode      = $Response.StatusCode
        graphCode       = $code
        graphMessage    = $message
        requestId       = $requestId
        clientRequestId = $clientRequestId
        serviceDate     = $date
        attempts        = $Attempt
    }

    $exception = New-Object System.Exception -ArgumentList $text

    # Exception.Data travels with the exception through throw/rethrow. A
    # NoteProperty on the ErrorRecord does not: PowerShell rebuilds the record,
    # and the correlation ids you actually need for a support case vanish.
    $exception.Data['MtGraph'] = $details

    $errorId = 'MtGraph.{0}.{1}' -f $Response.StatusCode, $(if ([string]::IsNullOrWhiteSpace($code)) { 'Unknown' } else { $code })

    $record = New-Object System.Management.Automation.ErrorRecord -ArgumentList @(
        $exception
        $errorId
        [System.Management.Automation.ErrorCategory]::InvalidResult
        $Url
    )

    return $record
}

function Invoke-MtGraphCall {
    <#
    .SYNOPSIS
        One Graph call with the retry policy applied. Private to the pipeline;
        Invoke-MtGraphRequest owns URL shaping, gating and paging.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$Url,

        [string]$Method = 'GET',

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph',

        [AllowNull()]
        [string]$BodyJson = $null,

        [hashtable]$ExtraHeaders = @{},

        [int]$MaxRetry = 5,

        [int]$TimeoutSec = 120
    )

    $attempt = 0
    $lastStatus = 0
    $retryableStatus = @(429, 500, 502, 503, 504)

    while ($true) {
        $attempt++

        $forceRefresh = ($attempt -gt 1 -and $lastStatus -eq 401)
        $token = Get-MtValidToken -Context $Context -Service $Service -Force:$forceRefresh

        $headers = @{
            'Authorization'     = ('Bearer {0}' -f $token)
            'Accept'            = 'application/json'
            'client-request-id' = [guid]::NewGuid().ToString()
        }

        foreach ($key in $ExtraHeaders.Keys) {
            $headers[$key] = $ExtraHeaders[$key]
        }

        $httpSplat = @{
            Uri        = $Url
            Method     = $Method
            Headers    = $headers
            TimeoutSec = $TimeoutSec
        }

        if (-not [string]::IsNullOrWhiteSpace($BodyJson)) {
            $httpSplat['Body'] = $BodyJson
        }

        $response = Invoke-MtHttp @httpSplat
        $lastStatus = $response.StatusCode

        if ($response.Success) {
            return $response
        }

        # A 401 on a token we believed was live means revocation or a CA change.
        # Burn the cache and try exactly once more before giving up.
        if ($response.StatusCode -eq 401 -and $attempt -eq 1) {
            Write-Verbose ('401 on {0} {1}; refreshing token and retrying once.' -f $Method, $Url)
            (Get-MtTokenSlot -Context $Context -Service $Service).AccessToken = ''
            continue
        }

        if (($retryableStatus -contains $response.StatusCode) -and $attempt -le $MaxRetry) {
            $wait = Get-MtBackoffSeconds -Attempt $attempt -RetryAfterHeader ([string]$response.Headers['Retry-After'])

            Write-MtLog -Level 'Warning' -Context $Context -Message ('HTTP {0} on {1} {2}; backing off {3}s (attempt {4} of {5}).' -f $response.StatusCode, $Method, $Url, $wait, $attempt, $MaxRetry) -Data @{
                statusCode = $response.StatusCode
                url        = $Url
                attempt    = $attempt
            }

            Start-Sleep -Seconds $wait
            continue
        }

        $record = New-MtGraphErrorRecord -Context $Context -Method $Method -Url $Url -Response $response -Attempt $attempt

        Write-MtLog -Level 'Error' -Context $Context -Message $record.Exception.Message -Data @{
            statusCode = $response.StatusCode
            url        = $Url
            body       = $response.Text
        }

        # Cleanup and logging complete; the throw stands on its own.
        throw $record
    }
}

function Invoke-MtGraphRequest {
    <#
    .SYNOPSIS
        Calls Microsoft Graph against a tenant context with retry, paging and
        read-only gating.

    .DESCRIPTION
        Accepts a relative resource path ('users', 'deviceManagement/managedDevices')
        or a full URL (used internally when following @odata.nextLink).

        Mutating methods are refused when the context is in read-only mode. The
        intended call is logged and a simulation object is returned so calling
        code can be written once and run in both modes.

    .PARAMETER All
        Follows @odata.nextLink until exhausted. Without it you get one page.

    .PARAMETER ConsistencyEventual
        Adds ConsistencyLevel: eventual, required for $count, $search and some
        $filter forms on directory objects.

    .PARAMETER ReadOnlyPost
        Treats a POST as non-mutating for gating purposes.

        Some read operations are POSTs by protocol rather than by intent --
        Azure Policy Insights summarize, Resource Graph queries, and Graph's
        getMemberGroups among them. A gate keyed purely on HTTP verb refuses
        them, which would make a read-only sweep unable to read.

        Deliberately narrow: pass it only where the endpoint genuinely cannot
        change state. It is never set by default, and anything it unlocks still
        appears in the run log.

    .PARAMETER RedactBody
        Replaces the request body with [redacted] in the run log. Required for
        any call carrying a credential -- a password reset body would otherwise
        land in run.jsonl in plaintext, and that file is written to disk and
        attached to tickets.

    .EXAMPLE
        Invoke-MtGraphRequest -Context $ctx -Uri "users?`$select=id,userPrincipalName,accountEnabled" -All

    .EXAMPLE
        Invoke-MtGraphRequest -Context $ctx -Method POST -Uri "users/$upn/revokeSignInSessions"

    .EXAMPLE
        $ctx | Invoke-MtGraphRequest -Uri 'identity/conditionalAccess/policies' -All |
            Select-Object displayName, state
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Context,

        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method = 'GET',

        [ValidateSet('Graph', 'ResourceManager')]
        [string]$Service = 'Graph',

        [string]$ApiVersion = '',

        [AllowNull()]
        [object]$Body = $null,

        [hashtable]$Headers = @{},

        [switch]$All,

        [switch]$ConsistencyEventual,

        [switch]$RedactBody,

        [switch]$ReadOnlyPost,

        [int]$MaxRetry = 5,

        [int]$TimeoutSec = 120,

        [int]$MaxPages = 0,

        [switch]$Raw
    )

    process {
        $baseUri = Get-MtServiceEndpoint -Context $Context -Service $Service

        if ($Uri -match '^https?://') {
            $url = $Uri
        }
        elseif ($Service -eq 'ResourceManager') {
            # ARM carries its version as a query parameter, and the version
            # differs per resource provider -- there is no tenant-wide default
            # that is correct, so the caller must supply one.
            if ([string]::IsNullOrWhiteSpace($ApiVersion)) {
                throw "ARM requests require -ApiVersion (for example '2024-07-01'); the version differs per resource provider."
            }

            $url = '{0}/{1}' -f $baseUri, $Uri.TrimStart('/')

            if ($url -notmatch '[?&]api-version=') {
                $separator = '?'
                if ($url.Contains('?')) {
                    $separator = '&'
                }
                $url = '{0}{1}api-version={2}' -f $url, $separator, $ApiVersion
            }
        }
        else {
            $graphVersion = $ApiVersion
            if ([string]::IsNullOrWhiteSpace($graphVersion)) {
                $graphVersion = 'v1.0'
            }

            if (@('v1.0', 'beta') -notcontains $graphVersion) {
                throw "Graph requests accept -ApiVersion 'v1.0' or 'beta'; got '$graphVersion'."
            }

            $url = '{0}/{1}/{2}' -f $baseUri, $graphVersion, $Uri.TrimStart('/')
        }

        $isWrite = @('POST', 'PATCH', 'PUT', 'DELETE') -contains $Method
        if ($ReadOnlyPost -and $Method -eq 'POST') {
            $isWrite = $false
        }

        $bodyJson = $null
        if ($null -ne $Body) {
            if ($Body -is [string]) {
                $bodyJson = $Body
            }
            else {
                $bodyJson = $Body | ConvertTo-Json -Depth 20 -Compress
            }
        }

        $loggedBody = $bodyJson
        if ($RedactBody -and $null -ne $bodyJson) {
            $loggedBody = '[redacted]'
        }

        if ($isWrite -and $Context.WhatIfMode) {
            Write-MtLog -Level 'WhatIf' -Context $Context -Message ('[read-only] would {0} {1}' -f $Method, $url) -Data @{
                method = $Method
                url    = $url
                body   = $loggedBody
            }

            return [pscustomobject]@{
                PSTypeName = 'MtGraph.Simulation'
                Simulated  = $true
                Tenant     = $Context.Name
                TenantId   = $Context.TenantId
                Method     = $Method
                Url        = $url
                Body       = $bodyJson
            }
        }

        if ($isWrite) {
            $target = '{0} :: {1}' -f $Context.Name, $url
            if (-not $PSCmdlet.ShouldProcess($target, $Method)) {
                return
            }
        }

        $extraHeaders = @{}
        foreach ($key in $Headers.Keys) {
            $extraHeaders[$key] = $Headers[$key]
        }

        if ($ConsistencyEventual) {
            $extraHeaders['ConsistencyLevel'] = 'eventual'
        }

        if ($null -ne $bodyJson) {
            $extraHeaders['Content-Type'] = 'application/json; charset=utf-8'
        }

        $page = 0
        $nextUrl = $url

        while (-not [string]::IsNullOrWhiteSpace($nextUrl)) {
            $page++

            $response = Invoke-MtGraphCall -Context $Context -Url $nextUrl -Method $Method -Service $Service `
                -BodyJson $bodyJson -ExtraHeaders $extraHeaders -MaxRetry $MaxRetry -TimeoutSec $TimeoutSec

            if ($isWrite) {
                Write-MtLog -Level 'Change' -Context $Context -Message ('{0} {1} -> HTTP {2}' -f $Method, $nextUrl, $response.StatusCode) -Data @{
                    method     = $Method
                    url        = $nextUrl
                    statusCode = $response.StatusCode
                }
            }

            if ($Raw) {
                $response
            }
            elseif ($null -eq $response.Object) {
                # 204 No Content, typical for DELETE and many action endpoints.
                if (-not $isWrite) {
                    Write-Verbose ('Empty body returned for {0} {1}.' -f $Method, $nextUrl)
                }
            }
            elseif (Test-MtProperty -InputObject $response.Object -Name 'value') {
                foreach ($item in @($response.Object.value)) {
                    $item
                }
            }
            else {
                $response.Object
            }

            $nextUrl = ''

            if ($All -and $null -ne $response.Object) {
                # Graph pages on @odata.nextLink; ARM pages on nextLink.
                $nextUrl = [string](Get-MtProperty -InputObject $response.Object -Name '@odata.nextLink' -Default '')
                if ([string]::IsNullOrWhiteSpace($nextUrl)) {
                    $nextUrl = [string](Get-MtProperty -InputObject $response.Object -Name 'nextLink' -Default '')
                }

                if ($MaxPages -gt 0 -and $page -ge $MaxPages) {
                    Write-Verbose ('MaxPages ({0}) reached; stopping pagination.' -f $MaxPages)
                    $nextUrl = ''
                }
            }

            # Paging is always a GET against the supplied link, never a repeat
            # of the original body or verb.
            if (-not [string]::IsNullOrWhiteSpace($nextUrl)) {
                $Method = 'GET'
                $bodyJson = $null
                $isWrite = $false
            }
        }
    }
}
