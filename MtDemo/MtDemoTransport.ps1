#Requires -Version 5.1
<#
.SYNOPSIS
    Installs an offline transport into MtGraph so the demo runs with no
    network, no local server, no Python and no elevation.

.DESCRIPTION
    Replaces MtGraph's private Invoke-MtHttp with a fixture replayer, inside
    the module's own scope, so every layer above it runs for real: token
    handling, the retry loop, paging, the read-only write gate, capability
    discovery, the findings engines, the report writers.

    What is simulated is exactly one thing -- the HTTP response. Everything
    the modules actually do is genuine code executing against realistic
    payloads. That is the claim being made, and it is worth stating plainly
    rather than letting a demo imply a live tenant.

    Writes are recorded and answered 204, which is how the demo can prove the
    investigation issued zero writes and the armed run issued seven.
#>

function Install-MtDemoTransport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FixtureRoot
    )

    $graphFixture = Get-Content -LiteralPath (Join-Path $FixtureRoot 'graph.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $armFixture = Get-Content -LiteralPath (Join-Path $FixtureRoot 'arm.json') -Raw -Encoding UTF8 | ConvertFrom-Json

    $module = Get-Module MtGraph
    if ($null -eq $module) {
        throw 'MtGraph is not loaded. Import it before installing the demo transport.'
    }

    & $module {
        param($GraphFixture, $ArmFixture)

        $script:MtDemoRoutes = @(@($GraphFixture.routes) + @($ArmFixture.routes))
        $script:MtDemoWrites = New-Object System.Collections.ArrayList
        $script:MtDemoReads = New-Object System.Collections.ArrayList

        $replayer = {
            param($Uri, $Method = 'GET', $Headers = @{}, $Body = $null, $ContentType = '', $TimeoutSec = 120)

            # Strip scheme and host; fixtures are keyed on the path and query.
            $path = $Uri
            if ($path -match '^https?://[^/]+(/.*)$') {
                $path = $Matches[1]
            }

            $verb = $Method.ToUpperInvariant()

            $okHeaders = ConvertTo-MtHeaderTable -Headers @{
                'request-id'        = 'demo-fixture'
                'client-request-id' = [guid]::NewGuid().ToString()
            }

            # The token endpoint is never reached: the demo seeds the cache.
            if ($path -match '/oauth2/v2\.0/token') {
                $payload = '{"access_token":"demo-token","expires_in":3600,"token_type":"Bearer"}'
                return [pscustomobject]@{
                    StatusCode = 200; Headers = $okHeaders; Text = $payload
                    Object     = ($payload | ConvertFrom-Json); Success = $true; Exception = $null
                }
            }

            foreach ($route in $script:MtDemoRoutes) {
                if ($verb -ne [string]$route.method) {
                    continue
                }

                if ($path -notmatch [string]$route.pattern) {
                    continue
                }

                $status = [int]$route.status
                $json = $route.body | ConvertTo-Json -Depth 20 -Compress

                $null = $script:MtDemoReads.Add(('{0} {1}' -f $verb, $path))

                return [pscustomobject]@{
                    StatusCode = $status
                    Headers    = $okHeaders
                    Text       = $json
                    Object     = ($json | ConvertFrom-Json)
                    Success    = ($status -ge 200 -and $status -lt 300)
                    Exception  = $null
                }
            }

            if (@('POST', 'PATCH', 'PUT', 'DELETE') -contains $verb) {
                $null = $script:MtDemoWrites.Add([pscustomobject]@{
                        Method = $verb
                        Path   = $path
                        Body   = $Body
                    })

                return [pscustomobject]@{
                    StatusCode = 204; Headers = $okHeaders; Text = ''
                    Object     = $null; Success = $true; Exception = $null
                }
            }

            $notFound = '{"error":{"code":"ResourceNotFound","message":"No fixture for this route."}}'
            return [pscustomobject]@{
                StatusCode = 404; Headers = $okHeaders; Text = $notFound
                Object     = ($notFound | ConvertFrom-Json); Success = $false; Exception = $null
            }
        }

        Set-Item -Path 'function:script:Invoke-MtHttp' -Value $replayer
    } $graphFixture $armFixture
}

function Get-MtDemoWrite {
    [CmdletBinding()]
    param()

    $module = Get-Module MtGraph
    return (& $module { @($script:MtDemoWrites) })
}

function Clear-MtDemoWrite {
    [CmdletBinding()]
    param()

    $module = Get-Module MtGraph
    & $module { $script:MtDemoWrites.Clear() }
}

function New-MtDemoContext {
    <#
    .SYNOPSIS
        Builds a context wired to the offline transport with tokens pre-seeded.
    #>
    [CmdletBinding()]
    param(
        [string]$Name = 'Contoso Manufacturing',

        [Parameter(Mandatory)]
        [string]$ArtifactRoot
    )

    $context = New-MtTenantContext -TenantId 'contoso.onmicrosoft.com' -ClientId 'demo-client-id' `
        -DeviceCode -Name $Name -ArtifactRoot $ArtifactRoot

    foreach ($service in @('Graph', 'ResourceManager')) {
        $context.Tokens[$service] = @{
            AccessToken  = 'demo-token'
            RefreshToken = ''
            AcquiredOn   = [DateTimeOffset]::UtcNow
            ExpiresOn    = ([DateTimeOffset]::UtcNow).AddHours(1)
        }
    }
    $context.Token = $context.Tokens['Graph']

    return $context
}
