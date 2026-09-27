function New-MtTenantContext {
    <#
    .SYNOPSIS
        Builds a tenant context: the unit of work every other function takes.

    .DESCRIPTION
        A context carries who you are (client id + credential), which tenant you
        are acting against, which sovereign cloud, the cached token, discovered
        licensing capabilities, and the write mode.

        Write mode defaults to read-only. Mutating verbs are refused until the
        context is explicitly armed with -AllowWrites or Set-MtWriteMode. That is
        deliberate: in a multi-tenant run, an un-gated typo is a fleet-wide event.

    .EXAMPLE
        $ctx = New-MtTenantContext -TenantId 'contoso.onmicrosoft.com' `
            -ClientId '11111111-2222-3333-4444-555555555555' `
            -CertificateThumbprint 'A1B2C3...' -Name 'Contoso Manufacturing'

    .EXAMPLE
        $ctx = New-MtTenantContext -TenantId 'fabrikam.onmicrosoft.com' `
            -ClientId $appId -DeviceCode -Name 'Fabrikam' -AllowWrites
    #>
    [CmdletBinding(DefaultParameterSetName = 'CertificateThumbprint')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'CertificateThumbprint')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$CertStoreLocation = 'CurrentUser',

        [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
        [securestring]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
        [switch]$DeviceCode,

        [string]$Name,

        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string]$Cloud = 'Global',

        [switch]$AllowWrites,

        [string]$ArtifactRoot,

        [string[]]$Tag = @()
    )

    $authMode = 'Certificate'
    $auth = @{
        Certificate  = $null
        ClientSecret = $null
        Thumbprint   = ''
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Certificate' {
            $auth.Certificate = $Certificate
            $auth.Thumbprint = $Certificate.Thumbprint
        }
        'CertificateThumbprint' {
            $certPath = 'Cert:\{0}\My\{1}' -f $CertStoreLocation, $CertificateThumbprint
            if (-not (Test-Path -LiteralPath $certPath)) {
                throw "Certificate '$CertificateThumbprint' was not found at $certPath. Pass -Certificate directly if the key lives outside the Windows certificate store."
            }
            $auth.Certificate = Get-Item -LiteralPath $certPath
            $auth.Thumbprint = $CertificateThumbprint
        }
        'ClientSecret' {
            $authMode = 'ClientSecret'
            $auth.ClientSecret = $ClientSecret
        }
        'DeviceCode' {
            $authMode = 'DeviceCode'
        }
    }

    $nameIsAuto = [string]::IsNullOrWhiteSpace($Name)
    if ($nameIsAuto) {
        $Name = $TenantId
    }

    if ([string]::IsNullOrWhiteSpace($ArtifactRoot)) {
        $ArtifactRoot = Get-MtDefaultArtifactRoot
    }

    $context = [pscustomobject]@{
        PSTypeName    = 'MtGraph.TenantContext'
        Name          = $Name
        TenantId      = $TenantId
        DisplayName   = ''
        DefaultDomain = ''
        ClientId      = $ClientId
        AuthMode      = $authMode
        Cloud         = $Cloud
        Endpoints     = (Get-MtCloudEndpoint -Cloud $Cloud)
        Auth          = $auth
        Tokens        = @{}
        Token         = $null
        Capabilities  = @{}
        WhatIfMode    = (-not $AllowWrites.IsPresent)
        ArtifactRoot  = $ArtifactRoot
        Tag           = @($Tag)
        NameIsAuto    = $nameIsAuto
        ConnectedOn   = $null
    }

    # Tokens is keyed by service (Graph, ResourceManager). .Token stays as a
    # live reference to the Graph slot -- hashtables are reference types, so
    # both paths see the same object and existing callers keep working.
    $context.Tokens['Graph'] = @{
        AccessToken  = ''
        RefreshToken = ''
        AcquiredOn   = $null
        ExpiresOn    = $null
    }
    $context.Token = $context.Tokens['Graph']

    return $context
}

function Set-MtWriteMode {
    <#
    .SYNOPSIS
        Arms or disarms a context for mutating calls.

    .DESCRIPTION
        This is the toggle the GUI binds to. Keep it red when armed.
        Arming is per-context, so a fleet run can be read-only everywhere
        except the one tenant you actually intend to change.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ReadOnly')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Context,

        [Parameter(Mandatory, ParameterSetName = 'AllowWrites')]
        [switch]$AllowWrites,

        [Parameter(ParameterSetName = 'ReadOnly')]
        [switch]$ReadOnly,

        [switch]$PassThru
    )

    process {
        foreach ($item in $Context) {
            $target = 'tenant {0} ({1})' -f $item.Name, $item.TenantId

            if ($AllowWrites.IsPresent) {
                if ($PSCmdlet.ShouldProcess($target, 'Enable write operations')) {
                    $item.WhatIfMode = $false
                    Write-MtLog -Level 'Warning' -Context $item -Message 'Context armed for write operations.'
                }
            }
            else {
                $item.WhatIfMode = $true
                Write-MtLog -Level 'Info' -Context $item -Message 'Context set to read-only.'
            }

            if ($PassThru) {
                $item
            }
        }
    }
}

function Connect-MtTenant {
    <#
    .SYNOPSIS
        Acquires a token, resolves tenant identity, and registers the context.

    .DESCRIPTION
        Resolves the tenant's object id and default domain so downstream output
        and artifacts are labelled with something a human recognizes rather than
        a GUID. Capability discovery runs unless suppressed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Context,

        [switch]$SkipCapabilities
    )

    process {
        foreach ($item in $Context) {
            $null = Get-MtValidToken -Context $item

            $organization = @(Invoke-MtGraphRequest -Context $item -Uri 'organization')
            if ($organization.Count -gt 0) {
                $org = $organization[0]
                $item.TenantId = [string](Get-MtProperty -InputObject $org -Name 'id' -Default $item.TenantId)
                $item.DisplayName = [string](Get-MtProperty -InputObject $org -Name 'displayName' -Default '')

                $domains = @(Get-MtProperty -InputObject $org -Name 'verifiedDomains' -Default @())
                foreach ($domain in $domains) {
                    if ([bool](Get-MtProperty -InputObject $domain -Name 'isDefault' -Default $false)) {
                        $item.DefaultDomain = [string](Get-MtProperty -InputObject $domain -Name 'name' -Default '')
                        break
                    }
                }

                if ($item.NameIsAuto -and -not [string]::IsNullOrWhiteSpace($item.DisplayName)) {
                    $item.Name = $item.DisplayName
                    $item.NameIsAuto = $false
                }
            }

            $item.ConnectedOn = [DateTimeOffset]::UtcNow
            $script:MtGraphState.Contexts[$item.TenantId] = $item

            if (-not $SkipCapabilities) {
                $null = Get-MtTenantCapability -Context $item
            }

            Write-MtLog -Context $item -Message ('Connected as {0} ({1}), write mode: {2}.' -f $item.ClientId, $item.AuthMode, $(if ($item.WhatIfMode) { 'read-only' } else { 'ARMED' }))

            $item
        }
    }
}

function Disconnect-MtTenant {
    <#
    .SYNOPSIS
        Clears cached tokens and drops the context from the registry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Context
    )

    process {
        foreach ($item in $Context) {
            foreach ($service in @($item.Tokens.Keys)) {
                $item.Tokens[$service].AccessToken = ''
                $item.Tokens[$service].RefreshToken = ''
                $item.Tokens[$service].AcquiredOn = $null
                $item.Tokens[$service].ExpiresOn = $null
            }
            $item.ConnectedOn = $null

            if ($script:MtGraphState.Contexts.ContainsKey($item.TenantId)) {
                $null = $script:MtGraphState.Contexts.Remove($item.TenantId)
            }
        }
    }
}

function Get-MtContext {
    <#
    .SYNOPSIS
        Lists contexts registered by Connect-MtTenant.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Name,

        [string[]]$Tag
    )

    $all = @($script:MtGraphState.Contexts.Values)

    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        $all = @($all | Where-Object { $_.Name -like $Name })
    }

    if ($null -ne $Tag -and $Tag.Count -gt 0) {
        $all = @($all | Where-Object {
                $contextTags = @($_.Tag)
                @($Tag | Where-Object { $contextTags -contains $_ }).Count -gt 0
            })
    }

    return ($all | Sort-Object -Property Name)
}

function Import-MtTenantConfig {
    <#
    .SYNOPSIS
        Builds contexts for a whole customer book from one JSON file.

    .DESCRIPTION
        Top-level keys supply partner defaults (client id, auth mode, cloud,
        artifact root); each entry under "tenants" may override any of them.
        Secrets are never stored in this file — certificate auth reads the
        thumbprint, and client secret auth reads the named environment variable.

    .EXAMPLE
        $book = Import-MtTenantConfig -Path .\tenants.json
        $book | Connect-MtTenant
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string[]]$Tag,

        [switch]$AllowWrites
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Tenant config '$Path' was not found."
    }

    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $config = $raw | ConvertFrom-Json

    $defaultClientId = [string](Get-MtProperty -InputObject $config -Name 'clientId' -Default '')
    $defaultAuthMode = [string](Get-MtProperty -InputObject $config -Name 'authMode' -Default 'Certificate')
    $defaultCloud = [string](Get-MtProperty -InputObject $config -Name 'cloud' -Default 'Global')
    $defaultThumbprint = [string](Get-MtProperty -InputObject $config -Name 'certificateThumbprint' -Default '')
    $defaultStore = [string](Get-MtProperty -InputObject $config -Name 'certStoreLocation' -Default 'CurrentUser')
    $defaultSecretVar = [string](Get-MtProperty -InputObject $config -Name 'clientSecretEnvVar' -Default '')
    $defaultArtifactRoot = [string](Get-MtProperty -InputObject $config -Name 'artifactRoot' -Default '')

    $entries = @(Get-MtProperty -InputObject $config -Name 'tenants' -Default @())

    foreach ($entry in $entries) {
        $entryTags = @(Get-MtProperty -InputObject $entry -Name 'tags' -Default @())

        if ($null -ne $Tag -and $Tag.Count -gt 0) {
            $matched = @($Tag | Where-Object { $entryTags -contains $_ })
            if ($matched.Count -eq 0) {
                continue
            }
        }

        $splat = @{
            TenantId = [string](Get-MtProperty -InputObject $entry -Name 'tenantId' -Default '')
            ClientId = [string](Get-MtProperty -InputObject $entry -Name 'clientId' -Default $defaultClientId)
            Name     = [string](Get-MtProperty -InputObject $entry -Name 'name' -Default '')
            Cloud    = [string](Get-MtProperty -InputObject $entry -Name 'cloud' -Default $defaultCloud)
            Tag      = $entryTags
        }

        $artifactRoot = [string](Get-MtProperty -InputObject $entry -Name 'artifactRoot' -Default $defaultArtifactRoot)
        if (-not [string]::IsNullOrWhiteSpace($artifactRoot)) {
            $splat['ArtifactRoot'] = $artifactRoot
        }

        if ($AllowWrites) {
            $splat['AllowWrites'] = $true
        }

        $authMode = [string](Get-MtProperty -InputObject $entry -Name 'authMode' -Default $defaultAuthMode)

        if ($authMode -eq 'DeviceCode') {
            $splat['DeviceCode'] = $true
        }
        elseif ($authMode -eq 'ClientSecret') {
            $secretVar = [string](Get-MtProperty -InputObject $entry -Name 'clientSecretEnvVar' -Default $defaultSecretVar)
            if ([string]::IsNullOrWhiteSpace($secretVar)) {
                throw "Tenant '$($splat.TenantId)' uses ClientSecret auth but no clientSecretEnvVar was supplied."
            }

            $secretValue = [Environment]::GetEnvironmentVariable($secretVar)
            if ([string]::IsNullOrWhiteSpace($secretValue)) {
                throw "Environment variable '$secretVar' is empty; cannot build a client secret credential for tenant '$($splat.TenantId)'."
            }

            $splat['ClientSecret'] = (ConvertTo-SecureString -String $secretValue -AsPlainText -Force)
        }
        else {
            $splat['CertificateThumbprint'] = [string](Get-MtProperty -InputObject $entry -Name 'certificateThumbprint' -Default $defaultThumbprint)
            $splat['CertStoreLocation'] = [string](Get-MtProperty -InputObject $entry -Name 'certStoreLocation' -Default $defaultStore)
        }

        New-MtTenantContext @splat
    }
}
