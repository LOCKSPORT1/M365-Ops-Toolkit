function ConvertTo-MtHeaderTable {
    <#
    .SYNOPSIS
        Normalizes response headers. PS 5.1 gives Dictionary[string,string];
        PS 7 gives Dictionary[string,IEnumerable[string]].
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [AllowNull()]
        [object]$Headers
    )

    $table = New-Object -TypeName System.Collections.Hashtable -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)

    if ($null -eq $Headers) {
        return $table
    }

    # Three shapes reach this function:
    #   PS 5.1 success  : Dictionary[string,string]
    #   PS 7   success  : Dictionary[string,IEnumerable[string]]
    #   PS 7   failure  : HttpResponseHeaders, which has NO .Keys and must be
    #                     enumerated as KeyValuePair objects. Missing this is
    #                     why Retry-After silently stops being honored on 429.
    $hasKeys = $false
    try {
        $hasKeys = ($null -ne $Headers.PSObject.Properties['Keys'])
    }
    catch {
        $hasKeys = $false
    }

    if ($hasKeys) {
        foreach ($key in @($Headers.Keys)) {
            $value = $Headers[$key]
            if ($value -is [string]) {
                $table[$key] = $value
            }
            else {
                $table[$key] = (@($value) -join ',')
            }
        }

        return $table
    }

    foreach ($pair in $Headers) {
        $key = $null
        try {
            $key = $pair.Key
        }
        catch {
            continue
        }

        if ([string]::IsNullOrEmpty([string]$key)) {
            continue
        }

        $table[$key] = (@($pair.Value) -join ',')
    }

    return $table
}

function Read-MtResponseText {
    <#
    .SYNOPSIS
        Decodes a response body as UTF-8 from the raw stream. Avoids the
        charset mangling Invoke-RestMethod does on Windows PowerShell.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object]$Response
    )

    if ($null -eq $Response) {
        return ''
    }

    if (Test-MtProperty -InputObject $Response -Name 'RawContentStream') {
        $stream = $Response.RawContentStream
        if ($null -ne $stream) {
            try {
                $null = $stream.Seek(0, [System.IO.SeekOrigin]::Begin)
                $bytes = $stream.ToArray()
                if ($bytes.Length -gt 0) {
                    return [System.Text.Encoding]::UTF8.GetString($bytes)
                }
                return ''
            }
            catch {
                Write-Verbose ('Raw stream read failed, falling back to .Content: {0}' -f $_.Exception.Message)
            }
        }
    }

    if (Test-MtProperty -InputObject $Response -Name 'Content') {
        return [string]$Response.Content
    }

    return ''
}

function Resolve-MtHttpError {
    <#
    .SYNOPSIS
        Extracts status code, headers and body from a failed web request on
        either PowerShell edition.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $result = @{
        StatusCode = 0
        Headers    = (ConvertTo-MtHeaderTable -Headers $null)
        Text       = ''
    }

    $response = $null
    try {
        if (Test-MtProperty -InputObject $ErrorRecord.Exception -Name 'Response') {
            $response = $ErrorRecord.Exception.Response
        }
    }
    catch {
        $response = $null
    }

    if ($null -ne $response) {
        try {
            $result.StatusCode = [int]$response.StatusCode
        }
        catch {
            $result.StatusCode = 0
        }

        try {
            $result.Headers = ConvertTo-MtHeaderTable -Headers $response.Headers
        }
        catch {
            Write-Verbose 'Could not read headers from the error response.'
        }

        if (-not $script:MtGraphIsCore) {
            $reader = $null
            try {
                $stream = $response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader -ArgumentList $stream, ([System.Text.Encoding]::UTF8)
                $result.Text = $reader.ReadToEnd()
            }
            catch {
                Write-Verbose 'Could not read the error response stream.'
            }
            finally {
                if ($null -ne $reader) {
                    $reader.Dispose()
                }
            }
        }
    }

    if ([string]::IsNullOrEmpty($result.Text)) {
        $details = Get-MtProperty -InputObject $ErrorRecord -Name 'ErrorDetails'
        if ($null -ne $details) {
            $result.Text = [string](Get-MtProperty -InputObject $details -Name 'Message' -Default '')
        }
    }

    return $result
}

function Invoke-MtHttp {
    <#
    .SYNOPSIS
        Single HTTP call returning a normalized result instead of throwing on
        non-2xx. Callers decide what is retryable.

    .OUTPUTS
        PSCustomObject with StatusCode, Headers, Text, Object, Success, Exception.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'HEAD')]
        [string]$Method = 'GET',

        [hashtable]$Headers = @{},

        [AllowNull()]
        [object]$Body = $null,

        [string]$ContentType = 'application/json; charset=utf-8',

        [int]$TimeoutSec = 120
    )

    $splat = @{
        Uri             = $Uri
        Method          = $Method
        Headers         = $Headers
        UseBasicParsing = $true
        TimeoutSec      = $TimeoutSec
        ErrorAction     = 'Stop'
    }

    if ($null -ne $Body) {
        $splat['Body'] = $Body
        $splat['ContentType'] = $ContentType
    }

    $result = @{
        StatusCode = 0
        Headers    = (ConvertTo-MtHeaderTable -Headers $null)
        Text       = ''
        Object     = $null
        Success    = $false
        Exception  = $null
    }

    $previousProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    try {
        $response = Invoke-WebRequest @splat
        $result.StatusCode = [int]$response.StatusCode
        $result.Headers = ConvertTo-MtHeaderTable -Headers $response.Headers
        $result.Text = Read-MtResponseText -Response $response
        $result.Success = $true
    }
    catch {
        $errorRecord = $_
        $parsed = Resolve-MtHttpError -ErrorRecord $errorRecord
        $result.StatusCode = $parsed.StatusCode
        $result.Headers = $parsed.Headers
        $result.Text = $parsed.Text
        $result.Success = $false
        $result.Exception = $errorRecord
    }
    finally {
        $ProgressPreference = $previousProgress
    }

    if (-not [string]::IsNullOrWhiteSpace($result.Text)) {
        try {
            $result.Object = $result.Text | ConvertFrom-Json
        }
        catch {
            $result.Object = $null
        }
    }

    return [pscustomobject]$result
}
