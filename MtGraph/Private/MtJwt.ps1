function ConvertTo-MtBase64Url {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )

    $standard = [Convert]::ToBase64String($Bytes)
    return $standard.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-MtClientAssertion {
    <#
    .SYNOPSIS
        Builds a signed JWT client assertion for the client_credentials grant.

    .DESCRIPTION
        Certificate auth without an MSAL dependency. Keeps the module portable
        to any admin workstation, Azure Automation sandbox, or RMM runner
        without a module install step.

        The x5t header uses the SHA-1 cert hash, which is what the identity
        platform expects for certificate identification.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$Audience
    )

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)

    if ($null -eq $rsa) {
        throw "Certificate '$($Certificate.Thumbprint)' has no usable RSA private key. Confirm the private key is present and the running account has read access to it."
    }

    try {
        $encoding = [System.Text.Encoding]::UTF8
        $now = [DateTimeOffset]::UtcNow

        $header = [ordered]@{
            alg = 'RS256'
            typ = 'JWT'
            x5t = (ConvertTo-MtBase64Url -Bytes $Certificate.GetCertHash())
        }

        $payload = [ordered]@{
            aud = $Audience
            iss = $ClientId
            sub = $ClientId
            jti = [guid]::NewGuid().ToString()
            nbf = $now.AddMinutes(-5).ToUnixTimeSeconds()
            exp = $now.AddMinutes(10).ToUnixTimeSeconds()
        }

        $headerSegment = ConvertTo-MtBase64Url -Bytes $encoding.GetBytes(($header | ConvertTo-Json -Compress))
        $payloadSegment = ConvertTo-MtBase64Url -Bytes $encoding.GetBytes(($payload | ConvertTo-Json -Compress))
        $signingInput = '{0}.{1}' -f $headerSegment, $payloadSegment

        $signature = $rsa.SignData(
            $encoding.GetBytes($signingInput),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        return '{0}.{1}' -f $signingInput, (ConvertTo-MtBase64Url -Bytes $signature)
    }
    finally {
        if ($null -ne $rsa) {
            $rsa.Dispose()
        }
    }
}
