[CmdletBinding()]
param(
    [string]$ProjectRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ProjectRoot = $PSScriptRoot
    } else {
        $ProjectRoot = 'T:\SeaHorse'
    }
}

$releaseHome = Join-Path $ProjectRoot '.gnupg-release'
$fprPrimary = 'F8DF590FCD82D5230EC736E94A578E36E430FB08'
$fprSign = '3A4D4D59A8694DA8F74B4D63C909AD4A6C03054F'

if (-not (Test-Path -LiteralPath $releaseHome)) {
    throw "Missing release GnuPG home: $releaseHome"
}

function Invoke-Gpg {
    param([Parameter(Mandatory)][string[]]$GpgArgs)
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & gpg @GpgArgs 2>&1 | Out-Null
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

function Sign-File {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $asc = "$Path.asc"
    if (Test-Path -LiteralPath $asc) { Remove-Item -LiteralPath $asc -Force }
    # Release key material is unprotected; no passphrase needed.
    $code = Invoke-Gpg -GpgArgs @(
        '--batch', '--yes',
        '--local-user', $fprSign, '--detach-sign', '--armor',
        '--output', $asc, '--', $Path
    )
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $asc)) {
        throw "gpg sign failed for $Path (exit $code)"
    }
    Write-Host "Signed $Path"
}

$prevHome = $env:GNUPGHOME
$env:GNUPGHOME = $releaseHome
try {
    $secOut = & gpg --list-secret-keys --with-colons 2>$null | Out-String
    if ($secOut -notmatch [regex]::Escape($fprPrimary)) {
        throw "Secret key $fprPrimary not found in $releaseHome"
    }

    $pubDoc = Join-Path $ProjectRoot 'docs\SeaHorse_Release_Signing_2026_pubkey.asc'
    New-Item -ItemType Directory -Path (Split-Path $pubDoc) -Force | Out-Null
    $pubText = & gpg --armor --export $fprPrimary 2>$null | Out-String
    if ([string]::IsNullOrWhiteSpace($pubText)) { throw 'Failed to export public key' }
    Set-Content -Path $pubDoc -Value $pubText.TrimEnd() -Encoding ASCII
    Write-Host "Exported $pubDoc"

    $dist = Join-Path $ProjectRoot 'dist\SeaHorse'
    if (-not (Test-Path -LiteralPath (Join-Path $dist 'SeaHorse.exe'))) {
        throw "Missing dist\SeaHorse\SeaHorse.exe - run python build.py first"
    }

    Sign-File (Join-Path $dist 'SeaHorse.exe')
    $readme = Join-Path $dist 'README-PORTABLE.txt'
    if (Test-Path -LiteralPath $readme) { Sign-File $readme }

    # dist SHA256SUMS
    $distEntries = @(
        'SeaHorse.exe', 'SeaHorse.exe.asc',
        'README-PORTABLE.txt', 'README-PORTABLE.txt.asc'
    )
    $distLines = foreach ($name in $distEntries) {
        $p = Join-Path $dist $name
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
        "$h  $name"
    }
    $distSums = Join-Path $dist 'SHA256SUMS'
    (($distLines -join "`n") + "`n") | Set-Content -Path $distSums -Encoding ASCII -NoNewline
    Sign-File $distSums

    # docs SHA256SUMS (repo-relative)
    $manifest = @(
        'dist/SeaHorse/SeaHorse.exe',
        'dist/SeaHorse/SeaHorse.exe.asc',
        'dist/SeaHorse/README-PORTABLE.txt',
        'dist/SeaHorse/README-PORTABLE.txt.asc',
        'dist/SeaHorse/SHA256SUMS',
        'dist/SeaHorse/SHA256SUMS.asc',
        'docs/SeaHorse_Release_Signing_2026_pubkey.asc'
    )
    Push-Location $ProjectRoot
    try {
        $docLines = foreach ($rel in $manifest) {
            $p = Join-Path $ProjectRoot ($rel -replace '/', '\')
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
            "$h  $rel"
        }
        $docsSums = 'docs\SHA256SUMS'
        (($docLines -join "`n") + "`n") | Set-Content -Path $docsSums -Encoding ASCII -NoNewline
        Sign-File (Join-Path $ProjectRoot $docsSums)
    } finally {
        Pop-Location
    }

    Write-Host "Done GNUPGHOME=$releaseHome signing_subkey=$fprSign"
} finally {
    & gpgconf --kill all 2>$null | Out-Null
    if ([string]::IsNullOrWhiteSpace($prevHome)) {
        Remove-Item Env:GNUPGHOME -ErrorAction SilentlyContinue
    } else {
        $env:GNUPGHOME = $prevHome
    }
}
