# BioKey publish script
# Run from the root of the BioAuth monorepo
#
# Usage:
#   .\publish.ps1                    auto-bump patch + publish all three packages
#   .\publish.ps1 -DryRun            simulate, no publish, no version bump
#   .\publish.ps1 -Minor             bump minor version (x.N.0)
#   .\publish.ps1 -Major             bump major version (N.0.0)
#   .\publish.ps1 -Core              publish biokey-core only
#   .\publish.ps1 -Js                publish biokey-js only
#   .\publish.ps1 -React             publish biokey-react only
#   .\publish.ps1 -Token npm_xxxx    pass token inline
#   .\publish.ps1 -Token npm_xxxx -Save   save token to .npmtoken for reuse
#
# Token resolution order:
#   1. -Token param
#   2. NPM_TOKEN environment variable
#   3. .npmtoken file in this directory (gitignored)
#
# Publish order is always: biokey-core -> biokey-js -> biokey-react
# biokey-react depends on biokey-js, so order matters.

param(
    [switch]$DryRun,
    [switch]$Minor,
    [switch]$Major,
    [switch]$Core,
    [switch]$Js,
    [switch]$React,
    [switch]$Save,
    [string]$Token = ""
)

$TokenFile   = Join-Path $PSScriptRoot ".npmtoken"
$UserNpmrc   = Join-Path $env:USERPROFILE ".npmrc"
$RegistryKey = "//registry.npmjs.org/:_authToken"
$CoreDir     = Join-Path $PSScriptRoot "packages\biokey-core"
$JsDir       = Join-Path $PSScriptRoot "packages\biokey-js"
$ReactDir    = Join-Path $PSScriptRoot "packages\biokey-react"

$BumpType = "patch"
if ($Minor) { $BumpType = "minor" }
if ($Major) { $BumpType = "major" }

# Determine which packages to publish.
# If none specified, publish all. If any specified, publish only those.
$AnySelected = $Core -or $Js -or $React
$PublishCore  = !$AnySelected -or $Core
$PublishJs    = !$AnySelected -or $Js
$PublishReact = !$AnySelected -or $React


# --------------------------------------------------------------------------
# Resolve token
# --------------------------------------------------------------------------

$npmToken = ""

if ($Token -ne "") {
    $npmToken = $Token.Trim()
    if ($Save) {
        Set-Content -Path $TokenFile -Value $npmToken -NoNewline -Encoding UTF8
        Write-Host "  Token saved to .npmtoken" -ForegroundColor Green
    }
}
elseif ($env:NPM_TOKEN -ne $null -and $env:NPM_TOKEN.Trim() -ne "") {
    $npmToken = $env:NPM_TOKEN.Trim()
    Write-Host "  Using NPM_TOKEN from environment" -ForegroundColor Gray
}
elseif (Test-Path $TokenFile) {
    $npmToken = (Get-Content $TokenFile -Encoding UTF8 -Raw).Trim()
    Write-Host "  Using token from .npmtoken" -ForegroundColor Gray
}
else {
    Write-Host ""
    Write-Host "  ERROR: No npm token found." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Create a Granular Access Token at:" -ForegroundColor Yellow
    Write-Host "  https://www.npmjs.com/settings/~/tokens/new" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Settings required:" -ForegroundColor Gray
    Write-Host "    Type:        Granular access token" -ForegroundColor Gray
    Write-Host "    Packages:    Read and write" -ForegroundColor Gray
    Write-Host "    Bypass 2FA:  Yes  (required for scripts)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Then run:" -ForegroundColor Gray
    Write-Host "    .\publish.ps1 -Token npm_xxxx -Save" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}


# --------------------------------------------------------------------------
# Write temp auth to ~/.npmrc
# --------------------------------------------------------------------------

$originalNpmrc = ""
if (Test-Path $UserNpmrc) {
    $originalNpmrc = Get-Content $UserNpmrc -Raw -Encoding UTF8
}

function Restore-Npmrc {
    if ($originalNpmrc -ne "") {
        Set-Content -Path $UserNpmrc -Value $originalNpmrc -Encoding UTF8
    } elseif (Test-Path $UserNpmrc) {
        Remove-Item $UserNpmrc -Force
    }
}

$filtered = ($originalNpmrc -split "`n" | Where-Object { $_ -notmatch [regex]::Escape($RegistryKey) }) -join "`n"
$newNpmrc = ($RegistryKey + "=" + $npmToken).Trim() + "`n" + $filtered.TrimStart()
Set-Content -Path $UserNpmrc -Value $newNpmrc -Encoding UTF8


# --------------------------------------------------------------------------
# Verify token
# --------------------------------------------------------------------------

Write-Host ""
Write-Host "  Verifying npm token..." -ForegroundColor Gray

$whoami = npm whoami 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  ERROR: Token rejected by npm." -ForegroundColor Red
    Write-Host "  $whoami" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Make sure your token has Read and write + Bypass 2FA." -ForegroundColor Yellow
    Write-Host "  https://www.npmjs.com/settings/~/tokens/new" -ForegroundColor Cyan
    Write-Host ""
    Restore-Npmrc
    exit 1
}

Write-Host "  Authenticated as: $whoami" -ForegroundColor Green
Write-Host ""


# --------------------------------------------------------------------------
# Dry run
# --------------------------------------------------------------------------

if ($DryRun) {
    function Get-NextVersion($current, $bump) {
        $parts = $current -split "\."
        switch ($bump) {
            "major" { return "$([int]$parts[0] + 1).0.0" }
            "minor" { return "$($parts[0]).$([int]$parts[1] + 1).0" }
            default { return "$($parts[0]).$($parts[1]).$([int]$parts[2] + 1)" }
        }
    }

    $coreV  = (Get-Content (Join-Path $CoreDir  "package.json") -Raw | ConvertFrom-Json).version
    $jsV    = (Get-Content (Join-Path $JsDir    "package.json") -Raw | ConvertFrom-Json).version
    $reactV = (Get-Content (Join-Path $ReactDir "package.json") -Raw | ConvertFrom-Json).version

    Write-Host "  [DRY RUN] No version bumps. Nothing will be published." -ForegroundColor Yellow
    Write-Host ""
    if ($PublishCore)  { Write-Host "  Would bump ($BumpType): biokey-core   $coreV  ->  $(Get-NextVersion $coreV $BumpType)"   -ForegroundColor White }
    if ($PublishJs)    { Write-Host "  Would bump ($BumpType): biokey-js     $jsV    ->  $(Get-NextVersion $jsV $BumpType)"     -ForegroundColor White }
    if ($PublishReact) { Write-Host "  Would bump ($BumpType): biokey-react  $reactV ->  $(Get-NextVersion $reactV $BumpType)"  -ForegroundColor White }
    Write-Host ""
    Restore-Npmrc
    exit 0
}


# --------------------------------------------------------------------------
# Bump + publish helper
# --------------------------------------------------------------------------

function Invoke-Publish {
    param([string]$Dir, [string]$Label)

    Push-Location $Dir

    Write-Host "  Bumping $Label ($BumpType)..." -ForegroundColor Gray
    npm version $BumpType --no-git-tag-version | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: Version bump failed for $Label" -ForegroundColor Red
        Pop-Location; Restore-Npmrc; exit 1
    }

    $version = (Get-Content "package.json" -Raw | ConvertFrom-Json).version
    Write-Host "  Publishing $Label @ $version ..." -ForegroundColor Cyan

    $maxRetries = 3
    $attempt    = 0
    $exitCode   = 1
    while ($attempt -lt $maxRetries -and $exitCode -ne 0) {
        if ($attempt -gt 0) {
            Write-Host "  Retrying in 10s (attempt $($attempt + 1)/$maxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
        npm publish --access public
        $exitCode = $LASTEXITCODE
        $attempt++
    }
    Pop-Location

    if ($exitCode -ne 0) {
        Write-Host "  FAILED: $Label after $maxRetries attempts" -ForegroundColor Red
        Restore-Npmrc; exit 1
    }

    Write-Host "  OK: $Label @ $version" -ForegroundColor Green
    Write-Host ""
}


# --------------------------------------------------------------------------
# Publish — always in dependency order: core -> js -> react
# --------------------------------------------------------------------------

if ($PublishCore)  { Invoke-Publish -Dir $CoreDir  -Label "biokey-core"  }
if ($PublishJs)    { Invoke-Publish -Dir $JsDir    -Label "biokey-js"    }
if ($PublishReact) { Invoke-Publish -Dir $ReactDir -Label "biokey-react" }

# --------------------------------------------------------------------------
# Restore .npmrc + summary
# --------------------------------------------------------------------------

Restore-Npmrc

$coreF  = (Get-Content (Join-Path $CoreDir  "package.json") -Raw | ConvertFrom-Json).version
$jsF    = (Get-Content (Join-Path $JsDir    "package.json") -Raw | ConvertFrom-Json).version
$reactF = (Get-Content (Join-Path $ReactDir "package.json") -Raw | ConvertFrom-Json).version

Write-Host "  -----------------------------------------" -ForegroundColor DarkGray
if ($PublishCore)  { Write-Host "  biokey-core   $coreF"  -ForegroundColor White }
if ($PublishJs)    { Write-Host "  biokey-js     $jsF"    -ForegroundColor White }
if ($PublishReact) { Write-Host "  biokey-react  $reactF" -ForegroundColor White }
Write-Host "  -----------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  https://www.npmjs.com/package/biokey-core"  -ForegroundColor DarkGray
Write-Host "  https://www.npmjs.com/package/biokey-js"    -ForegroundColor DarkGray
Write-Host "  https://www.npmjs.com/package/biokey-react" -ForegroundColor DarkGray
Write-Host ""
