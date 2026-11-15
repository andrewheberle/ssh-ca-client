# Download the MSI of the previous release, for test-msi.ps1 to upgrade from:
# the latest published release, not a draft or prerelease, with a version
# below the build under test. The MSI is checked against that release's
# checksums.txt. Prints the path of the downloaded MSI.
#
# Usage (needs gh, authenticated with GH_TOKEN):
#   templates/get-previous-msi.ps1 -Repository owner/repo -Version 1.2.3 -OutDir path\to\dir
param(
    [Parameter(Mandatory = $true)]
    [string]$Repository,

    # the version of the build under test (major.minor.patch)
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'

$build = [version]$Version

$tags = gh api --paginate "repos/$Repository/releases" --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name'
if ($LASTEXITCODE -ne 0) {
    throw "listing the releases of $Repository failed"
}

$previous = $tags |
    Where-Object { $_ -match '^v\d+\.\d+\.\d+$' } |
    ForEach-Object { [version]$_.Substring(1) } |
    Where-Object { $_ -lt $build } |
    Sort-Object -Descending |
    Select-Object -First 1
if ($null -eq $previous) {
    throw "no published release of $Repository below $Version to upgrade from"
}

$tag = "v$previous"
$name = "ssh-ca-client_${previous}_windows_amd64.msi"
Write-Host "previous release: $tag"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
gh release download $tag --repo $Repository --dir $OutDir --pattern $name --pattern checksums.txt --clobber | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "downloading $name from $tag failed"
}

# checksums.txt lines are "<sha256>  <file name>"
$msi = Join-Path $OutDir $name
$line = Get-Content (Join-Path $OutDir 'checksums.txt') |
    Where-Object { ($_ -split '\s+', 2)[1] -eq $name } |
    Select-Object -First 1
if ($null -eq $line) {
    throw "$name is not in the checksums.txt of $tag"
}
$want = ($line -split '\s+', 2)[0].ToLowerInvariant()
$got = (Get-FileHash -Algorithm SHA256 -Path $msi).Hash.ToLowerInvariant()
if ($got -ne $want) {
    throw "$name has sha256 $got, but the checksums.txt of $tag has $want"
}
Write-Host "ok: $name matches the checksums.txt of $tag"

Write-Output $msi
