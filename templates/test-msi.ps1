# Smoke test for the MSI: install, check the result and uninstall, both with
# the default options and with the optional start on login entries disabled.
#
# Usage (elevated): templates/test-msi.ps1 -Msi path\to\ssh-ca-client.msi
param(
    [Parameter(Mandatory = $true)]
    [string]$Msi
)

$ErrorActionPreference = 'Stop'

$Msi = (Resolve-Path $Msi).Path
$installDir = Join-Path $env:ProgramFiles 'Serverless SSH CA Client'
$runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$eventLogKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Serverless SSH CA Client'
$files = @(
    'ssh-ca-client.exe',
    'ssh-ca-client-cli.exe',
    'policy\ServerlessSSHCAClient.admx',
    'policy\en-US\ServerlessSSHCAClient.adml'
)
$runValues = @('Serverless SSH CA Client', 'OpenSSH Authentication Agent')

function Invoke-Msiexec([string[]]$Arguments, [string]$Log) {
    $p = Start-Process -FilePath msiexec.exe -ArgumentList ($Arguments + @('/qn', '/l*v', $Log)) -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Get-Content $Log -Tail 100
        throw "msiexec $($Arguments -join ' ') exited with $($p.ExitCode)"
    }
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "FAIL: $Message"
    }
    Write-Output "ok: $Message"
}

function Test-RunValue([string]$Name) {
    return $null -ne (Get-ItemProperty -Path $runKey -Name $Name -ErrorAction SilentlyContinue)
}

$tests = @(
    @{ Name = 'default options'; Properties = @(); RunExpected = $true },
    @{ Name = 'start on login disabled'; Properties = @('START_ON_LOGIN=0', 'START_SSH_AGENT=0'); RunExpected = $false }
)

foreach ($t in $tests) {
    Write-Output "== $($t.Name)"

    Invoke-Msiexec -Arguments (@('/i', "`"$Msi`"") + $t.Properties) -Log (Join-Path $env:TEMP 'msi-install.log')
    foreach ($f in $files) {
        Assert-True (Test-Path (Join-Path $installDir $f)) "$f installed"
    }
    Assert-True ($null -ne (Get-ItemProperty -Path $eventLogKey -Name EventMessageFile -ErrorAction SilentlyContinue)) 'event log source registered'
    foreach ($v in $runValues) {
        Assert-True ((Test-RunValue $v) -eq $t.RunExpected) "Run value '$v' present is $($t.RunExpected)"
    }

    Invoke-Msiexec -Arguments @('/x', "`"$Msi`"") -Log (Join-Path $env:TEMP 'msi-uninstall.log')
    Assert-True (-not (Test-Path $installDir)) 'install directory removed'
    Assert-True ($null -eq (Get-ItemProperty -Path $eventLogKey -Name EventMessageFile -ErrorAction SilentlyContinue)) 'event log source removed'
    foreach ($v in $runValues) {
        Assert-True (-not (Test-RunValue $v)) "Run value '$v' removed"
    }
}
