# Smoke test for the MSI: install, check the result and uninstall, both with
# the default install options and with a custom directory and the start on
# login entries disabled. Then install the previous release with custom
# options and upgrade it to the MSI, which must keep them unless they are
# given again, and uninstall it. Each uninstall must leave nothing behind.
#
# Usage (elevated):
#   templates/test-msi.ps1 -Msi path\to\ssh-ca-client.msi -PreviousMsi path\to\previous.msi
#
# templates/get-previous-msi.ps1 downloads the previous release's MSI.
param(
    [Parameter(Mandatory = $true)]
    [string]$Msi,

    # the MSI of the previous release, which has a lower version
    [Parameter(Mandatory = $true)]
    [string]$PreviousMsi
)

$ErrorActionPreference = 'Stop'

$Msi = (Resolve-Path $Msi).Path
$PreviousMsi = (Resolve-Path $PreviousMsi).Path
$installDir = Join-Path $env:ProgramFiles 'Serverless SSH CA Client'
$runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$eventLogKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Serverless SSH CA Client'
$installerKey = 'HKLM:\SOFTWARE\Andrew Heberle\Serverless SSH CA Client\Installer'
$files = @(
    'ssh-ca-client.exe',
    'ssh-ca-client-cli.exe',
    'policy\ServerlessSSHCAClient.admx',
    'policy\en-US\ServerlessSSHCAClient.adml'
)
# msiexec verbose logs go to the runner's temp directory in CI, where the
# workflow uploads them if the test fails
$logDir = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$clientRun = 'Serverless SSH CA Client'
$agentRun = 'OpenSSH Authentication Agent'
$agentPath = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-agent.exe'

# the verbose log of the last msiexec run, shown when a check fails
$script:lastLog = $null

function Invoke-Msiexec([string[]]$Arguments, [string]$Log) {
    $script:lastLog = $Log
    $p = Start-Process -FilePath msiexec.exe -ArgumentList ($Arguments + @('/qn', '/l*v', $Log)) -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Get-Content $Log -Tail 100
        throw "msiexec $($Arguments -join ' ') exited with $($p.ExitCode)"
    }
}

# Write-Diagnostics shows what the last msiexec run did, so a failed check
# can be understood from the job log alone: where the files are, the saved
# options, and the lines of the verbose log about the install options,
# directories and files
function Write-Diagnostics {
    Write-Output '== diagnostics'
    foreach ($d in @($installDir, (Join-Path $env:ProgramFiles 'SSH CA Test'))) {
        if (Test-Path $d) {
            Write-Output "-- files in $d"
            Get-ChildItem -Path $d -Recurse -File | ForEach-Object { Write-Output "   $($_.FullName)" }
        } else {
            Write-Output "-- $d does not exist"
        }
    }
    Write-Output "-- $installerKey"
    Get-ItemProperty -Path $installerKey -ErrorAction SilentlyContinue | Out-String | Write-Output
    Write-Output "-- $runKey"
    Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue | Out-String | Write-Output

    if ($null -ne $script:lastLog -and (Test-Path $script:lastLog)) {
        Write-Output "-- $($script:lastLog)"
        $pattern = 'Component: |Doing action: |Skipping action: |Action ended .*Return value [^1]|AppSearch|INSTALLDIR|START_ON_LOGIN|START_SSH_AGENT|StartOnLoginValue|StartSSHAgentValue|RemoveExistingProducts|UPGRADINGPRODUCTCODE|OLDERVERSIONBEINGUPGRADED|ApplicationFile|Overwrite|FileCopy|Note: 1: |Error '
        Select-String -Path $script:lastLog -Pattern $pattern | ForEach-Object { Write-Output $_.Line }
    }
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        Write-Diagnostics
        throw "FAIL: $Message"
    }
    Write-Output "ok: $Message"
}

function Get-RegistryValue([string]$Path, [string]$Name) {
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return $null
    }
    return $item.$Name
}

# Assert-Installed checks an install in $Dir, with the Run values present or
# absent as $StartOnLogin and $StartSSHAgent say, and those options saved
function Assert-Installed([string]$Dir, [bool]$StartOnLogin, [bool]$StartSSHAgent) {
    foreach ($f in $files) {
        Assert-True (Test-Path (Join-Path $Dir $f)) "$f installed in $Dir"
    }
    Assert-True ($null -ne (Get-RegistryValue $eventLogKey 'EventMessageFile')) 'event log source registered'

    # the paths are quoted, as they can contain spaces
    $client = Get-RegistryValue $runKey $clientRun
    if ($StartOnLogin) {
        $want = '"' + (Join-Path $Dir 'ssh-ca-client.exe') + '"'
        Assert-True ($client -eq $want) "Run value '$clientRun' is $want (got $client)"
    } else {
        Assert-True ($null -eq $client) "Run value '$clientRun' absent"
    }
    $agent = Get-RegistryValue $runKey $agentRun
    if ($StartSSHAgent) {
        $want = '"' + $agentPath + '"'
        Assert-True ($agent -eq $want) "Run value '$agentRun' is $want (got $agent)"
    } else {
        Assert-True ($null -eq $agent) "Run value '$agentRun' absent"
    }

    # the options are saved for the next upgrade
    $want = $Dir.TrimEnd('\') + '\'
    $got = Get-RegistryValue $installerKey 'InstallDir'
    Assert-True ($got -eq $want) "saved InstallDir is $want (got $got)"
    foreach ($o in @(@('StartOnLogin', $StartOnLogin), @('StartSSHAgent', $StartSSHAgent))) {
        $want = if ($o[1]) { '1' } else { '0' }
        $got = Get-RegistryValue $installerKey $o[0]
        Assert-True ($got -eq $want) "saved $($o[0]) is $want (got $got)"
    }
}

# Assert-Uninstalled checks nothing is left of an install in $Dir
function Assert-Uninstalled([string]$Dir) {
    Assert-True (-not (Test-Path $Dir)) "install directory $Dir removed"
    Assert-True ($null -eq (Get-RegistryValue $eventLogKey 'EventMessageFile')) 'event log source removed'
    foreach ($v in @($clientRun, $agentRun)) {
        Assert-True ($null -eq (Get-RegistryValue $runKey $v)) "Run value '$v' removed"
    }
    # 1.0.1 also saved Version, which an upgrade from it must remove
    foreach ($v in @('InstallDir', 'StartOnLogin', 'StartSSHAgent', 'Version')) {
        Assert-True ($null -eq (Get-RegistryValue $installerKey $v)) "saved $v removed"
    }
}

# a directory with a space in its name, as the Run value must be quoted
$customDir = Join-Path $env:ProgramFiles 'SSH CA Test'
$customOptions = @("INSTALLDIR=`"$customDir`"", 'START_ON_LOGIN=0', 'START_SSH_AGENT=0')

$tests = @(
    @{ Name = 'default install options'; Properties = @(); Dir = $installDir; Enabled = $true },
    @{ Name = 'custom directory, start on login disabled'; Properties = $customOptions; Dir = $customDir; Enabled = $false }
)

foreach ($t in $tests) {
    Write-Output "== fresh install: $($t.Name)"

    Invoke-Msiexec -Arguments (@('/i', "`"$Msi`"") + $t.Properties) -Log (Join-Path $logDir 'msi-install.log')
    Assert-Installed -Dir $t.Dir -StartOnLogin $t.Enabled -StartSSHAgent $t.Enabled

    Invoke-Msiexec -Arguments @('/x', "`"$Msi`"") -Log (Join-Path $logDir 'msi-uninstall.log')
    Assert-Uninstalled -Dir $t.Dir
}

# An upgrade from the previous release keeps the install options it used,
# except any given again on the command line, which win
Write-Output '== upgrade from the previous release keeps the install options'

Invoke-Msiexec -Arguments (@('/i', "`"$PreviousMsi`"") + $customOptions) -Log (Join-Path $logDir 'msi-previous.log')
Assert-Installed -Dir $customDir -StartOnLogin $false -StartSSHAgent $false

Invoke-Msiexec -Arguments @('/i', "`"$Msi`"", 'START_SSH_AGENT=1') -Log (Join-Path $logDir 'msi-upgrade.log')
Assert-Installed -Dir $customDir -StartOnLogin $false -StartSSHAgent $true
Assert-True (-not (Test-Path $installDir)) "default install directory $installDir not used"

Invoke-Msiexec -Arguments @('/x', "`"$Msi`"") -Log (Join-Path $logDir 'msi-uninstall.log')
Assert-Uninstalled -Dir $customDir
