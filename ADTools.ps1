<#
.SYNOPSIS
    RVC ADTools - Active Directory Helpdesk Toolkit
.DESCRIPTION
    A tabbed helpdesk tool for Active Directory management.

    Tab 1 - User:               Look up any AD account, view full details,
                                 group memberships, reset password, unlock.
    Tab 2 - Computer:           Look up AD computer objects, OU placement,
                                 OS, IP/DNS details, and memberships.
    Tab 3 - Lockout Diagnostics: Find what's causing account lockouts by
                                 querying all DCs and pulling Security event
                                 log entries (4740 lockout, 4625 bad logon).

    Access control is enforced by AD delegation - this script can only affect
    accounts your AD account has been granted rights over.

    REQUIREMENTS:
    - Run on a domain-joined machine
    - ActiveDirectory PowerShell module (RSAT) must be installed
    - PowerShell 5.1 or later
    - Security event log access on DCs required for Lockout Diagnostics
      (Domain Admin or delegated Event Log Reader on DCs)

.NOTES
    Version:  2.3.6
    GitHub:   https://github.com/Rock-Valley-College/ADTools
    Releases: https://github.com/Rock-Valley-College/ADTools/releases
#>

# -- VERSION -------------------------------------------------------------------
$SCRIPT_VERSION = "2.3.6"
$REPO_URL      = "https://github.com/Rock-Valley-College/ADTools"
$RELEASES_URL  = "$REPO_URL/releases"

function Get-StartupLogPath {
    if ($PSScriptRoot) { return Join-Path $PSScriptRoot 'ADTools-startup.log' }
    return Join-Path $env:TEMP 'ADTools-startup.log'
}

function Show-StartupFailure {
    param([string]$Message, [string]$Detail = '')
    $logPath = Get-StartupLogPath
    $entry = @(
        "----- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -----"
        $Message
        $Detail
        ""
    ) -join "`r`n"
    try { Add-Content -LiteralPath $logPath -Value $entry -Encoding UTF8 } catch { }
  try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue | Out-Null
        [System.Windows.Forms.MessageBox]::Show(
            "$Message`n`n$Detail`n`nLog: $logPath",
            'ADTools',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    } catch {
        Write-Host $Message -ForegroundColor Red
        if ($Detail) { Write-Host $Detail }
        Write-Host "Log: $logPath"
    }
}

# WinForms requires an STA thread. Re-launch and WAIT so the window stays open.
if ($PSCommandPath) {
    $apt = [System.Threading.Thread]::CurrentThread.GetApartmentState()
    if ($apt -ne [System.Threading.ApartmentState]::STA) {
        $psExe = if ($PSVersionTable.PSEdition -eq 'Core') {
            (Get-Command pwsh -ErrorAction SilentlyContinue).Source
        } else {
            Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        }
        if (-not $psExe -or -not (Test-Path -LiteralPath $psExe)) { $psExe = 'powershell.exe' }
        $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        $proc = Start-Process -FilePath $psExe -ArgumentList $argList -Wait -PassThru
        exit $(if ($null -ne $proc.ExitCode) { $proc.ExitCode } else { 0 })
    }
}

# -- CONFIG (local config.json beside this script) -----------------------------
$CONFIG = @{
    MinPasswordLength         = 16
    TempPasswordLength        = 16
}

$configPath = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'config.json' } else { $null }
if ($configPath -and (Test-Path -LiteralPath $configPath)) {
    try {
        $localConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        foreach ($key in $localConfig.PSObject.Properties.Name) {
            if ($key -eq '_comment') { continue }
            $CONFIG[$key] = $localConfig.$key
        }
    } catch { }
}

# -- BOOTSTRAP -----------------------------------------------------------------
$script:StartupOk = $false
try {
Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
Add-Type -AssemblyName System.Drawing -ErrorAction Stop
# Do not call EnableVisualStyles() - it lets Windows override our light text on dark backgrounds.

$script:ADModuleReady = $false
$script:ADSessionConnected = $false
$script:CachedPasswordPolicy = $null
$script:CachedDomainInfo = $null
$script:CachedDomainControllers = $null

function Ensure-ADModule {
    if ($script:ADModuleReady -and (Get-Module -Name ActiveDirectory)) {
        return @{ Ready=$true; Error='' }
    }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        return @{
            Ready = $false
            Error = 'ActiveDirectory module is not installed. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
        }
    }
    $prevDrive = $Env:ADPS_LoadDefaultDrive
    $Env:ADPS_LoadDefaultDrive = '0'
    try {
        Write-TerminalLog 'Import-Module ActiveDirectory' 'cmd'
        Import-Module ActiveDirectory -ErrorAction Stop
        $script:ADModuleReady = $true
        Write-TerminalLog 'Active Directory module loaded' 'ok'
        return @{ Ready=$true; Error='' }
    } catch {
        return @{ Ready=$false; Error="Could not load Active Directory module: $($_.Exception.Message)" }
    } finally {
        if ($null -eq $prevDrive) { Remove-Item Env:ADPS_LoadDefaultDrive -ErrorAction SilentlyContinue }
        else { $Env:ADPS_LoadDefaultDrive = $prevDrive }
    }
}

function Test-ADConnectivity {
    param([switch]$Quiet, [switch]$Force)
    if (-not $Force -and $script:ADSessionConnected) {
        return @{ Ready=$true; Error='' }
    }
    $ad = Ensure-ADModule
    if (-not $ad.Ready) { return $ad }
    try {
        $script:CachedDomainInfo = Invoke-LoggedAd { Get-ADDomain -ErrorAction Stop } -CommandLabel 'Get-ADDomain'
        $script:ADSessionConnected = $true
        return @{ Ready=$true; Error='' }
    } catch {
        $script:ADSessionConnected = $false
        $msg = 'Domain not reachable. Connect to your network or VPN, then try again.'
        Write-TerminalLog $msg 'err'
        if (-not $Quiet) { return @{ Ready=$false; Error=$msg } }
        return @{ Ready=$false; Error=$msg }
    }
}

function Pump-WinFormsMessages {
    try { [System.Windows.Forms.Application]::DoEvents() } catch { }
}

function Write-TerminalLog {
    param(
        [string]$Message,
        [ValidateSet('cmd', 'info', 'ok', 'warn', 'err')][string]$Kind = 'info'
    )
    $ts = Get-Date -Format 'HH:mm:ss'
    $tag = switch ($Kind) {
        'cmd'  { 'CMD' }
        'ok'   { ' OK' }
        'warn' { 'WRN' }
        'err'  { 'ERR' }
        default { '   ' }
    }
    $color = switch ($Kind) {
        'cmd'  { 'Cyan' }
        'ok'   { 'Green' }
        'warn' { 'Yellow' }
        'err'  { 'Red' }
        default { 'DarkGray' }
    }
    Write-Host "[$ts][$tag] $Message" -ForegroundColor $color
}

function Invoke-LoggedAd {
    param(
        [scriptblock]$ScriptBlock,
        [string]$CommandLabel
    )
    Write-TerminalLog $CommandLabel 'cmd'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $out = & $ScriptBlock
        $sw.Stop()
        Write-TerminalLog ("finished in {0:N0} ms" -f $sw.ElapsedMilliseconds) 'ok'
        return $out
    } catch {
        $sw.Stop()
        Write-TerminalLog ("failed after {0:N0} ms: {1}" -f $sw.ElapsedMilliseconds, $_.Exception.Message) 'err'
        throw
    }
}

function Invoke-LoggedWinEvent {
    param(
        [scriptblock]$ScriptBlock,
        [string]$CommandLabel
    )
    Write-TerminalLog $CommandLabel 'cmd'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $out = & $ScriptBlock
        $sw.Stop()
        $count = @($out).Count
        Write-TerminalLog ("finished in {0:N0} ms ({1} event(s))" -f $sw.ElapsedMilliseconds, $count) 'ok'
        return $out
    } catch {
        $sw.Stop()
        if ($_.Exception.Message -match 'No events were found|No matching events') {
            Write-TerminalLog ("no events ({0:N0} ms)" -f $sw.ElapsedMilliseconds) 'info'
            return @()
        }
        Write-TerminalLog ("failed after {0:N0} ms: {1}" -f $sw.ElapsedMilliseconds, $_.Exception.Message) 'err'
        throw
    }
}

function Get-GroupNamesFromMemberOf {
    param([AllowNull()][object]$MemberOf)
    if ($null -eq $MemberOf) { return @() }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($dn in @($MemberOf)) {
        if ([string]::IsNullOrWhiteSpace($dn)) { continue }
        $name = $null
        if ($dn.StartsWith('CN=', [StringComparison]::OrdinalIgnoreCase)) {
            $comma = $dn.IndexOf(',')
            if ($comma -gt 3) { $name = $dn.Substring(3, $comma - 3) }
            else { $name = $dn.Substring(3) }
            $name = $name -replace '\\,', ',' -replace '\\"', '"'
        }
        if ($name) { [void]$names.Add($name) }
    }
    return @($names | Sort-Object -Unique)
}

function Get-DomainPasswordPolicyCached {
    if ($script:CachedPasswordPolicy) { return $script:CachedPasswordPolicy }
    $script:CachedPasswordPolicy = Invoke-LoggedAd {
        Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    } -CommandLabel 'Get-ADDefaultDomainPasswordPolicy'
    return $script:CachedPasswordPolicy
}

function Get-DomainInfoCached {
    if ($script:CachedDomainInfo) { return $script:CachedDomainInfo }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { throw $ad.Error }
    return $script:CachedDomainInfo
}

function Get-DomainControllersCached {
    if ($script:CachedDomainControllers) { return $script:CachedDomainControllers }
    $script:CachedDomainControllers = @(
        Invoke-LoggedAd {
            Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object { $_.HostName }
        } -CommandLabel 'Get-ADDomainController -Filter *'
    )
    return $script:CachedDomainControllers
}

function Invoke-LockoutDiagnostics {
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [int]$HoursBack = 24
    )
    $out = New-Object System.Collections.Generic.List[object]
    $res = New-Object System.Collections.Generic.List[object]
    function Add-LogLine {
        param([string]$Text, [string]$Type = 'normal')
        [void]$out.Add([pscustomobject]@{ Text = $Text; Type = $Type })
    }

    $since = (Get-Date).AddHours(-$HoursBack)
    $iso = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

    try {
        $domain = Get-DomainInfoCached
        $pdc = $domain.PDCEmulator
    } catch {
        Add-LogLine "ERROR: Could not get domain info: $_" 'error'
        return @{ O = $out; R = $res }
    }

    try {
        $dcs = Get-DomainControllersCached
    } catch {
        Add-LogLine "ERROR: Could not enumerate DCs: $_" 'error'
        return @{ O = $out; R = $res }
    }

    Add-LogLine 'RVC ADTools - Lockout Diagnostics' 'heading'
    Add-LogLine "Started:    $(Get-Date -Format 'MM/dd/yyyy h:mm tt')" 'muted'
    Add-LogLine "Hours back: $HoursBack" 'muted'
    Add-LogLine "PDC:        $pdc" 'label'
    Add-LogLine "DCs ($($dcs.Count)): $($dcs -join ', ')" 'label'
    Add-LogLine '' 'muted'

    $u = $SamAccountName
    Add-LogLine '' 'normal'
    Add-LogLine ('=' * 72) 'heading'
    Add-LogLine "  USER: $u" 'heading'
    Add-LogLine ('=' * 72) 'heading'

    Add-LogLine '' 'normal'
    Add-LogLine '[ Per-DC State ]' 'label'
    $dcState = @()
    foreach ($dc in $dcs) {
        try {
            $a = Invoke-LoggedAd {
                Get-ADUser -Identity $u -Server $dc -Properties LockedOut, badPwdCount, LastBadPasswordAttempt, AccountLockoutTime -ErrorAction Stop
            } -CommandLabel "Get-ADUser -Identity '$u' -Server $dc -Properties LockedOut,badPwdCount,..."
            $dcState += [pscustomobject]@{
                DC       = $dc
                LockedOut = $a.LockedOut
                BadPwd   = $a.badPwdCount
                LastBad  = $a.LastBadPasswordAttempt
                LockTime = $a.AccountLockoutTime
            }
            $ls = if ($a.LockedOut) { 'LOCKED' } else { 'OK     ' }
            $lc = if ($a.LockedOut) { 'error' } else { 'success' }
            $lastBad = if ($a.LastBadPasswordAttempt) { $a.LastBadPasswordAttempt.ToString('MM/dd HH:mm:ss') } else { 'never' }
            Add-LogLine ("  {0,-42} {1}   BadPwd:{2,3}   LastBad: {3}" -f $dc, $ls, $a.badPwdCount, $lastBad) $lc
        } catch {
            Add-LogLine "  WARNING: Could not query $dc - $_" 'warn'
        }
        Pump-WinFormsMessages
    }

    $orig = $dcState | Where-Object { $_.LockTime } | Sort-Object LockTime -Descending | Select-Object -First 1
    Add-LogLine '' 'normal'
    if ($orig) {
        Add-LogLine "  > Originating DC: $($orig.DC)  (lockout at $($orig.LockTime))" 'warn'
    } else {
        Add-LogLine '  > No LockoutTime on any DC - may not be currently locked.' 'muted'
    }

    Add-LogLine '' 'normal'
    Add-LogLine "[ Event 4740 - Account Locked Out - PDC: $pdc ]" 'label'
    $x40 = "*[System[EventID=4740 and TimeCreated[@SystemTime>='$iso']] and EventData[Data[@Name='TargetUserName']='$u']]"
    try {
        $e40 = Invoke-LoggedWinEvent {
            Get-WinEvent -ComputerName $pdc -LogName Security -FilterXPath $x40 -ErrorAction Stop
        } -CommandLabel "Get-WinEvent -ComputerName $pdc -LogName Security -FilterXPath (EventID=4740, user=$u)"
    } catch {
        $e40 = @()
        Add-LogLine "  WARNING: $($_)" 'warn'
    }
    if ($e40) {
        foreach ($e in $e40) {
            $caller = $e.Properties[1].Value
            Add-LogLine ("  {0}   Caller: {1}" -f $e.TimeCreated.ToString('MM/dd/yyyy HH:mm:ss'), $caller) 'warn'
            [void]$res.Add([pscustomobject]@{
                User           = $u
                EventTime      = $e.TimeCreated
                EventId        = 4740
                EventType      = 'AccountLocked'
                CallerComputer = $caller
                CallerIP       = $null
                LogonProcess   = $null
                FailureReason  = $null
                SourceDC       = $pdc
            })
        }
    } else {
        Add-LogLine "  No 4740 events in last $HoursBack hour(s)." 'muted'
    }
    Pump-WinFormsMessages

    $srcs = @($pdc)
    if ($orig -and $orig.DC -ne $pdc) { $srcs += $orig.DC }
    foreach ($src in $srcs) {
        Add-LogLine '' 'normal'
        Add-LogLine "[ Event 4625 - Failed Logon - $src ]" 'label'
        $x25 = "*[System[EventID=4625 and TimeCreated[@SystemTime>='$iso']] and EventData[Data[@Name='TargetUserName']='$u']]"
        try {
            $e25 = Invoke-LoggedWinEvent {
                Get-WinEvent -ComputerName $src -LogName Security -FilterXPath $x25 -ErrorAction Stop
            } -CommandLabel "Get-WinEvent -ComputerName $src -LogName Security -FilterXPath (EventID=4625, user=$u)"
        } catch {
            $e25 = @()
            Add-LogLine "  WARNING: $($_)" 'warn'
        }
        if (-not $e25) {
            Add-LogLine "  No 4625 events in last $HoursBack hour(s)." 'muted'
            continue
        }
        $grp = $e25 | ForEach-Object {
            [pscustomobject]@{
                Time = $_.TimeCreated
                CC   = $_.Properties[13].Value
                IP   = $_.Properties[19].Value
                LP   = $_.Properties[10].Value
                FR   = $_.Properties[8].Value
            }
        }
        $grp | Group-Object CC, IP, LP | Sort-Object Count -Descending | ForEach-Object {
            $f = $_.Group[0]
            Add-LogLine ("  {0,4} attempts   Computer: {1,-24} IP: {2,-16} Process: {3}" -f $_.Count, $f.CC, $f.IP, $f.LP) 'warn'
        }
        foreach ($g in $grp) {
            [void]$res.Add([pscustomobject]@{
                User           = $u
                EventTime      = $g.Time
                EventId        = 4625
                EventType      = 'FailedLogon'
                CallerComputer = $g.CC
                CallerIP       = $g.IP
                LogonProcess   = $g.LP
                FailureReason  = $g.FR
                SourceDC       = $src
            })
        }
        Pump-WinFormsMessages
    }

    Add-LogLine '' 'normal'
    Add-LogLine ('-' * 72) 'muted'
    Add-LogLine "Complete - $($res.Count) event(s) collected." 'success'
    Add-LogLine '' 'normal'
    Add-LogLine 'Hints:' 'label'
    Add-LogLine '  CallerComputer - the machine submitting bad credentials.' 'muted'
    Add-LogLine '  Advapi process  - likely a service or scheduled task.' 'muted'
    Add-LogLine '  NtLmSsp/Kerberos - interactive or network logon.' 'muted'
    Add-LogLine '  Substatus 0xC000006A=wrong pwd  0xC0000064=bad username  0xC0000234=already locked' 'muted'

    return @{ O = $out; R = $res }
}

# -- HELPERS -------------------------------------------------------------------
function Test-SamAccountName {
    param([string]$Username)
    if ([string]::IsNullOrWhiteSpace($Username)) { return @{ Valid=$false; Error="Please enter a username." } }
    if ($Username -notmatch '^[a-zA-Z0-9._-]+$') { return @{ Valid=$false; Error="Invalid username characters." } }
    return @{ Valid=$true; Error="" }
}

function Test-ComputerAccountName {
    param([string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return @{ Valid=$false; Error="Please enter a computer name." } }
    $clean = $ComputerName.Trim().TrimEnd('$')
    if ($clean -notmatch '^[a-zA-Z0-9._-]+$') { return @{ Valid=$false; Error="Invalid computer name characters." } }
    return @{ Valid=$true; Name=$clean; Error="" }
}

function Get-CurrentOperatorName {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($identity -and -not [string]::IsNullOrWhiteSpace($identity.Name)) { return $identity.Name }
    } catch { }

    if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN) -and -not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
        return "$env:USERDOMAIN\$env:USERNAME"
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) { return $env:USERNAME }
    return 'unknown user'
}

function New-StampedAdNotes {
    param([AllowNull()][string]$Notes)
    if ([string]::IsNullOrWhiteSpace($Notes)) { return '' }

    $stamp = "Notes last updated by {0} on {1}" -f (Get-CurrentOperatorName), (Get-Date -Format 'yyyy-MM-dd')
    $body = $Notes.Trim()
    $lines = @($body -split "\r?\n")
    if ($lines.Count -gt 0 -and $lines[0].Trim() -match '^Notes last updated by .+ on \d{4}-\d{2}-\d{2}$') {
        $remaining = @($lines | Select-Object -Skip 1)
        if ($remaining.Count -gt 0) { return @($stamp) + $remaining -join "`r`n" }
        return $stamp
    }

    return @($stamp, $body) -join "`r`n"
}

function New-TempPassword {
    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $lower   = 'abcdefghjkmnpqrstuvwxyz'.ToCharArray()
    $digits  = '23456789'.ToCharArray()
    $special = '!@#$%^&*'.ToCharArray()
    $all     = $upper + $lower + $digits + $special
    $pwd     = @(($upper|Get-Random),($lower|Get-Random),($digits|Get-Random),($special|Get-Random))
    for ($i = 0; $i -lt ($CONFIG.TempPasswordLength - 4); $i++) { $pwd += ($all|Get-Random) }
    return -join ($pwd | Sort-Object { Get-Random })
}

function Get-UserAccount {
    param([string]$Username)
    $result = @{ Success=$false; User=$null; Groups=@(); PasswordStatus=$null; Error="" }
    $nameCheck = Test-SamAccountName -Username $Username
    if (-not $nameCheck.Valid) { $result.Error=$nameCheck.Error; return $result }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { $result.Error=$ad.Error; return $result }
    $props = @(
        'DisplayName', 'EmailAddress', 'Department', 'Title', 'DistinguishedName', 'Enabled',
        'LockedOut', 'CannotChangePassword', 'PasswordNeverExpires', 'PasswordLastSet',
        'PasswordExpired', 'LastLogonDate', 'Created', 'MemberOf', 'info'
    )
    $userCmd = "Get-ADUser -Identity '$Username' -Properties $($props -join ',')"
    try {
        $user = Invoke-LoggedAd {
            Get-ADUser -Identity $Username -Properties $props -ErrorAction Stop
        } -CommandLabel $userCmd
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $result.Error = "No account found for '$Username'."
        return $result
    } catch {
        $result.Error = "AD lookup failed: $($_.Exception.Message)"
        return $result
    }
    $memberCount = @($user.MemberOf).Count
    Write-TerminalLog "Resolved $memberCount group name(s) from MemberOf (no per-group AD queries)" 'info'
    $groups = Get-GroupNamesFromMemberOf -MemberOf $user.MemberOf
    $result.PasswordStatus = Get-UserPasswordChangeStatus -User $user
    $result.Success = $true
    $result.User = $user
    $result.Groups = $groups
    return $result
}

function Update-UserNotes {
    param([string]$Username, [AllowNull()][string]$Notes)
    $result = @{ Success=$false; Error="" }
    $nameCheck = Test-SamAccountName -Username $Username
    if (-not $nameCheck.Valid) { $result.Error=$nameCheck.Error; return $result }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { $result.Error=$ad.Error; return $result }
    try {
        if ([string]::IsNullOrWhiteSpace($Notes)) {
            Invoke-LoggedAd {
                Set-ADUser -Identity $Username -Clear info -ErrorAction Stop
            } -CommandLabel "Set-ADUser -Identity '$Username' -Clear info"
        } else {
            Invoke-LoggedAd {
                Set-ADUser -Identity $Username -Replace @{ info = $Notes } -ErrorAction Stop
            } -CommandLabel "Set-ADUser -Identity '$Username' -Replace @{info=...}"
        }
        $result.Success=$true
    } catch [System.UnauthorizedAccessException] { $result.Error="Access denied - no permission to update notes for this user."
    } catch { $result.Error="Notes update failed: $($_.Exception.Message)" }
    return $result
}

function Resolve-ComputerIPv4Address {
    param($Computer)
    if ($Computer.IPv4Address) { return [string]$Computer.IPv4Address }
    $target = if ($Computer.DNSHostName) { $Computer.DNSHostName } else { $Computer.Name }
    if ([string]::IsNullOrWhiteSpace($target)) { return '' }
    try {
        $addr = [System.Net.Dns]::GetHostAddresses($target) |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            Select-Object -First 1
        if ($addr) { return [string]$addr.IPAddressToString }
    } catch { }
    return ''
}

function Get-NameFromDN {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return '' }
    $cn = ($DN -split ',' | Where-Object { $_ -match '^CN=' } | Select-Object -First 1)
    if ($cn) { return ($cn -replace '^CN=','') -replace '\\,', ',' -replace '\\"', '"' }
    return $DN
}

function Get-ComputerAccount {
    param([string]$ComputerName)
    $result = @{ Success=$false; Computer=$null; Groups=@(); IPAddress=''; Error="" }
    $nameCheck = Test-ComputerAccountName -ComputerName $ComputerName
    if (-not $nameCheck.Valid) { $result.Error=$nameCheck.Error; return $result }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { $result.Error=$ad.Error; return $result }
    $name = $nameCheck.Name
    $props = @(
        'DNSHostName', 'IPv4Address', 'Description', 'DistinguishedName', 'Enabled',
        'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'Created',
        'Modified', 'PasswordLastSet', 'MemberOf', 'ManagedBy', 'Location', 'info'
    )
    $computerCmd = "Get-ADComputer -Identity '$name' -Properties $($props -join ',')"
    try {
        $computer = Invoke-LoggedAd {
            Get-ADComputer -Identity $name -Properties $props -ErrorAction Stop
        } -CommandLabel $computerCmd
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $result.Error = "No computer found for '$name'."
        return $result
    } catch {
        $result.Error = "Computer lookup failed: $($_.Exception.Message)"
        return $result
    }
    $memberCount = @($computer.MemberOf).Count
    Write-TerminalLog "Resolved $memberCount computer group name(s) from MemberOf (no per-group AD queries)" 'info'
    $result.Success = $true
    $result.Computer = $computer
    $result.Groups = Get-GroupNamesFromMemberOf -MemberOf $computer.MemberOf
    $result.IPAddress = Resolve-ComputerIPv4Address -Computer $computer
    return $result
}

function Update-ComputerNotes {
    param([string]$ComputerName, [AllowNull()][string]$Notes)
    $result = @{ Success=$false; Error="" }
    $nameCheck = Test-ComputerAccountName -ComputerName $ComputerName
    if (-not $nameCheck.Valid) { $result.Error=$nameCheck.Error; return $result }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { $result.Error=$ad.Error; return $result }
    $name = $nameCheck.Name
    try {
        if ([string]::IsNullOrWhiteSpace($Notes)) {
            Invoke-LoggedAd {
                Set-ADComputer -Identity $name -Clear info -ErrorAction Stop
            } -CommandLabel "Set-ADComputer -Identity '$name' -Clear info"
        } else {
            Invoke-LoggedAd {
                Set-ADComputer -Identity $name -Replace @{ info = $Notes } -ErrorAction Stop
            } -CommandLabel "Set-ADComputer -Identity '$name' -Replace @{info=...}"
        }
        $result.Success=$true
    } catch [System.UnauthorizedAccessException] { $result.Error="Access denied - no permission to update notes for this computer."
    } catch { $result.Error="Computer notes update failed: $($_.Exception.Message)" }
    return $result
}

function Invoke-PasswordReset {
    param([string]$Username,[string]$NewPassword)
    $result = @{ Success=$false; Error="" }
    if ($NewPassword.Length -lt $CONFIG.MinPasswordLength) { $result.Error="Password must be at least $($CONFIG.MinPasswordLength) characters."; return $result }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { $result.Error=$ad.Error; return $result }
    try {
        Invoke-LoggedAd {
            Set-ADAccountPassword -Identity $Username -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force) -Reset -ErrorAction Stop
        } -CommandLabel "Set-ADAccountPassword -Identity '$Username' -Reset"
        Invoke-LoggedAd {
            Set-ADUser -Identity $Username -ChangePasswordAtLogon $true -ErrorAction Stop
        } -CommandLabel "Set-ADUser -Identity '$Username' -ChangePasswordAtLogon `$true"
        $result.Success=$true
    } catch [System.UnauthorizedAccessException] { $result.Error="Access denied - no permission to reset this password."
    } catch { $result.Error="Reset failed: $($_.Exception.Message)" }
    return $result
}

function Invoke-AccountUnlock {
    param([string]$Username)
    $result = @{ Success=$false; Error="" }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { $result.Error=$ad.Error; return $result }
    try {
        Invoke-LoggedAd { Unlock-ADAccount -Identity $Username -ErrorAction Stop } -CommandLabel "Unlock-ADAccount -Identity '$Username'"
        $result.Success=$true
    } catch [System.UnauthorizedAccessException] { $result.Error="Access denied - no permission to unlock this account."
    } catch { $result.Error="Unlock failed: $($_.Exception.Message)" }
    return $result
}

function Invoke-AccountEnable {
    param([string]$Username)
    $result = @{ Success=$false; Error="" }
    $nameCheck = Test-SamAccountName -Username $Username
    if (-not $nameCheck.Valid) { $result.Error=$nameCheck.Error; return $result }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) { $result.Error=$ad.Error; return $result }
    try {
        Invoke-LoggedAd { Enable-ADAccount -Identity $Username -ErrorAction Stop } -CommandLabel "Enable-ADAccount -Identity '$Username'"
        $result.Success=$true
    } catch [System.UnauthorizedAccessException] { $result.Error="Access denied - no permission to enable this account."
    } catch { $result.Error="Enable failed: $($_.Exception.Message)" }
    return $result
}

function Format-DateOrNever {
    param($Value)
    if ($null -eq $Value) { return "Never" }
    try { return ([datetime]$Value).ToString("MM/dd/yyyy  h:mm tt") } catch { return "-" }
}

function Get-OUFromDN {
    param([string]$DN)
    $ou = ($DN -split ',' | Where-Object { $_ -match '^OU=' } | Select-Object -First 1)
    if ($ou) { return $ou -replace '^OU=','' }
    return $DN
}

function Get-OUPathFromDN {
    param([string]$DN)
    $ous = @($DN -split ',' | Where-Object { $_ -match '^OU=' } | ForEach-Object { $_ -replace '^OU=','' })
    if ($ous.Count -gt 0) { return ($ous -join ' / ') }
    return $DN
}

function Test-MustChangePasswordAtLogon {
    param($User)
    if ($null -eq $User.PasswordLastSet) { return $false }
    return ($User.PasswordLastSet.ToUniversalTime().Year -le 1601)
}

function Get-AdObjectLdapPath {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    return "LDAP://$DistinguishedName"
}

function Get-AdUserObjectSecurity {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    $ldapPath = Get-AdObjectLdapPath -DistinguishedName $DistinguishedName
    $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    return $entry.ObjectSecurity
}

function Get-SelfChangePasswordAceSummary {
    param([System.DirectoryServices.ActiveDirectorySecurity]$Acl)
    $changePwdGuid = [Guid]'ab721a53-1e2f-11d0-9819-00aa0040529b'
    $selfSid = 'S-1-5-10'
    $summary = @{
        ExplicitAllow  = $false
        InheritedAllow = $false
        ExplicitDeny   = $false
        InheritedDeny  = $false
    }
    foreach ($ace in $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($ace -isnot [System.DirectoryServices.ActiveDirectoryAccessRule]) { continue }
        if ($ace.ObjectType -ne $changePwdGuid) { continue }
        try {
            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            if ($sid.Value -ne $selfSid) { continue }
        } catch { continue }
        if ($ace.AccessControlType -eq 'Deny') {
            if ($ace.IsInherited) { $summary.InheritedDeny = $true } else { $summary.ExplicitDeny = $true }
        } elseif ($ace.AccessControlType -eq 'Allow') {
            if ($ace.IsInherited) { $summary.InheritedAllow = $true } else { $summary.ExplicitAllow = $true }
        }
    }
    return $summary
}

function Get-UserPasswordChangeStatus {
    param($User)
    $status = @{
        CannotChangePassword = [bool]$User.CannotChangePassword
        MustChangeAtLogon    = (Test-MustChangePasswordAtLogon -User $User)
        SelfChangePassword   = 'Unknown'
        Issues               = New-Object System.Collections.Generic.List[string]
        CanChangeOwnPassword = $true
    }

    if ($status.CannotChangePassword) {
        [void]$status.Issues.Add('Account flag "User cannot change password" is ON (AD Users and Computers > Account tab).')
    }
    if (-not $status.MustChangeAtLogon) {
        [void]$status.Issues.Add('"User must change password at next logon" is not set (temp logins may not prompt for a new password).')
    }

    try {
        $sam = $User.SamAccountName
        $acl = Invoke-LoggedAd {
            Get-AdUserObjectSecurity -DistinguishedName $User.DistinguishedName
        } -CommandLabel "DirectoryEntry.ObjectSecurity ($sam) - SELF Change Password"
        $self = Get-SelfChangePasswordAceSummary -Acl $acl
        if ($self.ExplicitDeny -or $self.InheritedDeny) {
            $status.SelfChangePassword = 'Deny'
            [void]$status.Issues.Add('SELF "Change password" is denied on this account (Security tab > SELF).')
        } elseif ($self.ExplicitAllow) {
            $status.SelfChangePassword = 'AllowExplicit'
        } elseif ($self.InheritedAllow) {
            $status.SelfChangePassword = 'AllowInherited'
        } else {
            $status.SelfChangePassword = 'NotAllowed'
            [void]$status.Issues.Add('SELF does not have "Change password" allowed (Security tab > SELF > Allow Change password).')
        }
    } catch {
        $status.SelfChangePassword = 'Error'
        [void]$status.Issues.Add("Could not read security ACL: $($_.Exception.Message)")
    }

    $status.CanChangeOwnPassword = (-not $status.CannotChangePassword) -and
        ($status.SelfChangePassword -in @('AllowExplicit', 'AllowInherited'))
    return $status
}

# -- THEME (standard light grey - readable on any Windows theme) ---------------
$C = @{
    Bg          = [System.Drawing.Color]::FromArgb(240, 240, 240)
    Panel       = [System.Drawing.Color]::FromArgb(245, 245, 245)
    Card        = [System.Drawing.Color]::White
    Border      = [System.Drawing.Color]::FromArgb(200, 200, 200)
    Accent      = [System.Drawing.Color]::FromArgb(0, 120, 215)
    Success     = [System.Drawing.Color]::FromArgb(0, 110, 55)
    Warning     = [System.Drawing.Color]::FromArgb(160, 90, 0)
    Danger      = [System.Drawing.Color]::FromArgb(180, 0, 0)
    TextPrimary = [System.Drawing.Color]::FromArgb(30, 30, 30)
    TextMuted   = [System.Drawing.Color]::FromArgb(90, 90, 90)
    TextDim     = [System.Drawing.Color]::FromArgb(120, 120, 120)
    InputBg     = [System.Drawing.Color]::White
    LogNormal   = [System.Drawing.Color]::FromArgb(30, 30, 30)
    LogWarn     = [System.Drawing.Color]::FromArgb(140, 80, 0)
    LogError    = [System.Drawing.Color]::FromArgb(180, 0, 0)
    LogSuccess  = [System.Drawing.Color]::FromArgb(0, 110, 55)
    LogMuted    = [System.Drawing.Color]::FromArgb(100, 100, 100)
    LogAccent   = [System.Drawing.Color]::FromArgb(0, 90, 180)
}
$F = @{
    Title   = New-Object System.Drawing.Font("Segoe UI",13,[System.Drawing.FontStyle]::Bold)
    Heading = New-Object System.Drawing.Font("Segoe UI",9, [System.Drawing.FontStyle]::Bold)
    Normal  = New-Object System.Drawing.Font("Segoe UI",9)
    Small   = New-Object System.Drawing.Font("Segoe UI",8)
    Micro   = New-Object System.Drawing.Font("Segoe UI",8)
    Mono    = New-Object System.Drawing.Font("Consolas",10,[System.Drawing.FontStyle]::Bold)
    MonoSm  = New-Object System.Drawing.Font("Consolas",9)
    MonoLog = New-Object System.Drawing.Font("Consolas",8.5)
}

function Set-ControlDarkStyle {
    param(
        [System.Windows.Forms.Control]$Control,
        [System.Drawing.Color]$BackColor = [System.Drawing.Color]::Empty
    )
    try {
        $styleProp = $Control.GetType().GetProperty('UseVisualStyleBackColor')
        if ($styleProp) { $styleProp.SetValue($Control, $false, $null) }
        if ($BackColor -ne [System.Drawing.Color]::Empty) { $Control.BackColor = $BackColor }
    } catch { }
}

function Set-TabNavStyle {
    param([System.Windows.Forms.Button]$Button, [bool]$Selected)
    Set-ControlDarkStyle $Button $(if ($Selected) { $C.Card } else { $C.Bg })
    $Button.ForeColor = $C.TextPrimary
    $Button.Font = if ($Selected) { $F.Heading } else { $F.Normal }
    $Button.FlatStyle = 'Flat'
    if ($Selected) {
        $Button.FlatAppearance.BorderColor = $C.Accent
        $Button.FlatAppearance.BorderSize = 2
    } else {
        $Button.FlatAppearance.BorderColor = $C.Border
        $Button.FlatAppearance.BorderSize = 1
    }
}

function Switch-AppTab {
    param([ValidateSet('User', 'Computer', 'Lockout')][string]$Name)
    $userOn = ($Name -eq 'User')
    $computerOn = ($Name -eq 'Computer')
    $lockoutOn = ($Name -eq 'Lockout')
    $pnlUserTab.Visible = $userOn
    $pnlComputerTab.Visible = $computerOn
    $pnlLockoutTab.Visible = $lockoutOn
    Set-TabNavStyle $btnTabUser $userOn
    Set-TabNavStyle $btnTabComputer $computerOn
    Set-TabNavStyle $btnTabLockout $lockoutOn
    if ($userOn) { $txtUserSearch.Focus() }
    elseif ($computerOn) { $txtComputerSearch.Focus() }
    else { $txtLockoutUser.Focus() }
}

# -- FORM ----------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text            = "RVC ADTools"
$form.Size            = New-Object System.Drawing.Size(920, 740)
$form.MinimumSize     = New-Object System.Drawing.Size(860, 660)
$form.StartPosition   = "CenterScreen"
$form.BackColor       = $C.Bg
$form.ForeColor       = $C.TextPrimary
$form.FormBorderStyle = "Sizable"
$form.Font            = $F.Normal

# Title bar and tab bar are separate Top panels so content never sits under the tabs
$pnlTitleBar = New-Object System.Windows.Forms.Panel
$pnlTitleBar.Dock="Top"; $pnlTitleBar.Height=44; $pnlTitleBar.BackColor=$C.Panel

$lblAppTitle = New-Object System.Windows.Forms.Label
$lblAppTitle.Text="RVC ADTools"; $lblAppTitle.Font=$F.Title
$lblAppTitle.ForeColor=$C.TextPrimary; $lblAppTitle.AutoSize=$true
Set-ControlDarkStyle $lblAppTitle $C.Panel
$lblAppTitle.Location=New-Object System.Drawing.Point(8,10)
$pnlTitleBar.Controls.Add($lblAppTitle)

$lblVerBadge = New-Object System.Windows.Forms.Label
$lblVerBadge.Text="v$SCRIPT_VERSION"; $lblVerBadge.Font=$F.Micro
$lblVerBadge.ForeColor=$C.TextMuted; $lblVerBadge.AutoSize=$true
Set-ControlDarkStyle $lblVerBadge $C.Panel
$lblVerBadge.Anchor="Top,Right"; $lblVerBadge.Location=New-Object System.Drawing.Point(830,14)
$pnlTitleBar.Controls.Add($lblVerBadge)

$pnlTabBar = New-Object System.Windows.Forms.Panel
$pnlTabBar.Dock="Top"; $pnlTabBar.Height=48; $pnlTabBar.BackColor=$C.Bg

$btnTabUser = New-Object System.Windows.Forms.Button
$btnTabUser.Text="User"; $btnTabUser.Width=170; $btnTabUser.Height=40
$btnTabUser.Dock="Left"; $btnTabUser.Cursor="Hand"

$btnTabComputer = New-Object System.Windows.Forms.Button
$btnTabComputer.Text="Computer"; $btnTabComputer.Width=190; $btnTabComputer.Height=40
$btnTabComputer.Dock="Left"; $btnTabComputer.Cursor="Hand"

$btnTabLockout = New-Object System.Windows.Forms.Button
$btnTabLockout.Text="Lockout Diagnostics"; $btnTabLockout.Height=40
$btnTabLockout.Dock="Fill"; $btnTabLockout.Cursor="Hand"

$pnlTabBar.Controls.Add($btnTabLockout)
$pnlTabBar.Controls.Add($btnTabComputer)
$pnlTabBar.Controls.Add($btnTabUser)

# Toolbar rows on the form (below tabs) so Fill panels cannot cover them
$pnlUserSearch = New-Object System.Windows.Forms.Panel
$pnlUserSearch.Dock="Top"; $pnlUserSearch.Height=56; $pnlUserSearch.BackColor=$C.Bg

$pnlComputerSearch = New-Object System.Windows.Forms.Panel
$pnlComputerSearch.Dock="Top"; $pnlComputerSearch.Height=56; $pnlComputerSearch.BackColor=$C.Bg

$pnlLkCtrl = New-Object System.Windows.Forms.Panel
$pnlLkCtrl.Dock="Top"; $pnlLkCtrl.Height=56; $pnlLkCtrl.BackColor=$C.Bg

$pnlLkAct = New-Object System.Windows.Forms.Panel
$pnlLkAct.Dock="Top"; $pnlLkAct.Height=36; $pnlLkAct.BackColor=$C.Bg

# Status bar
$pnlStatus = New-Object System.Windows.Forms.Panel
$pnlStatus.Dock="Bottom"; $pnlStatus.Height=26; $pnlStatus.BackColor=$C.Panel

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text="Ready."; $lblStatus.Font=$F.Small
$lblStatus.ForeColor=$C.TextPrimary; $lblStatus.AutoSize=$true
Set-ControlDarkStyle $lblStatus $C.Panel
$lblStatus.Location=New-Object System.Drawing.Point(14,6)
$pnlStatus.Controls.Add($lblStatus)

$lnkUpdates = New-Object System.Windows.Forms.LinkLabel
$lnkUpdates.Text="Get latest version"; $lnkUpdates.Font=$F.Small
$lnkUpdates.LinkColor=$C.Accent; $lnkUpdates.ActiveLinkColor=$C.Accent
$lnkUpdates.VisitedLinkColor=$C.TextMuted; $lnkUpdates.AutoSize=$true
Set-ControlDarkStyle $lnkUpdates $C.Panel
$lnkUpdates.Cursor=[System.Windows.Forms.Cursors]::Hand
$lnkUpdates.Anchor="Top,Right"
$pnlStatus.Controls.Add($lnkUpdates)
$lnkUpdates.Add_LinkClicked({ Start-Process $RELEASES_URL })
$pnlStatus.Add_Resize({
    $lnkUpdates.Location=New-Object System.Drawing.Point(($pnlStatus.ClientSize.Width-$lnkUpdates.Width-14),6)
})
$lnkUpdates.Location=New-Object System.Drawing.Point(780,6)

function Set-Status {
    param([string]$Msg,[string]$Type="info")
    $lblStatus.ForeColor=switch($Type){"success"{$C.Success}"error"{$C.Danger}"warning"{$C.Warning}default{$C.TextPrimary}}
    $lblStatus.Text=$Msg
}

# -- BODY (toolbars + tab pages in one Fill panel so layout stacks correctly) -----
$pnlBody = New-Object System.Windows.Forms.Panel
$pnlBody.Dock="Fill"; $pnlBody.BackColor=$C.Bg

$pnlShell = New-Object System.Windows.Forms.Panel
$pnlShell.Dock="Fill"; $pnlShell.BackColor=$C.Bg

$pnlUserTab = New-Object System.Windows.Forms.Panel
$pnlUserTab.Dock="Fill"; $pnlUserTab.BackColor=$C.Bg; $pnlUserTab.Visible=$true

$pnlComputerTab = New-Object System.Windows.Forms.Panel
$pnlComputerTab.Dock="Fill"; $pnlComputerTab.BackColor=$C.Bg; $pnlComputerTab.Visible=$false

$pnlLockoutTab = New-Object System.Windows.Forms.Panel
$pnlLockoutTab.Dock="Fill"; $pnlLockoutTab.BackColor=$C.Bg; $pnlLockoutTab.Visible=$false

$pnlShell.Controls.Add($pnlLockoutTab)
$pnlShell.Controls.Add($pnlComputerTab)
$pnlShell.Controls.Add($pnlUserTab)

$pnlBody.Controls.Add($pnlShell)

$btnTabUser.Add_Click({ Switch-AppTab -Name User })
$btnTabComputer.Add_Click({ Switch-AppTab -Name Computer })
$btnTabLockout.Add_Click({ Switch-AppTab -Name Lockout })
Set-TabNavStyle $btnTabUser $true
Set-TabNavStyle $btnTabComputer $false
Set-TabNavStyle $btnTabLockout $false

$form.Controls.Add($pnlBody)
$form.Controls.Add($pnlStatus)
$form.Controls.Add($pnlTitleBar)
$form.Controls.Add($pnlTabBar)

# ==============================================================================
# TAB 1 - USER
# ==============================================================================

$splitUser = New-Object System.Windows.Forms.SplitContainer
$splitUser.Dock="Fill"; $splitUser.BackColor=$C.Bg; $splitUser.BorderStyle="None"
$splitUser.Panel1.AutoScroll=$true; $splitUser.Panel2.AutoScroll=$true
$splitUser.Panel1.Padding=New-Object System.Windows.Forms.Padding(8,8,4,8)
$splitUser.Panel2.Padding=New-Object System.Windows.Forms.Padding(4,8,8,8)

function Update-GroupsListHeight {
    if (-not $cGrp -or -not $lstGroups) { return }
    $lstGroups.Width=[Math]::Max(100,$cGrp.ClientSize.Width-24)
    $lstGroups.Height=[Math]::Max(120,$cGrp.ClientSize.Height-36)
}

function Update-UserNotesLayout {
    if (-not $cUserNotes -or -not $txtUserNotes) { return }
    $txtUserNotes.Width=[Math]::Max(100,$cUserNotes.ClientSize.Width-24)
}

function New-Lbl { param($parent,$text,$font,$color,$x,$y,$autosize=$true)
    $lblCtrl=New-Object System.Windows.Forms.Label; $lblCtrl.Text=$text; $lblCtrl.Font=$font
    $lblCtrl.AutoSize=$autosize; $lblCtrl.Location=New-Object System.Drawing.Point($x,$y)
    Set-ControlDarkStyle $lblCtrl $parent.BackColor
    $lblCtrl.ForeColor=$color
    $parent.Controls.Add($lblCtrl); return $lblCtrl }
function New-Btn { param($parent,$text,$font,$bg,$fg,$x,$y,$w,$h,[bool]$enabled=$true)
    $b=New-Object System.Windows.Forms.Button; $b.Text=$text; $b.Font=$font
    $b.BackColor=$bg; $b.ForeColor=$fg; $b.Size=New-Object System.Drawing.Size($w,$h)
    $b.Location=New-Object System.Drawing.Point($x,$y); $b.FlatStyle="Flat"
    $b.FlatAppearance.BorderSize=0; $b.Cursor="Hand"; $b.Enabled=$enabled
    Set-ControlDarkStyle $b
    $b.ForeColor=$fg
    $parent.Controls.Add($b); return $b }
function New-Txt { param($parent,$x,$y,$w,$font)
    $t=New-Object System.Windows.Forms.TextBox; $t.Size=New-Object System.Drawing.Size($w,26)
    $t.Location=New-Object System.Drawing.Point($x,$y); $t.BackColor=$C.InputBg
    $t.ForeColor=$C.TextPrimary; $t.BorderStyle="FixedSingle"; $t.Font=$font
    Set-ControlDarkStyle $t $C.InputBg
    $parent.Controls.Add($t); return $t }
function New-Memo { param($parent,$x,$y,$w,$h)
    $t=New-Object System.Windows.Forms.TextBox; $t.Size=New-Object System.Drawing.Size($w,$h)
    $t.Location=New-Object System.Drawing.Point($x,$y); $t.BackColor=$C.InputBg
    $t.ForeColor=$C.TextPrimary; $t.BorderStyle="FixedSingle"; $t.Font=$F.MonoSm
    $t.Multiline=$true; $t.AcceptsReturn=$true; $t.ScrollBars="Vertical"; $t.Enabled=$false
    Set-ControlDarkStyle $t $C.InputBg
    $parent.Controls.Add($t); return $t }

# Fill first, then Top (search bar) so the bar never sits under the split view
$pnlUserTab.Controls.Add($splitUser)

New-Lbl $pnlUserSearch "Username" $F.Heading $C.TextPrimary 12 18 | Out-Null
$txtUserSearch = New-Txt $pnlUserSearch 98 14 320 $F.Mono
$btnUserSearch = New-Btn $pnlUserSearch "Look Up" $F.Heading $C.Accent ([System.Drawing.Color]::White) 430 14 86 28

function New-Card {
    param([System.Windows.Forms.Control]$Parent,[string]$Title,[int]$Height)
    $card=New-Object System.Windows.Forms.Panel
    $card.Height=$Height; $card.Dock="Top"; $card.BackColor=$C.Card
    $Parent.Controls.Add($card)
    if($Title){ New-Lbl $card $Title.ToUpper() $F.Micro $C.TextMuted 14 10 | Out-Null }
    return $card
}

# Identity (Dock Top: add top-to-bottom in order)
$cId = New-Card $splitUser.Panel1 "Identity" 155
$lblDN   = New-Lbl $cId "-" (New-Object System.Drawing.Font("Segoe UI",15,[System.Drawing.FontStyle]::Bold)) $C.TextPrimary 14 28
$lblDN.Size=New-Object System.Drawing.Size(360,30)
$lblUN2  = New-Lbl $cId "-" $F.MonoSm $C.Accent 14 62
$lblMail = New-Lbl $cId "-" $F.Small $C.TextMuted 14 82
$lblDept = New-Lbl $cId "-" $F.Small $C.TextMuted 14 100
$lblStat = New-Lbl $cId "" $F.Heading $C.TextMuted 14 124
$lblLock = New-Lbl $cId "" $F.Heading $C.Danger 120 124

# Details
$cDet = New-Card $splitUser.Panel1 "Account Details" 260
function New-DR { param($card,$lbl,$y)
    New-Lbl $card $lbl $F.Small $C.TextMuted 14 $y | Out-Null
    $v=New-Lbl $card "-" $F.Small $C.TextPrimary 158 $y; $v.Size=New-Object System.Drawing.Size(220,16); return $v }
$vCreated = New-DR $cDet "Created"            28
$vLogon   = New-DR $cDet "Last Logon"         50
$vPwdSet  = New-DR $cDet "Password Last Set"  72
$vPwdExp  = New-DR $cDet "Password Expires"   94
$vNvrExp  = New-DR $cDet "Pwd Never Expires"  116
$vCantChg = New-DR $cDet "Cannot Change Pwd"  138
$vMustChg = New-DR $cDet "Must Change Pwd"    160
$vSelfChg = New-DR $cDet "SELF Change Pwd"    182
$vOU      = New-DR $cDet "OU"                 204

# Password reset
$cPwd = New-Card $splitUser.Panel1 "Password Reset" 150
New-Lbl $cPwd "Temporary Password" $F.Heading $C.TextPrimary 14 28 | Out-Null
$txtPwd    = New-Txt   $cPwd 14 48 212 $F.Mono
$btnGenPwd = New-Btn   $cPwd "New" $F.Small $C.Bg $C.TextPrimary 234 48 56 24 $false
$btnGenPwd.FlatAppearance.BorderColor=$C.Border; $btnGenPwd.FlatAppearance.BorderSize=1
$btnCpyPwd = New-Btn   $cPwd "Copy" $F.Small $C.Bg $C.TextPrimary 298 48 52 24 $false
$btnCpyPwd.FlatAppearance.BorderColor=$C.Border; $btnCpyPwd.FlatAppearance.BorderSize=1
$chkShow   = New-Object System.Windows.Forms.CheckBox; $chkShow.Text="Show password"
$chkShow.Font=$F.Small; $chkShow.ForeColor=$C.TextPrimary; $chkShow.AutoSize=$true
$chkShow.Checked=$true; $chkShow.Location=New-Object System.Drawing.Point(14,80)
$chkShow.FlatStyle="Flat"; Set-ControlDarkStyle $chkShow $C.Card
$cPwd.Controls.Add($chkShow)

$btnRstPwd = New-Btn   $cPwd "Reset Password" $F.Heading $C.Accent ([System.Drawing.Color]::White) 14 106 344 32 $false

# Right - Groups
$cGrp = New-Card $splitUser.Panel2 "Group Memberships" 395
$lstGroups = New-Object System.Windows.Forms.ListBox
$lstGroups.Location=New-Object System.Drawing.Point(12,27)
$lstGroups.Size=New-Object System.Drawing.Size(360,358)
$lstGroups.BackColor=$C.InputBg; $lstGroups.ForeColor=$C.TextPrimary
$lstGroups.BorderStyle="None"; $lstGroups.Font=$F.MonoSm
$lstGroups.Anchor="Top,Left,Right,Bottom"
$cGrp.Controls.Add($lstGroups)
$cGrp.Add_Resize({ Update-GroupsListHeight })
$splitUser.Add_SplitterMoved({ Update-GroupsListHeight })

# Right - AD Notes
$cUserNotes = New-Card $splitUser.Panel2 "AD Notes" 178
$txtUserNotes = New-Memo $cUserNotes 12 30 360 96
$txtUserNotes.Anchor="Top,Left,Right"
$btnUserSaveNotes = New-Btn $cUserNotes "Save Notes" $F.Heading $C.Bg $C.TextPrimary 12 136 130 30 $false
$btnUserSaveNotes.FlatAppearance.BorderColor=$C.Border; $btnUserSaveNotes.FlatAppearance.BorderSize=1
$lblUserNotesHint = New-Lbl $cUserNotes "Updates the 'Notes last updated by' line." $F.Small $C.TextMuted 154 143
$cUserNotes.Add_Resize({ Update-UserNotesLayout })
$splitUser.Add_SplitterMoved({ Update-UserNotesLayout })

# Right - Actions
$cAct = New-Card $splitUser.Panel2 "Actions" 120
$btnUnlock  = New-Btn $cAct "Unlock Account"    $F.Heading $C.Bg $C.TextPrimary  14  30 150 34 $false
$btnUnlock.FlatAppearance.BorderColor=$C.Warning; $btnUnlock.FlatAppearance.BorderSize=1
$btnEnable  = New-Btn $cAct "Enable Account"     $F.Heading $C.Bg $C.TextPrimary 176 30 150 34 $false
$btnEnable.FlatAppearance.BorderColor=$C.Success; $btnEnable.FlatAppearance.BorderSize=1
$btnRefresh = New-Btn $cAct "Refresh"             $F.Heading $C.Bg $C.TextPrimary 338 30 100 34 $false
$btnRefresh.FlatAppearance.BorderColor=$C.Border; $btnRefresh.FlatAppearance.BorderSize=1
$btnDiag    = New-Btn $cAct "Diagnose Lockout"   $F.Heading $C.Bg $C.TextPrimary   14 74 180 34 $false
$btnDiag.FlatAppearance.BorderColor=$C.Danger; $btnDiag.FlatAppearance.BorderSize=1
$btnDiag.Visible=$false

$pnlUserTab.Controls.Add($pnlUserSearch)

# -- USER TAB LOGIC ------------------------------------------------------------
$script:CurUser=$null; $script:CurGroups=@(); $script:CurPasswordStatus=$null

function Clear-UDisplay {
    $lblDN.Text="-"; $lblUN2.Text="-"; $lblMail.Text="-"; $lblDept.Text="-"
    $lblStat.Text=""; $lblLock.Text=""
    $vCreated.Text="-"; $vLogon.Text="-"; $vPwdSet.Text="-"; $vPwdExp.Text="-"
    $vNvrExp.Text="-"; $vCantChg.Text="-"; $vMustChg.Text="-"; $vSelfChg.Text="-"; $vOU.Text="-"
    $lstGroups.Items.Clear(); $txtPwd.Text=""; $txtUserNotes.Text=""; $txtUserNotes.Enabled=$false
    $btnRstPwd.Enabled=$false; $btnGenPwd.Enabled=$false; $btnCpyPwd.Enabled=$false
    $btnUnlock.Enabled=$false; $btnEnable.Enabled=$false; $btnRefresh.Enabled=$false; $btnUserSaveNotes.Enabled=$false; $btnDiag.Visible=$false
    $script:CurUser=$null; $script:CurGroups=@(); $script:CurPasswordStatus=$null
}

function Show-UData {
    param($User, $Groups, $PasswordStatus = $null)
    $lblDN.Text  = if($User.DisplayName){$User.DisplayName}else{$User.SamAccountName}
    $lblUN2.Text = $User.SamAccountName
    $lblMail.Text= if($User.EmailAddress){$User.EmailAddress}else{"No email on file"}
    $dp=@(); if($User.Title){$dp+=$User.Title}; if($User.Department){$dp+=$User.Department}
    $lblDept.Text= if($dp){$dp -join "  |  "}else{"No dept/title on file"}
    if($User.Enabled){ $lblStat.Text="* ACTIVE";    $lblStat.ForeColor=$C.Success; $btnEnable.Enabled=$false }
    else             { $lblStat.Text="* DISABLED";  $lblStat.ForeColor=$C.Danger;  $btnEnable.Enabled=$true  }
    if($User.LockedOut){
        $lblLock.Text="LOCKED OUT"; $btnUnlock.Enabled=$true; $btnDiag.Visible=$true
    } else { $lblLock.Text=""; $btnUnlock.Enabled=$false; $btnDiag.Visible=$false }
    $vCreated.Text= Format-DateOrNever $User.Created
    $vLogon.Text  = Format-DateOrNever $User.LastLogonDate
    $vPwdSet.Text = Format-DateOrNever $User.PasswordLastSet
    if($User.PasswordNeverExpires){ $vPwdExp.Text="Never"; $vPwdExp.ForeColor=$C.TextMuted }
    elseif($User.PasswordExpired) { $vPwdExp.Text="EXPIRED"; $vPwdExp.ForeColor=$C.Danger  }
    else {
        try {
            $pol = Get-DomainPasswordPolicyCached
            if($User.PasswordLastSet -and $pol.MaxPasswordAge.TotalDays -gt 0){
                $exp=$User.PasswordLastSet+$pol.MaxPasswordAge; $d=($exp-(Get-Date)).Days
                $vPwdExp.Text=$exp.ToString("MM/dd/yyyy")+"  ($d days)"
                $vPwdExp.ForeColor=if($d -le 14){$C.Warning}else{$C.TextPrimary}
            } else { $vPwdExp.Text="-"; $vPwdExp.ForeColor=$C.TextPrimary }
        } catch { $vPwdExp.Text="-"; $vPwdExp.ForeColor=$C.TextPrimary }
    }
    $vNvrExp.Text  = if($User.PasswordNeverExpires){"Yes"}else{"No"}
    $vCantChg.Text = if ($User.CannotChangePassword) { 'Yes (blocked)' } else { 'No' }
    $vCantChg.ForeColor = if ($User.CannotChangePassword) { $C.Warning } else { $C.TextPrimary }

    if ($PasswordStatus) {
        $vMustChg.Text = if ($PasswordStatus.MustChangeAtLogon) { 'Yes' } else { 'No (may skip prompt)' }
        $vMustChg.ForeColor = if ($PasswordStatus.MustChangeAtLogon) { $C.Success } else { $C.Warning }
        $vSelfChg.Text = switch ($PasswordStatus.SelfChangePassword) {
            'AllowExplicit'  { 'Allow (explicit)' }
            'AllowInherited' { 'Allow (inherited)' }
            'Deny'           { 'DENIED' }
            'NotAllowed'     { 'Not allowed' }
            'Error'          { 'Could not read' }
            default          { '-' }
        }
        $vSelfChg.ForeColor = switch ($PasswordStatus.SelfChangePassword) {
            { $_ -in @('AllowExplicit', 'AllowInherited') } { $C.Success }
            'Deny'       { $C.Danger }
            'NotAllowed' { $C.Warning }
            default      { $C.TextPrimary }
        }
    } else {
        $vMustChg.Text = '-'; $vSelfChg.Text = '-'
        $vMustChg.ForeColor = $C.TextPrimary; $vSelfChg.ForeColor = $C.TextPrimary
    }

    $vOU.Text = Get-OUFromDN $User.DistinguishedName
    $lstGroups.Items.Clear()
    if($Groups.Count -gt 0){ foreach($g in $Groups){ $lstGroups.Items.Add($g)|Out-Null } }
    else { $lstGroups.Items.Add("(no group memberships)")|Out-Null }
    $txtUserNotes.Text = if($User.info){[string]$User.info}else{""}
    $txtUserNotes.Enabled = $true
    $btnRstPwd.Enabled = (-not $User.CannotChangePassword)
    $btnGenPwd.Enabled = $btnRstPwd.Enabled
    $btnCpyPwd.Enabled = $btnRstPwd.Enabled
    $btnRefresh.Enabled = $true
    $btnUserSaveNotes.Enabled = $true
    if ($btnRstPwd.Enabled) { $txtPwd.Text = New-TempPassword }

    if ($PasswordStatus -and $PasswordStatus.Issues.Count -gt 0) {
        $hint = $PasswordStatus.Issues[0]
        if ($PasswordStatus.Issues.Count -gt 1) { $hint += " (+$($PasswordStatus.Issues.Count - 1) more - see terminal)" }
        foreach ($issue in $PasswordStatus.Issues) { Write-TerminalLog "Password change: $issue" 'warn' }
        $stype = if (-not $PasswordStatus.CanChangeOwnPassword) { 'error' } else { 'warning' }
        Set-Status $hint $stype
    } elseif (-not $User.CannotChangePassword) {
        Set-Status "Loaded: $($User.DisplayName)  |  $($Groups.Count) group(s)" 'success'
    }
}

function Invoke-USearch {
    $u=$txtUserSearch.Text.Trim(); if([string]::IsNullOrWhiteSpace($u)){return}
    Clear-UDisplay; Set-Status "Looking up '$u'..." "info"
    $btnUserSearch.Enabled=$false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-TerminalLog "----- Lookup: $u -----" 'info'
    try {
        $r = Get-UserAccount -Username $u
    } finally {
        $btnUserSearch.Enabled = $true
    }
    $sw.Stop()
    if (-not $r.Success) {
        Set-Status $r.Error "error"
        Write-TerminalLog "Lookup failed for '$u'" 'err'
        return
    }
    $script:CurUser = $r.User
    $script:CurGroups = $r.Groups
    $script:CurPasswordStatus = $r.PasswordStatus
    Show-UData -User $r.User -Groups $r.Groups -PasswordStatus $r.PasswordStatus
    Write-TerminalLog ("Lookup complete: $($r.Groups.Count) group(s), total {0:N0} ms" -f $sw.ElapsedMilliseconds) 'ok'
}

$btnUserSearch.Add_Click({ Invoke-USearch })
$txtUserSearch.Add_KeyDown({ if($_.KeyCode -eq "Return"){ Invoke-USearch } })
$btnRefresh.Add_Click({ if($script:CurUser){ $txtUserSearch.Text=$script:CurUser.SamAccountName; Invoke-USearch } })
$btnUserSaveNotes.Add_Click({
    if(-not $script:CurUser){return}
    $u=$script:CurUser.SamAccountName
    $notes=New-StampedAdNotes -Notes $txtUserNotes.Text
    $btnUserSaveNotes.Enabled=$false
    Set-Status "Updating AD notes for $u..." "info"
    $r=Update-UserNotes -Username $u -Notes $notes
    if($r.Success){
        $txtUserNotes.Text = $notes
        try { $script:CurUser.info = $notes } catch { }
        Set-Status "AD notes updated for $u." "success"
        $btnUserSaveNotes.Enabled=$true
    } else {
        Set-Status $r.Error "error"
        $btnUserSaveNotes.Enabled=$true
    }
})
$btnGenPwd.Add_Click({ $txtPwd.Text=New-TempPassword })
$btnCpyPwd.Add_Click({ if($txtPwd.Text){ [System.Windows.Forms.Clipboard]::SetText($txtPwd.Text); Set-Status "Password copied to clipboard." "info" } })
$chkShow.Add_CheckedChanged({ $txtPwd.UseSystemPasswordChar=-not $chkShow.Checked })

$btnRstPwd.Add_Click({
    if(-not $script:CurUser){return}
    $u=$script:CurUser.SamAccountName; $p=$txtPwd.Text
    if([string]::IsNullOrWhiteSpace($p)){Set-Status "Please generate a temporary password first." "error";return}
    $c=[System.Windows.Forms.MessageBox]::Show(
        "Reset password for $($script:CurUser.DisplayName) ($u)?`n`nTemporary password:  $p`n`nUser must change this at next sign-in.",
        "Confirm Password Reset",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Question)
    if($c -ne "Yes"){return}
    $btnRstPwd.Enabled=$false; Set-Status "Resetting password for $u..." "info"
    $r=Invoke-PasswordReset -Username $u -NewPassword $p
    if($r.Success){
        Set-Status "Password reset for $($script:CurUser.DisplayName)." "success"
        $extra = ''
        if ($script:CurPasswordStatus -and -not $script:CurPasswordStatus.CanChangeOwnPassword) {
            $extra = "`n`nNote: This account may still be unable to change its own password (check Cannot Change Pwd / SELF Change Pwd in Account Details)."
        } elseif ($script:CurPasswordStatus -and $script:CurPasswordStatus.SelfChangePassword -in @('NotAllowed', 'Deny')) {
            $extra = "`n`nIf the user gets Access Denied when changing password: AD Users and Computers > Security > SELF > check Allow for Change password."
        }
        [System.Windows.Forms.MessageBox]::Show(
            "Password reset successfully.`n`nUsername:        $u`nTemp Password:  $p`n`nUser must change password at next logon (domain PC: Ctrl+Alt+Del > Change a password).$extra",
            "Reset Complete",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)|Out-Null
        $txtPwd.Text=New-TempPassword; $btnRstPwd.Enabled=$true
    } else { Set-Status $r.Error "error"; $btnRstPwd.Enabled=$true }
})

$btnUnlock.Add_Click({
    if(-not $script:CurUser){return}
    $u=$script:CurUser.SamAccountName
    $c=[System.Windows.Forms.MessageBox]::Show("Unlock account for $($script:CurUser.DisplayName) ($u)?",
        "Confirm Unlock",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Question)
    if($c -ne "Yes"){return}
    $btnUnlock.Enabled=$false; Set-Status "Unlocking $u..." "info"
    $r=Invoke-AccountUnlock -Username $u
    if($r.Success){
        Set-Status "Account unlocked for $($script:CurUser.DisplayName)." "success"
        $lblLock.Text=""; $btnDiag.Visible=$false
    } else { Set-Status $r.Error "error"; $btnUnlock.Enabled=$true }
})

$btnEnable.Add_Click({
    if(-not $script:CurUser){return}
    $u=$script:CurUser.SamAccountName
    $c=[System.Windows.Forms.MessageBox]::Show("Enable account for $($script:CurUser.DisplayName) ($u)?",
        "Confirm Enable",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Question)
    if($c -ne "Yes"){return}
    $btnEnable.Enabled=$false; Set-Status "Enabling $u..." "info"
    $r=Invoke-AccountEnable -Username $u
    if($r.Success){
        $script:CurUser.Enabled=$true
        $lblStat.Text="* ACTIVE"; $lblStat.ForeColor=$C.Success
        Set-Status "Account enabled for $($script:CurUser.DisplayName)." "success"
    } else { Set-Status $r.Error "error"; $btnEnable.Enabled=$true }
})

# Diagnose button - prefill lockout tab and switch to it
$btnDiag.Add_Click({
    if($script:CurUser){ $txtLockoutUser.Text=$script:CurUser.SamAccountName; Switch-AppTab -Name Lockout }
})

# ==============================================================================
# TAB 2 - COMPUTER
# ==============================================================================

$splitComputer = New-Object System.Windows.Forms.SplitContainer
$splitComputer.Dock="Fill"; $splitComputer.BackColor=$C.Bg; $splitComputer.BorderStyle="None"
$splitComputer.Panel1.AutoScroll=$true; $splitComputer.Panel2.AutoScroll=$true
$splitComputer.Panel1.Padding=New-Object System.Windows.Forms.Padding(8,8,4,8)
$splitComputer.Panel2.Padding=New-Object System.Windows.Forms.Padding(4,8,8,8)

function Update-ComputerGroupsListHeight {
    if (-not $cCompGrp -or -not $lstComputerGroups) { return }
    $lstComputerGroups.Width=[Math]::Max(100,$cCompGrp.ClientSize.Width-24)
    $lstComputerGroups.Height=[Math]::Max(120,$cCompGrp.ClientSize.Height-36)
}

function Update-ComputerNotesLayout {
    if (-not $cCompNotes -or -not $txtComputerNotes) { return }
    $txtComputerNotes.Width=[Math]::Max(100,$cCompNotes.ClientSize.Width-24)
}

$pnlComputerTab.Controls.Add($splitComputer)

New-Lbl $pnlComputerSearch "Computer" $F.Heading $C.TextPrimary 12 18 | Out-Null
$txtComputerSearch = New-Txt $pnlComputerSearch 98 14 320 $F.Mono
$btnComputerSearch = New-Btn $pnlComputerSearch "Look Up" $F.Heading $C.Accent ([System.Drawing.Color]::White) 430 14 86 28

$cCompId = New-Card $splitComputer.Panel1 "Identity" 155
$lblCompName = New-Lbl $cCompId "-" (New-Object System.Drawing.Font("Segoe UI",15,[System.Drawing.FontStyle]::Bold)) $C.TextPrimary 14 28
$lblCompName.Size=New-Object System.Drawing.Size(360,30)
$lblCompDns  = New-Lbl $cCompId "-" $F.MonoSm $C.Accent 14 62
$lblCompDesc = New-Lbl $cCompId "-" $F.Small $C.TextMuted 14 84
$lblCompLoc  = New-Lbl $cCompId "-" $F.Small $C.TextMuted 14 104
$lblCompStat = New-Lbl $cCompId "" $F.Heading $C.TextMuted 14 128

$cCompDet = New-Card $splitComputer.Panel1 "Computer Details" 302
$vCompOU      = New-DR $cCompDet "OU Path"            28
$vCompIP      = New-DR $cCompDet "IP Address"         50
$vCompOS      = New-DR $cCompDet "Operating System"   72
$vCompOSVer   = New-DR $cCompDet "OS Version"         94
$vCompLogon   = New-DR $cCompDet "Last Logon"         116
$vCompPwdSet  = New-DR $cCompDet "Pwd Last Set"       138
$vCompCreated = New-DR $cCompDet "Created"            160
$vCompChanged = New-DR $cCompDet "Modified"           182
$vCompManaged = New-DR $cCompDet "Managed By"         204
$vCompDN      = New-DR $cCompDet "DN"                 226
foreach ($compValue in @($vCompOU,$vCompIP,$vCompOS,$vCompOSVer,$vCompLogon,$vCompPwdSet,$vCompCreated,$vCompChanged,$vCompManaged)) {
    $compValue.Size = New-Object System.Drawing.Size(360,16)
}
$vCompDN.Size = New-Object System.Drawing.Size(360,48)

$cCompGrp = New-Card $splitComputer.Panel2 "Computer Groups" 395
$lstComputerGroups = New-Object System.Windows.Forms.ListBox
$lstComputerGroups.Location=New-Object System.Drawing.Point(12,27)
$lstComputerGroups.Size=New-Object System.Drawing.Size(360,358)
$lstComputerGroups.BackColor=$C.InputBg; $lstComputerGroups.ForeColor=$C.TextPrimary
$lstComputerGroups.BorderStyle="None"; $lstComputerGroups.Font=$F.MonoSm
$lstComputerGroups.Anchor="Top,Left,Right,Bottom"
$cCompGrp.Controls.Add($lstComputerGroups)
$cCompGrp.Add_Resize({ Update-ComputerGroupsListHeight })
$splitComputer.Add_SplitterMoved({ Update-ComputerGroupsListHeight })

$cCompNotes = New-Card $splitComputer.Panel2 "AD Notes" 178
$txtComputerNotes = New-Memo $cCompNotes 12 30 360 96
$txtComputerNotes.Anchor="Top,Left,Right"
$btnComputerSaveNotes = New-Btn $cCompNotes "Save Notes" $F.Heading $C.Bg $C.TextPrimary 12 136 130 30 $false
$btnComputerSaveNotes.FlatAppearance.BorderColor=$C.Border; $btnComputerSaveNotes.FlatAppearance.BorderSize=1
$lblComputerNotesHint = New-Lbl $cCompNotes "Updates the 'Notes last updated by' line." $F.Small $C.TextMuted 154 143
$cCompNotes.Add_Resize({ Update-ComputerNotesLayout })
$splitComputer.Add_SplitterMoved({ Update-ComputerNotesLayout })

$cCompAct = New-Card $splitComputer.Panel2 "Actions" 84
$btnComputerRefresh = New-Btn $cCompAct "Refresh"      $F.Heading $C.Bg $C.TextPrimary 14 30 110 34 $false
$btnComputerRefresh.FlatAppearance.BorderColor=$C.Border; $btnComputerRefresh.FlatAppearance.BorderSize=1
$btnComputerCopy    = New-Btn $cCompAct "Copy Summary" $F.Heading $C.Bg $C.TextPrimary 138 30 150 34 $false
$btnComputerCopy.FlatAppearance.BorderColor=$C.Border; $btnComputerCopy.FlatAppearance.BorderSize=1

$pnlComputerTab.Controls.Add($pnlComputerSearch)

# -- COMPUTER TAB LOGIC --------------------------------------------------------
$script:CurComputer=$null; $script:CurComputerGroups=@(); $script:CurComputerIP=''

function Clear-CDisplay {
    $lblCompName.Text="-"; $lblCompDns.Text="-"; $lblCompDesc.Text="-"; $lblCompLoc.Text="-"; $lblCompStat.Text=""
    $vCompOU.Text="-"; $vCompIP.Text="-"; $vCompOS.Text="-"; $vCompOSVer.Text="-"; $vCompLogon.Text="-"
    $vCompPwdSet.Text="-"; $vCompCreated.Text="-"; $vCompChanged.Text="-"; $vCompManaged.Text="-"; $vCompDN.Text="-"
    $txtComputerNotes.Text=""; $txtComputerNotes.Enabled=$false
    $lstComputerGroups.Items.Clear()
    $btnComputerRefresh.Enabled=$false; $btnComputerCopy.Enabled=$false; $btnComputerSaveNotes.Enabled=$false
    $script:CurComputer=$null; $script:CurComputerGroups=@(); $script:CurComputerIP=''
}

function Show-CData {
    param($Computer, $Groups, [string]$IPAddress = '')
    $lblCompName.Text = $Computer.Name
    $lblCompDns.Text  = if($Computer.DNSHostName){$Computer.DNSHostName}else{"No DNS hostname on object"}
    $lblCompDesc.Text = if($Computer.Description){$Computer.Description}else{"No description on file"}
    $lblCompLoc.Text  = if($Computer.Location){"Location: $($Computer.Location)"}else{"No location on file"}
    if($Computer.Enabled){ $lblCompStat.Text="* ENABLED"; $lblCompStat.ForeColor=$C.Success }
    else                { $lblCompStat.Text="* DISABLED"; $lblCompStat.ForeColor=$C.Danger  }

    $vCompOU.Text      = Get-OUPathFromDN $Computer.DistinguishedName
    $vCompIP.Text      = if($IPAddress){$IPAddress}else{"Not found in DNS/AD"}
    $vCompIP.ForeColor = if($IPAddress){$C.TextPrimary}else{$C.Warning}
    $vCompOS.Text      = if($Computer.OperatingSystem){$Computer.OperatingSystem}else{"-"}
    $vCompOSVer.Text   = if($Computer.OperatingSystemVersion){$Computer.OperatingSystemVersion}else{"-"}
    $vCompLogon.Text   = Format-DateOrNever $Computer.LastLogonDate
    $vCompPwdSet.Text  = Format-DateOrNever $Computer.PasswordLastSet
    $vCompCreated.Text = Format-DateOrNever $Computer.Created
    $vCompChanged.Text = Format-DateOrNever $Computer.Modified
    $vCompManaged.Text = if($Computer.ManagedBy){Get-NameFromDN $Computer.ManagedBy}else{"-"}
    $vCompDN.Text      = $Computer.DistinguishedName
    $txtComputerNotes.Text = if($Computer.info){[string]$Computer.info}else{""}
    $txtComputerNotes.Enabled = $true

    $lstComputerGroups.Items.Clear()
    if($Groups.Count -gt 0){ foreach($g in $Groups){ $lstComputerGroups.Items.Add($g)|Out-Null } }
    else { $lstComputerGroups.Items.Add("(no computer group memberships)")|Out-Null }
    $btnComputerRefresh.Enabled = $true
    $btnComputerCopy.Enabled = $true
    $btnComputerSaveNotes.Enabled = $true
    Set-Status "Loaded computer: $($Computer.Name)  |  $($Groups.Count) group(s)" 'success'
}

function Get-ComputerSummaryText {
    if(-not $script:CurComputer){ return '' }
    $c = $script:CurComputer
    return @(
        "Computer: $($c.Name)"
        "DNS: $($c.DNSHostName)"
        "IP: $script:CurComputerIP"
        "Enabled: $($c.Enabled)"
        "OU: $(Get-OUPathFromDN $c.DistinguishedName)"
        "OS: $($c.OperatingSystem)"
        "Last Logon: $(Format-DateOrNever $c.LastLogonDate)"
        "Password Last Set: $(Format-DateOrNever $c.PasswordLastSet)"
        "Managed By: $(if($c.ManagedBy){Get-NameFromDN $c.ManagedBy}else{'-'})"
        "Notes: $($txtComputerNotes.Text)"
    ) -join "`r`n"
}

function Invoke-CSearch {
    $name=$txtComputerSearch.Text.Trim(); if([string]::IsNullOrWhiteSpace($name)){return}
    Clear-CDisplay; Set-Status "Looking up computer '$name'..." "info"
    $btnComputerSearch.Enabled=$false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-TerminalLog "----- Computer lookup: $name -----" 'info'
    try {
        $r = Get-ComputerAccount -ComputerName $name
    } finally {
        $btnComputerSearch.Enabled = $true
    }
    $sw.Stop()
    if (-not $r.Success) {
        Set-Status $r.Error "error"
        Write-TerminalLog "Computer lookup failed for '$name'" 'err'
        return
    }
    $script:CurComputer = $r.Computer
    $script:CurComputerGroups = $r.Groups
    $script:CurComputerIP = $r.IPAddress
    Show-CData -Computer $r.Computer -Groups $r.Groups -IPAddress $r.IPAddress
    Write-TerminalLog ("Computer lookup complete: $($r.Groups.Count) group(s), total {0:N0} ms" -f $sw.ElapsedMilliseconds) 'ok'
}

$btnComputerSearch.Add_Click({ Invoke-CSearch })
$txtComputerSearch.Add_KeyDown({ if($_.KeyCode -eq "Return"){ Invoke-CSearch } })
$btnComputerRefresh.Add_Click({ if($script:CurComputer){ $txtComputerSearch.Text=$script:CurComputer.Name; Invoke-CSearch } })
$btnComputerSaveNotes.Add_Click({
    if(-not $script:CurComputer){return}
    $name=$script:CurComputer.Name
    $notes=New-StampedAdNotes -Notes $txtComputerNotes.Text
    $btnComputerSaveNotes.Enabled=$false
    Set-Status "Updating AD notes for $name..." "info"
    $r=Update-ComputerNotes -ComputerName $name -Notes $notes
    if($r.Success){
        $txtComputerNotes.Text = $notes
        try { $script:CurComputer.info = $notes } catch { }
        Set-Status "AD notes updated for $name." "success"
        $btnComputerSaveNotes.Enabled=$true
    } else {
        Set-Status $r.Error "error"
        $btnComputerSaveNotes.Enabled=$true
    }
})
$btnComputerCopy.Add_Click({
    $summary = Get-ComputerSummaryText
    if($summary){ [System.Windows.Forms.Clipboard]::SetText($summary); Set-Status "Computer summary copied to clipboard." "info" }
})

# ==============================================================================
# TAB 3 - LOCKOUT DIAGNOSTICS
# ==============================================================================

$rtbLog = New-Object System.Windows.Forms.RichTextBox
$rtbLog.Dock="Fill"; $rtbLog.BackColor=$C.InputBg; $rtbLog.ForeColor=$C.LogNormal
$rtbLog.BorderStyle="None"; $rtbLog.Font=$F.MonoLog; $rtbLog.ReadOnly=$true
$rtbLog.WordWrap=$false; $rtbLog.ScrollBars="Both"

New-Lbl $pnlLkCtrl "Username" $F.Heading $C.TextPrimary 12 18 | Out-Null
$txtLockoutUser = New-Txt $pnlLkCtrl 98 15 200 $F.Mono
New-Lbl $pnlLkCtrl "Hours back" $F.Heading $C.TextPrimary 570 19 | Out-Null

$numHours = New-Object System.Windows.Forms.NumericUpDown
$numHours.Size=New-Object System.Drawing.Size(62,24); $numHours.Location=New-Object System.Drawing.Point(660,15)
$numHours.Minimum=1; $numHours.Maximum=168; $numHours.Value=24
$numHours.BackColor=$C.InputBg; $numHours.ForeColor=$C.TextPrimary; $numHours.Font=$F.Mono
Set-ControlDarkStyle $numHours $C.InputBg
$pnlLkCtrl.Controls.Add($numHours)

$btnRunDiag = New-Btn $pnlLkCtrl "Run Diagnostics" $F.Heading $C.Accent ([System.Drawing.Color]::White) 736 14 162 28

$btnExport = New-Btn $pnlLkAct "Export CSV" $F.Small $C.Bg $C.TextPrimary 12 4 120 26 $false
$btnExport.FlatAppearance.BorderColor=$C.Border; $btnExport.FlatAppearance.BorderSize=1
$btnClrLog = New-Btn $pnlLkAct "Clear"         $F.Small $C.Bg $C.TextPrimary  140 4  70 26
$btnClrLog.FlatAppearance.BorderColor=$C.Border; $btnClrLog.FlatAppearance.BorderSize=1

function Write-Log {
    param([string]$Text,[string]$Type="normal")
    $col=switch($Type){
        "heading"{$C.LogAccent}"warn"{$C.LogWarn}"error"{$C.LogError}
        "success"{$C.LogSuccess}"muted"{$C.LogMuted}"label"{$C.TextMuted}default{$C.LogNormal}}
    $rtbLog.SelectionStart=$rtbLog.TextLength; $rtbLog.SelectionLength=0
    $rtbLog.SelectionColor=$col; $rtbLog.AppendText($Text+"`n"); $rtbLog.ScrollToCaret()
}

$script:DiagResults = New-Object System.Collections.Generic.List[object]

$btnRunDiag.Add_Click({
    $rtbLog.Clear(); $script:DiagResults.Clear(); $btnExport.Enabled=$false
    $sam=[string]$txtLockoutUser.Text.Trim()
    $nameCheck = Test-SamAccountName -Username $sam
    if (-not $nameCheck.Valid) {
        Set-Status $nameCheck.Error "error"
        Write-Log $nameCheck.Error "error"
        return
    }
    $ad = Test-ADConnectivity
    if (-not $ad.Ready) {
        Set-Status $ad.Error "error"
        Write-Log $ad.Error "error"
        return
    }
    $hrs=[int]$numHours.Value
    $btnRunDiag.Enabled=$false
    Set-Status "Running lockout diagnostics for $sam..." "info"
    Write-TerminalLog "----- Lockout diagnostics: $sam ($hrs hours) -----" 'info'

    [System.Windows.Forms.Application]::DoEvents()
    try {
        $d = Invoke-LockoutDiagnostics -SamAccountName $sam -HoursBack $hrs
        if ($d -and $d.O) {
            foreach ($logLine in $d.O) { Write-Log $logLine.Text $logLine.Type }
        }
        if ($d -and $d.R) {
            foreach ($r in $d.R) { $script:DiagResults.Add($r) }
        }
        if ($script:DiagResults.Count -gt 0) { $btnExport.Enabled = $true }
        Set-Status "Diagnostics complete - $($script:DiagResults.Count) event(s) collected." "success"
        Write-TerminalLog "Diagnostics complete - $($script:DiagResults.Count) event(s) collected." 'ok'
    } catch {
        $msg = $_.Exception.Message
        Set-Status "Diagnostics failed: $msg" "error"
        Write-Log $msg "error"
        Write-TerminalLog "Diagnostics failed: $msg" 'err'
    } finally {
        $btnRunDiag.Enabled = $true
    }
})

$btnClrLog.Add_Click({ $rtbLog.Clear(); $script:DiagResults.Clear(); $btnExport.Enabled=$false; Set-Status "Log cleared." "info" })

$btnExport.Add_Click({
    $sd=New-Object System.Windows.Forms.SaveFileDialog
    $sd.Filter="CSV files (*.csv)|*.csv"; $sd.FileName="LockoutReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $sd.Title="Export Lockout Report"
    if($sd.ShowDialog() -eq "OK"){
        $script:DiagResults|Sort-Object User,EventTime|Export-Csv -Path $sd.FileName -NoTypeInformation
        Set-Status "Exported to $($sd.FileName)" "success"
    }
})

# Fill first, then Top toolbars (same pattern as User tab)
$pnlLockoutTab.Controls.Add($rtbLog)
$pnlLockoutTab.Controls.Add($pnlLkAct)
$pnlLockoutTab.Controls.Add($pnlLkCtrl)

$form.Add_Shown({
    try {
        Write-Host ''
        Write-TerminalLog "ADTools v$SCRIPT_VERSION - run from this console to see AD commands and timings" 'info'
        $form.PerformLayout()
        if ($splitUser.Width -gt 100) {
            $splitUser.SplitterDistance=[int]($splitUser.Width*0.46)
        }
        if ($splitComputer.Width -gt 100) {
            $splitComputer.SplitterDistance=[int]($splitComputer.Width*0.46)
        }
        Update-GroupsListHeight
        Update-UserNotesLayout
        Update-ComputerGroupsListHeight
        Update-ComputerNotesLayout
        $txtUserSearch.Focus()
        $ad = Ensure-ADModule
        if (-not $ad.Ready) {
            Set-Status $ad.Error "warning"
            return
        }
        $conn = Test-ADConnectivity -Quiet
        if (-not $conn.Ready) { Set-Status $conn.Error "warning" }
    } catch {
        Set-Status "Startup check failed: $($_.Exception.Message)" "error"
    }
})

$script:StartupOk = $true

} catch {
    Show-StartupFailure 'ADTools could not start.' $_.Exception.ToString()
    exit 1
}

if (-not $script:StartupOk) { exit 1 }

# -- RUN -----------------------------------------------------------------------
try {
    [void][System.Windows.Forms.Application]::Run($form)
} catch {
    Show-StartupFailure 'ADTools closed unexpectedly.' $_.Exception.ToString()
    exit 1
}
