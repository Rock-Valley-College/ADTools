#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    RVC ADTools — Active Directory Helpdesk Toolkit
.DESCRIPTION
    A tabbed helpdesk tool for Active Directory management.

    Tab 1 — User:               Look up any AD account, view full details,
                                 group memberships, reset password, unlock.
    Tab 2 — Lockout Diagnostics: Find what's causing account lockouts by
                                 querying all DCs and pulling Security event
                                 log entries (4740 lockout, 4625 bad logon).

    Access control is enforced by AD delegation — this script can only affect
    accounts your AD account has been granted rights over.

    REQUIREMENTS:
    - Run on a domain-joined machine
    - ActiveDirectory PowerShell module (RSAT) must be installed
    - PowerShell 5.1 or later
    - Security event log access on DCs required for Lockout Diagnostics
      (Domain Admin or delegated Event Log Reader on DCs)

.NOTES
    Version:  2.0.0
    GitHub:   https://github.com/Rock-Valley-College/ADTools

    irm https://raw.githubusercontent.com/Rock-Valley-College/ADTools/main/ADTools.ps1 | iex
#>

# ── VERSION ───────────────────────────────────────────────────────────────────
$SCRIPT_VERSION = "2.0.0"

# ── REMOTE CONFIG ─────────────────────────────────────────────────────────────
$CONFIG_URL = "https://raw.githubusercontent.com/Rock-Valley-College/ADTools/main/config.json"

$CONFIG = @{
    MinPasswordLength  = 16
    TempPasswordLength = 16
    UpdateCheckURL     = "https://raw.githubusercontent.com/Rock-Valley-College/ADTools/main/ADTools.ps1"
}

try {
    $remoteConfig = Invoke-RestMethod -Uri $CONFIG_URL -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
    foreach ($key in $remoteConfig.PSObject.Properties.Name) { $CONFIG[$key] = $remoteConfig.$key }
} catch { }

# ── BOOTSTRAP ─────────────────────────────────────────────────────────────────
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    [System.Windows.Forms.MessageBox]::Show(
        "The ActiveDirectory PowerShell module is not installed.`n`nRun this in an elevated PowerShell window:`n`nAdd-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0",
        "Missing: RSAT ActiveDirectory Module",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# ── HELPERS ───────────────────────────────────────────────────────────────────
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
    $result = @{ Success=$false; User=$null; Groups=@(); Error="" }
    if ([string]::IsNullOrWhiteSpace($Username)) { $result.Error="Please enter a username."; return $result }
    if ($Username -notmatch '^[a-zA-Z0-9._-]+$') { $result.Error="Invalid username characters."; return $result }
    try {
        $user = Get-ADUser -Identity $Username -Properties `
            DisplayName,EmailAddress,Department,Title,DistinguishedName,Enabled,LockedOut,
            CannotChangePassword,PasswordNeverExpires,PasswordLastSet,PasswordExpired,
            LastLogonDate,Created,MemberOf -ErrorAction Stop
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $result.Error="No account found for '$Username'."; return $result
    } catch { $result.Error="AD lookup failed: $($_.Exception.Message)"; return $result }
    $groups = @()
    foreach ($dn in $user.MemberOf) { try { $groups += (Get-ADGroup -Identity $dn -EA Stop).Name } catch {} }
    $result.Success=$true; $result.User=$user; $result.Groups=($groups|Sort-Object)
    return $result
}

function Invoke-PasswordReset {
    param([string]$Username,[string]$NewPassword)
    $result = @{ Success=$false; Error="" }
    if ($NewPassword.Length -lt $CONFIG.MinPasswordLength) { $result.Error="Password must be at least $($CONFIG.MinPasswordLength) characters."; return $result }
    try {
        Set-ADAccountPassword -Identity $Username -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force) -Reset -EA Stop
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $true -EA Stop
        $result.Success=$true
    } catch [System.UnauthorizedAccessException] { $result.Error="Access denied — no permission to reset this password."
    } catch { $result.Error="Reset failed: $($_.Exception.Message)" }
    return $result
}

function Invoke-AccountUnlock {
    param([string]$Username)
    $result = @{ Success=$false; Error="" }
    try { Unlock-ADAccount -Identity $Username -EA Stop; $result.Success=$true
    } catch [System.UnauthorizedAccessException] { $result.Error="Access denied — no permission to unlock this account."
    } catch { $result.Error="Unlock failed: $($_.Exception.Message)" }
    return $result
}

function Format-DateOrNever {
    param($Value)
    if ($null -eq $Value) { return "Never" }
    try { return ([datetime]$Value).ToString("MM/dd/yyyy  h:mm tt") } catch { return "—" }
}

function Get-OUFromDN {
    param([string]$DN)
    $ou = ($DN -split ',' | Where-Object { $_ -match '^OU=' } | Select-Object -First 1)
    if ($ou) { return $ou -replace '^OU=','' }
    return $DN
}

# ── THEME ─────────────────────────────────────────────────────────────────────
$C = @{
    Bg          = [System.Drawing.Color]::FromArgb(15,  20,  30)
    Panel       = [System.Drawing.Color]::FromArgb(22,  30,  45)
    Card        = [System.Drawing.Color]::FromArgb(28,  38,  58)
    Border      = [System.Drawing.Color]::FromArgb(45,  60,  90)
    Accent      = [System.Drawing.Color]::FromArgb(30, 130, 255)
    Success     = [System.Drawing.Color]::FromArgb(34, 197, 100)
    Warning     = [System.Drawing.Color]::FromArgb(250, 170,  30)
    Danger      = [System.Drawing.Color]::FromArgb(240,  60,  60)
    TextPrimary = [System.Drawing.Color]::FromArgb(220, 230, 245)
    TextMuted   = [System.Drawing.Color]::FromArgb(110, 130, 160)
    TextDim     = [System.Drawing.Color]::FromArgb(60,  80, 110)
    InputBg     = [System.Drawing.Color]::FromArgb(18,  25,  40)
    LogNormal   = [System.Drawing.Color]::FromArgb(180, 200, 230)
    LogWarn     = [System.Drawing.Color]::FromArgb(250, 200,  60)
    LogError    = [System.Drawing.Color]::FromArgb(240,  80,  80)
    LogSuccess  = [System.Drawing.Color]::FromArgb(60,  210, 120)
    LogMuted    = [System.Drawing.Color]::FromArgb(80,  100, 130)
    LogAccent   = [System.Drawing.Color]::FromArgb(80,  160, 255)
}
$F = @{
    Title   = New-Object System.Drawing.Font("Segoe UI",13,[System.Drawing.FontStyle]::Bold)
    Heading = New-Object System.Drawing.Font("Segoe UI",9, [System.Drawing.FontStyle]::Bold)
    Normal  = New-Object System.Drawing.Font("Segoe UI",9)
    Small   = New-Object System.Drawing.Font("Segoe UI",8)
    Micro   = New-Object System.Drawing.Font("Segoe UI",7.5)
    Mono    = New-Object System.Drawing.Font("Consolas",10,[System.Drawing.FontStyle]::Bold)
    MonoSm  = New-Object System.Drawing.Font("Consolas",9)
    MonoLog = New-Object System.Drawing.Font("Consolas",8.5)
}

# ── FORM ──────────────────────────────────────────────────────────────────────
$form = New-Object System.Windows.Forms.Form
$form.Text            = "RVC ADTools"
$form.Size            = New-Object System.Drawing.Size(920, 740)
$form.MinimumSize     = New-Object System.Drawing.Size(860, 660)
$form.StartPosition   = "CenterScreen"
$form.BackColor       = $C.Bg
$form.ForeColor       = $C.TextPrimary
$form.FormBorderStyle = "Sizable"
$form.Font            = $F.Normal

# Header
$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Dock=      "Top"; $pnlHeader.Height=50; $pnlHeader.BackColor=$C.Panel
$form.Controls.Add($pnlHeader)

$lblAppTitle = New-Object System.Windows.Forms.Label
$lblAppTitle.Text="  🛡  RVC ADTools"; $lblAppTitle.Font=$F.Title
$lblAppTitle.ForeColor=$C.TextPrimary; $lblAppTitle.AutoSize=$true
$lblAppTitle.Location=New-Object System.Drawing.Point(8,12)
$pnlHeader.Controls.Add($lblAppTitle)

$lblVerBadge = New-Object System.Windows.Forms.Label
$lblVerBadge.Text="v$SCRIPT_VERSION"; $lblVerBadge.Font=$F.Micro
$lblVerBadge.ForeColor=$C.TextDim; $lblVerBadge.AutoSize=$true
$lblVerBadge.Anchor="Top,Right"; $lblVerBadge.Location=New-Object System.Drawing.Point(830,36)
$pnlHeader.Controls.Add($lblVerBadge)

# Status bar
$pnlStatus = New-Object System.Windows.Forms.Panel
$pnlStatus.Dock="Bottom"; $pnlStatus.Height=26; $pnlStatus.BackColor=$C.Panel
$form.Controls.Add($pnlStatus)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text="Ready."; $lblStatus.Font=$F.Small
$lblStatus.ForeColor=$C.TextMuted; $lblStatus.AutoSize=$true
$lblStatus.Location=New-Object System.Drawing.Point(14,6)
$pnlStatus.Controls.Add($lblStatus)

function Set-Status {
    param([string]$Msg,[string]$Type="info")
    $lblStatus.ForeColor=switch($Type){"success"{$C.Success}"error"{$C.Danger}"warning"{$C.Warning}default{$C.TextMuted}}
    $lblStatus.Text=$Msg
}

# ── TABS ──────────────────────────────────────────────────────────────────────
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock="Fill"; $tabs.Font=$F.Heading
$tabs.DrawMode="OwnerDrawFixed"
$tabs.ItemSize=New-Object System.Drawing.Size(180,32)
$tabs.SizeMode="Fixed"
$form.Controls.Add($tabs)

$tabs.Add_DrawItem({
    param($s,$e)
    $tab=$s.TabPages[$e.Index]; $sel=($e.Index -eq $s.SelectedIndex)
    $bg=if($sel){$C.Card}else{$C.Panel}; $fg=if($sel){$C.TextPrimary}else{$C.TextMuted}
    $e.Graphics.FillRectangle((New-Object System.Drawing.SolidBrush($bg)),$e.Bounds)
    if($sel){$e.Graphics.FillRectangle((New-Object System.Drawing.SolidBrush($C.Accent)),
        (New-Object System.Drawing.Rectangle($e.Bounds.X,$e.Bounds.Y,$e.Bounds.Width,3)))}
    $sf=New-Object System.Drawing.StringFormat
    $sf.Alignment=[System.Drawing.StringAlignment]::Center
    $sf.LineAlignment=[System.Drawing.StringAlignment]::Center
    $e.Graphics.DrawString($tab.Text,$F.Heading,(New-Object System.Drawing.SolidBrush($fg)),[System.Drawing.RectangleF]$e.Bounds,$sf)
})

$tabUser    = New-Object System.Windows.Forms.TabPage; $tabUser.Text="👤  User"
$tabUser.BackColor=$C.Bg; $tabUser.ForeColor=$C.TextPrimary
$tabs.TabPages.Add($tabUser)

$tabLockout = New-Object System.Windows.Forms.TabPage; $tabLockout.Text="🔒  Lockout Diagnostics"
$tabLockout.BackColor=$C.Bg; $tabLockout.ForeColor=$C.TextPrimary
$tabs.TabPages.Add($tabLockout)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — USER
# ══════════════════════════════════════════════════════════════════════════════

$pnlUserSearch = New-Object System.Windows.Forms.Panel
$pnlUserSearch.Dock="Top"; $pnlUserSearch.Height=50; $pnlUserSearch.BackColor=$C.Bg
$tabUser.Controls.Add($pnlUserSearch)

function New-Lbl { param($parent,$text,$font,$color,$x,$y,$autosize=$true)
    $l=New-Object System.Windows.Forms.Label; $l.Text=$text; $l.Font=$font
    $l.ForeColor=$color; $l.AutoSize=$autosize; $l.Location=New-Object System.Drawing.Point($x,$y)
    $parent.Controls.Add($l); return $l }
function New-Btn { param($parent,$text,$font,$bg,$fg,$x,$y,$w,$h,[bool]$enabled=$true)
    $b=New-Object System.Windows.Forms.Button; $b.Text=$text; $b.Font=$font
    $b.BackColor=$bg; $b.ForeColor=$fg; $b.Size=New-Object System.Drawing.Size($w,$h)
    $b.Location=New-Object System.Drawing.Point($x,$y); $b.FlatStyle="Flat"
    $b.FlatAppearance.BorderSize=0; $b.Cursor="Hand"; $b.Enabled=$enabled
    $parent.Controls.Add($b); return $b }
function New-Txt { param($parent,$x,$y,$w,$font)
    $t=New-Object System.Windows.Forms.TextBox; $t.Size=New-Object System.Drawing.Size($w,26)
    $t.Location=New-Object System.Drawing.Point($x,$y); $t.BackColor=$C.InputBg
    $t.ForeColor=$C.TextPrimary; $t.BorderStyle="FixedSingle"; $t.Font=$font
    $parent.Controls.Add($t); return $t }

New-Lbl $pnlUserSearch "Username" $F.Heading $C.TextMuted 12 17 | Out-Null
$txtUserSearch = New-Txt $pnlUserSearch 98 13 240 $F.Mono
$btnUserSearch = New-Btn $pnlUserSearch "Look Up" $F.Heading $C.Accent ([System.Drawing.Color]::White) 350 13 86 26
$lblUserStatus = New-Lbl $pnlUserSearch "Enter a username to get started." $F.Small $C.TextMuted 452 17

$pnlUserContent = New-Object System.Windows.Forms.Panel
$pnlUserContent.Dock="Fill"; $pnlUserContent.BackColor=$C.Bg
$pnlUserContent.Padding=New-Object System.Windows.Forms.Padding(12,4,12,4)
$tabUser.Controls.Add($pnlUserContent)

$pnlUL = New-Object System.Windows.Forms.Panel; $pnlUL.BackColor=$C.Bg
$pnlUR = New-Object System.Windows.Forms.Panel; $pnlUR.BackColor=$C.Bg
$pnlUserContent.Controls.Add($pnlUL); $pnlUserContent.Controls.Add($pnlUR)

$pnlUserContent.Add_Resize({
    $w=$pnlUserContent.ClientSize.Width-8; $h=$pnlUserContent.ClientSize.Height-4
    $l=[int]($w*0.46); $r=$w-$l-12
    $pnlUL.Size=New-Object System.Drawing.Size($l,$h)
    $pnlUR.Location=New-Object System.Drawing.Point($l+12,0)
    $pnlUR.Size=New-Object System.Drawing.Size($r,$h)
})
# Trigger initial layout
$pnlUL.Size=New-Object System.Drawing.Size(390,600); $pnlUL.Location=New-Object System.Drawing.Point(0,0)
$pnlUR.Size=New-Object System.Drawing.Size(440,600); $pnlUR.Location=New-Object System.Drawing.Point(406,0)

function New-Card {
    param([System.Windows.Forms.Panel]$Parent,[string]$Title,[int]$Y,[int]$Height)
    $card=New-Object System.Windows.Forms.Panel
    $card.Size=New-Object System.Drawing.Size(($Parent.Width-2),$Height)
    $card.Location=New-Object System.Drawing.Point(0,$Y)
    $card.BackColor=$C.Card; $card.Anchor="Top,Left,Right"
    $Parent.Controls.Add($card)
    if($Title){ New-Lbl $card $Title.ToUpper() $F.Micro $C.TextDim 14 10 | Out-Null }
    return $card
}

# Identity
$cId = New-Card $pnlUL "Identity" 0 155
$lblDN   = New-Lbl $cId "—" (New-Object System.Drawing.Font("Segoe UI",15,[System.Drawing.FontStyle]::Bold)) $C.TextPrimary 14 28
$lblDN.Size=New-Object System.Drawing.Size(360,30)
$lblUN2  = New-Lbl $cId "—" $F.MonoSm $C.Accent 14 62
$lblMail = New-Lbl $cId "—" $F.Small $C.TextMuted 14 82
$lblDept = New-Lbl $cId "—" $F.Small $C.TextMuted 14 100
$lblStat = New-Lbl $cId "" $F.Heading $C.TextDim 14 124
$lblLock = New-Lbl $cId "" $F.Heading $C.Danger 120 124

# Details
$cDet = New-Card $pnlUL "Account Details" 163 215
function New-DR { param($card,$lbl,$y)
    New-Lbl $card $lbl $F.Small $C.TextDim 14 $y | Out-Null
    $v=New-Lbl $card "—" $F.Small $C.TextPrimary 158 $y; $v.Size=New-Object System.Drawing.Size(220,16); return $v }
$vCreated = New-DR $cDet "Created"            28
$vLogon   = New-DR $cDet "Last Logon"         50
$vPwdSet  = New-DR $cDet "Password Last Set"  72
$vPwdExp  = New-DR $cDet "Password Expires"   94
$vNvrExp  = New-DR $cDet "Pwd Never Expires"  116
$vCantChg = New-DR $cDet "Cannot Change Pwd"  138
$vOU      = New-DR $cDet "OU"                 160

# Password reset
$cPwd = New-Card $pnlUL "Password Reset" 386 150
New-Lbl $cPwd "Temporary Password" $F.Heading $C.TextMuted 14 28 | Out-Null
$txtPwd    = New-Txt   $cPwd 14 48 212 $F.Mono
$btnGenPwd = New-Btn   $cPwd "↺ New" $F.Small $C.Card $C.Accent 234 48 56 24 $false
$btnGenPwd.FlatAppearance.BorderColor=$C.Border; $btnGenPwd.FlatAppearance.BorderSize=1
$btnCpyPwd = New-Btn   $cPwd "Copy" $F.Small $C.Card $C.TextMuted 298 48 52 24 $false
$btnCpyPwd.FlatAppearance.BorderColor=$C.Border; $btnCpyPwd.FlatAppearance.BorderSize=1
$chkShow   = New-Object System.Windows.Forms.CheckBox; $chkShow.Text="Show password"
$chkShow.Font=$F.Small; $chkShow.ForeColor=$C.TextMuted; $chkShow.AutoSize=$true
$chkShow.Checked=$true; $chkShow.Location=New-Object System.Drawing.Point(14,80)
$chkShow.FlatStyle="Flat"; $cPwd.Controls.Add($chkShow)
$btnRstPwd = New-Btn   $cPwd "Reset Password" $F.Heading $C.Accent ([System.Drawing.Color]::White) 14 106 344 32 $false

# Right — Groups
$cGrp = New-Card $pnlUR "Group Memberships" 0 395
$lstGroups = New-Object System.Windows.Forms.ListBox
$lstGroups.Dock="None"; $lstGroups.Size=New-Object System.Drawing.Size(410,358)
$lstGroups.Location=New-Object System.Drawing.Point(12,27)
$lstGroups.BackColor=$C.InputBg; $lstGroups.ForeColor=$C.TextPrimary
$lstGroups.BorderStyle="None"; $lstGroups.Font=$F.MonoSm; $lstGroups.Anchor="Top,Left,Right,Bottom"
$cGrp.Controls.Add($lstGroups)

# Right — Actions
$cAct = New-Card $pnlUR "Actions" 403 84
$btnUnlock  = New-Btn $cAct "🔓 Unlock Account"    $F.Heading $C.Card $C.Warning  14  30 180 34 $false
$btnUnlock.FlatAppearance.BorderColor=$C.Warning; $btnUnlock.FlatAppearance.BorderSize=1
$btnRefresh = New-Btn $cAct "↻ Refresh"             $F.Heading $C.Card $C.TextMuted 206 30 110 34 $false
$btnRefresh.FlatAppearance.BorderColor=$C.Border; $btnRefresh.FlatAppearance.BorderSize=1
$btnDiag    = New-Btn $cAct "🔍 Diagnose Lockout"   $F.Heading $C.Card $C.Danger   330 30 180 34 $false
$btnDiag.FlatAppearance.BorderColor=$C.Danger; $btnDiag.FlatAppearance.BorderSize=1
$btnDiag.Visible=$false

# ── USER TAB LOGIC ────────────────────────────────────────────────────────────
$script:CurUser=$null; $script:CurGroups=@()

function Clear-UDisplay {
    $lblDN.Text="—"; $lblUN2.Text="—"; $lblMail.Text="—"; $lblDept.Text="—"
    $lblStat.Text=""; $lblLock.Text=""
    $vCreated.Text="—"; $vLogon.Text="—"; $vPwdSet.Text="—"; $vPwdExp.Text="—"
    $vNvrExp.Text="—"; $vCantChg.Text="—"; $vOU.Text="—"
    $lstGroups.Items.Clear(); $txtPwd.Text=""
    $btnRstPwd.Enabled=$false; $btnGenPwd.Enabled=$false; $btnCpyPwd.Enabled=$false
    $btnUnlock.Enabled=$false; $btnRefresh.Enabled=$false; $btnDiag.Visible=$false
    $script:CurUser=$null; $script:CurGroups=@()
}

function Show-UData { param($User,$Groups)
    $lblDN.Text  = if($User.DisplayName){$User.DisplayName}else{$User.SamAccountName}
    $lblUN2.Text = $User.SamAccountName
    $lblMail.Text= if($User.EmailAddress){$User.EmailAddress}else{"No email on file"}
    $dp=@(); if($User.Title){$dp+=$User.Title}; if($User.Department){$dp+=$User.Department}
    $lblDept.Text= if($dp){$dp -join "  ·  "}else{"No dept/title on file"}
    if($User.Enabled){ $lblStat.Text="● ACTIVE";    $lblStat.ForeColor=$C.Success }
    else             { $lblStat.Text="● DISABLED";  $lblStat.ForeColor=$C.Danger  }
    if($User.LockedOut){
        $lblLock.Text="  🔒 LOCKED OUT"; $btnUnlock.Enabled=$true; $btnDiag.Visible=$true
    } else { $lblLock.Text=""; $btnUnlock.Enabled=$false; $btnDiag.Visible=$false }
    $vCreated.Text= Format-DateOrNever $User.Created
    $vLogon.Text  = Format-DateOrNever $User.LastLogonDate
    $vPwdSet.Text = Format-DateOrNever $User.PasswordLastSet
    if($User.PasswordNeverExpires){ $vPwdExp.Text="Never"; $vPwdExp.ForeColor=$C.TextMuted }
    elseif($User.PasswordExpired) { $vPwdExp.Text="EXPIRED"; $vPwdExp.ForeColor=$C.Danger  }
    else {
        try {
            $pol=Get-ADDefaultDomainPasswordPolicy -EA Stop
            if($User.PasswordLastSet -and $pol.MaxPasswordAge.TotalDays -gt 0){
                $exp=$User.PasswordLastSet+$pol.MaxPasswordAge; $d=($exp-(Get-Date)).Days
                $vPwdExp.Text=$exp.ToString("MM/dd/yyyy")+"  ($d days)"
                $vPwdExp.ForeColor=if($d -le 14){$C.Warning}else{$C.TextPrimary}
            } else { $vPwdExp.Text="—"; $vPwdExp.ForeColor=$C.TextPrimary }
        } catch { $vPwdExp.Text="—"; $vPwdExp.ForeColor=$C.TextPrimary }
    }
    $vNvrExp.Text  = if($User.PasswordNeverExpires){"Yes"}else{"No"}
    $vCantChg.Text = if($User.CannotChangePassword) {"Yes ⚠"}else{"No"}
    $vCantChg.ForeColor=if($User.CannotChangePassword){$C.Warning}else{$C.TextPrimary}
    $vOU.Text = Get-OUFromDN $User.DistinguishedName
    $lstGroups.Items.Clear()
    if($Groups.Count -gt 0){ foreach($g in $Groups){ $lstGroups.Items.Add($g)|Out-Null } }
    else { $lstGroups.Items.Add("(no group memberships)")|Out-Null }
    $can=$(-not $User.CannotChangePassword)
    $btnRstPwd.Enabled=$can; $btnGenPwd.Enabled=$can; $btnCpyPwd.Enabled=$can
    $btnRefresh.Enabled=$true
    if($can){ $txtPwd.Text=New-TempPassword }
    if(-not $can){ Set-Status "⚠ 'User cannot change password' is set — clear this in AD first." "warning" }
}

function Invoke-USearch {
    $u=$txtUserSearch.Text.Trim(); if([string]::IsNullOrWhiteSpace($u)){return}
    Clear-UDisplay; Set-Status "Looking up '$u'..." "info"
    $btnUserSearch.Enabled=$false
    $r=Get-UserAccount -Username $u
    $btnUserSearch.Enabled=$true
    if(-not $r.Success){ Set-Status $r.Error "error"; $lblUserStatus.Text=$r.Error; return }
    $script:CurUser=$r.User; $script:CurGroups=$r.Groups
    Show-UData -User $r.User -Groups $r.Groups
    $lblUserStatus.Text=""; Set-Status "Loaded: $($r.User.DisplayName)  ·  $($r.Groups.Count) group(s)" "success"
}

$btnUserSearch.Add_Click({ Invoke-USearch })
$txtUserSearch.Add_KeyDown({ if($_.KeyCode -eq "Return"){ Invoke-USearch } })
$btnRefresh.Add_Click({ if($script:CurUser){ $txtUserSearch.Text=$script:CurUser.SamAccountName; Invoke-USearch } })
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
        Set-Status "✔ Password reset for $($script:CurUser.DisplayName)." "success"
        [System.Windows.Forms.MessageBox]::Show(
            "Password reset successfully.`n`nUsername:        $u`nTemp Password:  $p`n`nUser will be prompted to change on first sign-in.",
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
        Set-Status "✔ Account unlocked for $($script:CurUser.DisplayName)." "success"
        $lblLock.Text=""; $btnDiag.Visible=$false
    } else { Set-Status $r.Error "error"; $btnUnlock.Enabled=$true }
})

# Diagnose button — prefill lockout tab and switch to it
$btnDiag.Add_Click({
    if($script:CurUser){ $txtLockoutUser.Text=$script:CurUser.SamAccountName; $tabs.SelectedTab=$tabLockout }
})

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — LOCKOUT DIAGNOSTICS
# ══════════════════════════════════════════════════════════════════════════════

$pnlLkCtrl = New-Object System.Windows.Forms.Panel
$pnlLkCtrl.Dock="Top"; $pnlLkCtrl.Height=54; $pnlLkCtrl.BackColor=$C.Bg
$tabLockout.Controls.Add($pnlLkCtrl)

New-Lbl $pnlLkCtrl "Username" $F.Heading $C.TextMuted 12 18 | Out-Null
$txtLockoutUser = New-Txt $pnlLkCtrl 98 15 200 $F.Mono
New-Lbl $pnlLkCtrl "(blank = scan all locked accounts)" $F.Small $C.TextDim 310 19 | Out-Null
New-Lbl $pnlLkCtrl "Hours back" $F.Heading $C.TextMuted 570 19 | Out-Null

$numHours = New-Object System.Windows.Forms.NumericUpDown
$numHours.Size=New-Object System.Drawing.Size(62,24); $numHours.Location=New-Object System.Drawing.Point(660,15)
$numHours.Minimum=1; $numHours.Maximum=168; $numHours.Value=24
$numHours.BackColor=$C.InputBg; $numHours.ForeColor=$C.TextPrimary; $numHours.Font=$F.Mono
$pnlLkCtrl.Controls.Add($numHours)

$btnRunDiag = New-Btn $pnlLkCtrl "▶  Run Diagnostics" $F.Heading $C.Accent ([System.Drawing.Color]::White) 736 14 162 28

$pnlLkAct = New-Object System.Windows.Forms.Panel
$pnlLkAct.Dock="Top"; $pnlLkAct.Height=34; $pnlLkAct.BackColor=$C.Bg
$tabLockout.Controls.Add($pnlLkAct)

$btnExport = New-Btn $pnlLkAct "💾 Export CSV" $F.Small $C.Card $C.TextMuted 12 4 120 26 $false
$btnExport.FlatAppearance.BorderColor=$C.Border; $btnExport.FlatAppearance.BorderSize=1
$btnClrLog = New-Btn $pnlLkAct "Clear"         $F.Small $C.Card $C.TextDim  140 4  70 26
$btnClrLog.FlatAppearance.BorderColor=$C.Border; $btnClrLog.FlatAppearance.BorderSize=1

$rtbLog = New-Object System.Windows.Forms.RichTextBox
$rtbLog.Dock="Fill"; $rtbLog.BackColor=$C.InputBg; $rtbLog.ForeColor=$C.LogNormal
$rtbLog.BorderStyle="None"; $rtbLog.Font=$F.MonoLog; $rtbLog.ReadOnly=$true
$rtbLog.WordWrap=$false; $rtbLog.ScrollBars="Both"
$tabLockout.Controls.Add($rtbLog)

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
    $btnRunDiag.Enabled=$false; Set-Status "Running lockout diagnostics..." "info"
    $sam=[string]$txtLockoutUser.Text.Trim(); $hrs=[int]$numHours.Value

    $job=Start-Job -ScriptBlock {
        param($sam,$hrs)
        Import-Module ActiveDirectory -EA Stop
        $out=New-Object System.Collections.Generic.List[object]
        $res=New-Object System.Collections.Generic.List[object]
        $since=(Get-Date).AddHours(-$hrs)
        function L{param($t,$c="normal"); $out.Add([pscustomobject]@{Text=$t;Type=$c})}

        try{$pdc=(Get-ADDomain).PDCEmulator}catch{L "ERROR: Could not get PDC: $_" "error";return @{O=$out;R=$res}}
        try{$dcs=(Get-ADDomainController -Filter *).HostName}catch{L "ERROR: Could not enumerate DCs: $_" "error";return @{O=$out;R=$res}}

        L "RVC ADTools — Lockout Diagnostics" "heading"
        L "Started:    $(Get-Date -Format 'MM/dd/yyyy h:mm tt')" "muted"
        L "Hours back: $hrs" "muted"
        L "PDC:        $pdc" "label"
        L "DCs ($($dcs.Count)): $($dcs -join ', ')" "label"
        L "" "muted"

        if([string]::IsNullOrWhiteSpace($sam)){
            L "No username — scanning all locked accounts..." "warn"
            try{
                $locked=Search-ADAccount -LockedOut|Select-Object -Expand SamAccountName
                if(-not $locked){L "No locked accounts found right now." "success";return @{O=$out;R=$res}}
                $samList=$locked; L "Found $($locked.Count) locked account(s): $($locked -join ', ')" "warn"
            }catch{L "ERROR: $($_)" "error";return @{O=$out;R=$res}}
        } else { $samList=@($sam) }

        $iso=$since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        foreach($u in $samList){
            L "" "normal"; L ("═"*72) "heading"; L "  USER: $u" "heading"; L ("═"*72) "heading"

            # Per-DC state
            L "" "normal"; L "[ Per-DC State ]" "label"
            $dcState=@()
            foreach($dc in $dcs){
                try{
                    $a=Get-ADUser -Identity $u -Server $dc -Properties LockedOut,badPwdCount,LastBadPasswordAttempt,AccountLockoutTime -EA Stop
                    $dcState+=[pscustomobject]@{DC=$dc;LockedOut=$a.LockedOut;BadPwd=$a.badPwdCount;LastBad=$a.LastBadPasswordAttempt;LockTime=$a.AccountLockoutTime}
                    $ls=if($a.LockedOut){"LOCKED"}else{"OK     "}
                    $lc=if($a.LockedOut){"error"}else{"success"}
                    L ("  {0,-42} {1}   BadPwd:{2,3}   LastBad: {3}" -f $dc,$ls,$a.badPwdCount,$(if($a.LastBadPasswordAttempt){$a.LastBadPasswordAttempt.ToString("MM/dd HH:mm:ss")}else{"never"})) $lc
                }catch{ L "  WARNING: Could not query $dc — $_" "warn" }
            }
            $orig=$dcState|Where-Object{$_.LockTime}|Sort-Object LockTime -Desc|Select-Object -First 1
            L "" "normal"
            if($orig){L "  ► Originating DC: $($orig.DC)  (lockout at $($orig.LockTime))" "warn"}
            else     {L "  ► No LockoutTime on any DC — may not be currently locked." "muted"}

            # 4740
            L "" "normal"; L "[ Event 4740 — Account Locked Out — PDC: $pdc ]" "label"
            $x40="*[System[EventID=4740 and TimeCreated[@SystemTime>='$iso']] and EventData[Data[@Name='TargetUserName']='$u']]"
            try{$e40=Get-WinEvent -ComputerName $pdc -LogName Security -FilterXPath $x40 -EA Stop}
            catch{$e40=@(); if($_.Exception.Message -notmatch 'No events'){L "  WARNING: $($_)" "warn"}}
            if($e40){
                foreach($e in $e40){
                    $caller=$e.Properties[1].Value
                    L ("  {0}   Caller: {1}" -f $e.TimeCreated.ToString("MM/dd/yyyy HH:mm:ss"),$caller) "warn"
                    $res.Add([pscustomobject]@{User=$u;EventTime=$e.TimeCreated;EventId=4740;EventType='AccountLocked';CallerComputer=$caller;CallerIP=$null;LogonProcess=$null;FailureReason=$null;SourceDC=$pdc})
                }
            } else { L "  No 4740 events in last $hrs hour(s)." "muted" }

            # 4625
            $srcs=@($pdc); if($orig -and $orig.DC -ne $pdc){$srcs+=$orig.DC}
            foreach($src in $srcs){
                L "" "normal"; L "[ Event 4625 — Failed Logon — $src ]" "label"
                $x25="*[System[EventID=4625 and TimeCreated[@SystemTime>='$iso']] and EventData[Data[@Name='TargetUserName']='$u']]"
                try{$e25=Get-WinEvent -ComputerName $src -LogName Security -FilterXPath $x25 -EA Stop}
                catch{$e25=@(); if($_.Exception.Message -notmatch 'No events'){L "  WARNING: $($_)" "warn"}}
                if(-not $e25){L "  No 4625 events in last $hrs hour(s)." "muted";continue}
                $grp=$e25|ForEach-Object{[pscustomobject]@{Time=$_.TimeCreated;CC=$_.Properties[13].Value;IP=$_.Properties[19].Value;LP=$_.Properties[10].Value;FR=$_.Properties[8].Value}}
                $grp|Group-Object CC,IP,LP|Sort-Object Count -Desc|ForEach-Object{
                    $f=$_.Group[0]
                    L ("  {0,4} attempts   Computer: {1,-24} IP: {2,-16} Process: {3}" -f $_.Count,$f.CC,$f.IP,$f.LP) "warn"
                }
                foreach($g in $grp){
                    $res.Add([pscustomobject]@{User=$u;EventTime=$g.Time;EventId=4625;EventType='FailedLogon';CallerComputer=$g.CC;CallerIP=$g.IP;LogonProcess=$g.LP;FailureReason=$g.FR;SourceDC=$src})
                }
            }
        }

        L "" "normal"; L ("─"*72) "muted"
        L "Complete — $($res.Count) event(s) collected." "success"
        L "" "normal"; L "Hints:" "label"
        L "  CallerComputer — the machine submitting bad credentials." "muted"
        L "  Advapi process  — likely a service or scheduled task." "muted"
        L "  NtLmSsp/Kerberos — interactive or network logon." "muted"
        L "  Substatus 0xC000006A=wrong pwd  0xC0000064=bad username  0xC0000234=already locked" "muted"
        return @{O=$out;R=$res}
    } -ArgumentList $sam,$hrs

    $pt=New-Object System.Windows.Forms.Timer; $pt.Interval=500
    $pt.Add_Tick({
        if($job.State -in @("Completed","Failed","Stopped")){
            $pt.Stop()
            $d=Receive-Job $job -EA SilentlyContinue
            Remove-Job $job -EA SilentlyContinue
            if($d -and $d.O){ foreach($l in $d.O){ Write-Log $l.Text $l.Type } }
            if($d -and $d.R){ foreach($r in $d.R){ $script:DiagResults.Add($r) } }
            if($script:DiagResults.Count -gt 0){ $btnExport.Enabled=$true }
            $btnRunDiag.Enabled=$true
            Set-Status "Diagnostics complete — $($script:DiagResults.Count) event(s) collected." "success"
        }
    })
    $pt.Start()
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

# ── UPDATE CHECK ──────────────────────────────────────────────────────────────
$form.Add_Shown({
    $txtUserSearch.Focus()
    $uj=Start-Job -ScriptBlock {
        param($url,$ver)
        try{
            $r=Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 6 -EA Stop
            if($r.Content -match 'SCRIPT_VERSION\s*=\s*"(\d+\.\d+\.\d+)"'){
                $l=$Matches[1]; if([version]$l -gt [version]$ver){return $l}
            }
        }catch{}; return $null
    } -ArgumentList $CONFIG.UpdateCheckURL,$SCRIPT_VERSION

    $ut=New-Object System.Windows.Forms.Timer; $ut.Interval=600
    $ut.Add_Tick({
        if($uj.State -in @("Completed","Failed")){
            $ut.Stop(); $l=Receive-Job $uj -EA SilentlyContinue; Remove-Job $uj -EA SilentlyContinue
            if($l){ $lblVerBadge.Text="v$SCRIPT_VERSION — update available: v$l"; $lblVerBadge.ForeColor=$C.Warning }
        }
    })
    $ut.Start()
})

# ── RUN ───────────────────────────────────────────────────────────────────────
[System.Windows.Forms.Application]::Run($form)