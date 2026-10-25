#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RootDC - self-hosted AD training labs (Kerberoasting, AS-REP Roasting,
    Password Spray).

.DESCRIPTION
    Stands up the SAME training domain as the hosted RootDC labs on a single
    Windows Server VM you control. It promotes the machine to a domain
    controller for `fallen.local`, then creates the accounts for the scenario(s)
    you choose. This mirrors the hosted scenarios (KerberoastingScenario,
    ASREPRoastingScenario, PasswordSprayScenario) so the bundled manuals apply
    as-is.

    AUTHORIZED TRAINING USE ONLY. Run this exclusively on an isolated lab VM you
    own, on a host-only / internal network with no route to any production
    network or the internet-facing side of your LAN. The accounts it creates are
    intentionally insecure and exist only so you can study and detect the attacks.

.PARAMETER Stage
    Auto (default): promotes the DC if needed, otherwise configures the scenarios.
    DC: only install AD DS and promote to a new forest (the VM reboots).
    Scenario: only create the accounts (run on an existing DC).

.PARAMETER Scenario
    Which lab(s) to configure: All (default), Kerberoast, ASREP, or PasswordSpray.

.EXAMPLE
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Setup-Lab.ps1                      # all three labs
    .\Setup-Lab.ps1 -Scenario Kerberoast # just one
#>
[CmdletBinding()]
param(
    [ValidateSet('Auto', 'DC', 'Scenario')]
    [string]$Stage = 'Auto',

    [ValidateSet('All', 'Kerberoast', 'ASREP', 'PasswordSpray')]
    [string]$Scenario = 'All',

    [string]$DomainName = 'fallen.local',
    [string]$NetBIOS    = 'FALLEN',

    # DSRM (Directory Services Restore Mode) password. Lab-only; change if you like.
    [string]$SafeModePassword = 'RootDC-DSRM-2026!'
)

$ErrorActionPreference = 'Stop'
function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

$AttackerUser = 'attacker'
$AttackerPass = 'Welcome1!'

# --- Stage detection ---------------------------------------------------------
$domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole  # 4 or 5 = DC
$isDC = $domainRole -ge 4
if ($Stage -eq 'Auto') { $Stage = if ($isDC) { 'Scenario' } else { 'DC' } }

# =============================================================================
# DC promotion
# =============================================================================
function Invoke-DcStage {
    if ($isDC) { Ok "Already a domain controller - skipping promotion."; return }

    Info "Installing the AD DS role..."
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

    # Auto-resume the scenario step after the reboot (runs at next admin logon),
    # preserving the chosen scenario.
    $self = $PSCommandPath
    $runOnce = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    Set-ItemProperty -Path $runOnce -Name 'RootDCLab' `
        -Value "powershell.exe -ExecutionPolicy Bypass -NoExit -File `"$self`" -Stage Scenario -Scenario $Scenario"

    Import-Module ADDSDeployment
    $smp = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force
    Warn "Promoting to a new forest '$DomainName'. The VM will REBOOT when done."
    Info "After reboot, log in as Administrator; the scenario step runs on its own."
    Install-ADDSForest `
        -DomainName $DomainName -DomainNetbiosName $NetBIOS `
        -ForestMode 'WinThreshold' -DomainMode 'WinThreshold' `
        -InstallDns -SafeModeAdministratorPassword $smp `
        -Force -NoRebootOnCompletion:$false
}

# =============================================================================
# Helpers
# =============================================================================
function New-LabOU($name, $domainDN) {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $name -Path $domainDN -ProtectedFromAccidentalDeletion $false | Out-Null
        Ok "Created OU: $name"
    }
    return "OU=$name,$domainDN"
}

function New-StrongPassword {
    param([int]$Length = 20)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#$%^&*-_')
    $all = ($sets -join '').ToCharArray()
    $chars = @(foreach ($s in $sets) { $s[(Get-Random -Maximum $s.Length)] })      # one from each set
    $chars += 1..($Length - $sets.Count) | ForEach-Object { $all[(Get-Random -Maximum $all.Length)] }
    -join ($chars | Sort-Object { Get-Random })
}

function Set-LabUser {
    param(
        [string]$Sam, [string]$Pass, [string]$OuPath, [string]$Desc,
        [string]$Spn, [string[]]$Groups, [switch]$NoPreAuth
    )
    $sec = ConvertTo-SecureString $Pass -AsPlainText -Force
    if (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue) {
        Set-ADAccountPassword -Identity $Sam -Reset -NewPassword $sec
        Warn "User $Sam already existed - password reset to the lab value."
    }
    else {
        New-ADUser -Name $Sam -SamAccountName $Sam -UserPrincipalName "$Sam@$DomainName" `
            -AccountPassword $sec -Enabled $true -PasswordNeverExpires $true `
            -Path $OuPath -Description $Desc
        Ok "Created user: $Sam"
    }
    if ($Spn)       { Set-ADUser -Identity $Sam -ServicePrincipalNames @{ Replace = @($Spn) }; Ok "  SPN set: $Spn" }
    if ($NoPreAuth) { Set-ADAccountControl -Identity $Sam -DoesNotRequirePreAuth $true;        Ok "  Kerberos pre-auth disabled" }
    foreach ($g in $Groups) {
        try { Add-ADGroupMember -Identity $g -Members $Sam -ErrorAction Stop; Ok "  Added to group: $g" }
        catch { Warn "  Could not add $Sam to $g : $($_.Exception.Message)" }
    }
}

function Write-Brief($name, $text) {
    $dir = 'C:\RootDC\scenarios'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $text | Out-File "$dir\$name.txt" -Encoding UTF8
    Ok "Brief written to $dir\$name.txt"
}

# =============================================================================
# Scenarios (account sets identical to the hosted DSC configurations)
# =============================================================================
function Set-KerberoastScenario($usersOU, $svcOU) {
    Info "Kerberoasting: creating service accounts with SPNs..."
    Set-LabUser -Sam 'svc_sql'    -Pass 'Summer2024!'  -OuPath $svcOU -Desc 'Service account' -Spn "MSSQLSvc/sql01.${DomainName}:1433" -Groups @('Server Operators')
    Set-LabUser -Sam 'svc_web'    -Pass 'Password123!' -OuPath $svcOU -Desc 'Service account' -Spn "HTTP/web01.${DomainName}"
    Set-LabUser -Sam 'svc_backup' -Pass 'Passw0rd!'    -OuPath $svcOU -Desc 'Service account' -Spn "CIFS/backup01.${DomainName}"
    Set-LabUser -Sam 'svc_admin'  -Pass 'Admin123!'    -OuPath $svcOU -Desc 'Service account (HIGH VALUE - Domain Admin)' -Spn "HTTP/admin.${DomainName}" -Groups @('Domain Admins')
    Write-Brief 'kerberoasting' @"
Kerberoasting 101 - configured $(Get-Date -Format 'yyyy-MM-dd HH:mm')
Attacker: $AttackerUser / $AttackerPass (Domain Users)
Targets (SPN, weak password):
  svc_sql / Summer2024!   MSSQLSvc/sql01.${DomainName}:1433   [Server Operators]
  svc_web / Password123!  HTTP/web01.${DomainName}
  svc_backup / Passw0rd!  CIFS/backup01.${DomainName}
  svc_admin / Admin123!   HTTP/admin.${DomainName}            [Domain Admins - HIGH VALUE]
Goal: enumerate SPNs, request TGS tickets, crack offline, reach Domain Admin.
See manuals-kerberoasting-beginner.md.
"@
}

function Set-ASREPScenario($usersOU, $svcOU) {
    Info "AS-REP Roasting: creating pre-auth-disabled accounts..."
    Set-LabUser -Sam 'j.smith'    -Pass 'Welcome123!'   -OuPath $usersOU -Desc 'John Smith - IT Support'   -NoPreAuth
    Set-LabUser -Sam 'm.jones'    -Pass 'Password2024!' -OuPath $usersOU -Desc 'Mike Jones - Developer'    -NoPreAuth
    Set-LabUser -Sam 'svc.backup' -Pass 'Backup2024!'   -OuPath $svcOU   -Desc 'Backup Service Account (HIGH VALUE)' -Groups @('Backup Operators') -NoPreAuth
    Write-Brief 'asrep' @"
AS-REP Roasting - configured $(Get-Date -Format 'yyyy-MM-dd HH:mm')
Attacker: $AttackerUser / $AttackerPass (Domain Users)
Targets (DoesNotRequirePreAuth = true, weak password):
  j.smith / Welcome123!
  m.jones / Password2024!
  svc.backup / Backup2024!   [Backup Operators - HIGH VALUE]
Goal: request AS-REP hashes (no auth needed), crack offline (hashcat 18200).
See manuals-asrep-roasting-beginner.md.
"@
}

function Set-PasswordSprayScenario($usersOU) {
    Info "Password Spray: setting lockout policy and creating users..."
    Set-ADDefaultDomainPasswordPolicy -Identity $DomainName `
        -LockoutThreshold 5 `
        -LockoutDuration (New-TimeSpan -Minutes 30) `
        -LockoutObservationWindow (New-TimeSpan -Minutes 30)
    Ok "Lockout policy: 5 attempts, 30-minute lockout/observation window"

    $weak = @(
        @{ Sam = 'john.doe';   Pass = 'Welcome1!';    Desc = 'Standard user'; Groups = @() }
        @{ Sam = 'jane.smith'; Pass = 'Summer2024!';  Desc = 'HR Manager';    Groups = @() }
        @{ Sam = 'bob.wilson'; Pass = 'Password123!'; Desc = 'IT Support';    Groups = @() }
        @{ Sam = 'alice.chen'; Pass = 'Autumn2024!';  Desc = 'Developer';     Groups = @() }
        @{ Sam = 'admin.svc';  Pass = 'Company2024!'; Desc = 'Service Admin (HIGH VALUE - Domain Admin)'; Groups = @('Domain Admins') }
    )
    foreach ($u in $weak) { Set-LabUser -Sam $u.Sam -Pass $u.Pass -OuPath $usersOU -Desc $u.Desc -Groups $u.Groups }

    $decoys = @('sarah.johnson','mike.brown','lisa.davis','david.miller',
                'jennifer.wilson','james.moore','patricia.taylor','robert.anderson')
    Info "Creating $($decoys.Count) decoy users with strong random passwords..."
    foreach ($d in $decoys) { Set-LabUser -Sam $d -Pass (New-StrongPassword) -OuPath $usersOU -Desc 'Standard User' }

    Write-Brief 'password-spray' @"
Password Spray - configured $(Get-Date -Format 'yyyy-MM-dd HH:mm')
Lockout policy: 5 attempts / 30 min (stay under it when spraying).
Weak-password accounts:
  john.doe / Welcome1!      jane.smith / Summer2024!
  bob.wilson / Password123! alice.chen / Autumn2024!
  admin.svc / Company2024!  [Domain Admins - HIGH VALUE]
Plus 8 decoy users with strong random passwords.
Goal: enumerate users, read the lockout policy, spray safely, reach admin.svc.
See manuals-password-spray-beginner.md.
"@
}

# =============================================================================
function Invoke-ScenarioStage {
    Info "Waiting for AD Web Services..."
    Import-Module ActiveDirectory
    for ($i = 0; $i -lt 30; $i++) {
        try { Get-ADDomain | Out-Null; break } catch { Start-Sleep 5 }
    }
    $domainDN = (Get-ADDomain).DistinguishedName
    Info "Domain: $DomainName ($domainDN) - scenario: $Scenario"

    $usersOU = New-LabOU 'RootDC Users' $domainDN
    $svcOU   = New-LabOU 'Service Accounts' $domainDN

    Info "Creating the shared attacker account (Domain Users only)..."
    Set-LabUser -Sam $AttackerUser -Pass $AttackerPass -OuPath $usersOU -Desc 'Attacker starting point'

    if ($Scenario -in @('All', 'Kerberoast'))    { Set-KerberoastScenario    $usersOU $svcOU }
    if ($Scenario -in @('All', 'ASREP'))         { Set-ASREPScenario         $usersOU $svcOU }
    if ($Scenario -in @('All', 'PasswordSpray')) { Set-PasswordSprayScenario $usersOU }

    Ok "All done."
    Warn "This is an intentionally vulnerable lab. Keep this VM isolated."
}

# =============================================================================
switch ($Stage) {
    'DC'       { Invoke-DcStage }
    'Scenario' { Invoke-ScenarioStage }
}
