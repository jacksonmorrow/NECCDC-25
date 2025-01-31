# Ensure the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You need to run this script as an Administrator."
    exit
}

# Update the system
Install-PackageProvider -Name NuGet -Force
Install-Module PSWindowsUpdate -Force
Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -AutoReboot

# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIntrusionPreventionSystem $false

# Configure Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Disable unnecessary services
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled

# Enable Windows Event Logging
wevtutil sl Security /e:true
wevtutil sl System /e:true
wevtutil sl Application /e:true

# Disable Guest account
net user Guest /active:no

# Disable AutoRun
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# Enable User Account Control (UAC)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# Configure Account Lockout Policy
secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose
secedit /configure /db secedit.sdb /cfg C:\Windows\Security\Templates\hisecws.inf /overwrite /areas SECURITYPOLICY

# Configure Password Policy
net accounts /minpwlen:12
net accounts /maxpwage:90
net accounts /minpwage:1
net accounts /uniquepw:5

# Enable Audit Policies
auditpol /set /category:"Account Logon","Account Management","Detailed Tracking","DS Access","Logon/Logoff","Object Access","Policy Change","Privilege Use","System","Global Object Access Auditing" /success:enable /failure:enable

# Disable LLMNR (Link-Local Multicast Name Resolution)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

# Disable NBT-NS (NetBIOS over TCP/IP)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -Name "NetbiosOptions" -Value 2

# Enable LAPS (Local Administrator Password Solution)
Install-WindowsFeature -Name "RSAT-AD-PowerShell"
Import-Module AdmPwd.PS
Update-AdmPwdADSchema
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Domain Controllers,DC=yourdomain,DC=com"

# Configure DNS Security
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "EnableDirectoryPartitions" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name "EnableDnsSec" -Value 1

# Enable SMB Signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1

# Disable WPAD (Web Proxy Auto-Discovery Protocol)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 4

# Enable Controlled Folder Access (Defender Exploit Guard)
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable Network Protection
Set-MpPreference -EnableNetworkProtection Enabled

# Enable Attack Surface Reduction Rules
Add-MpPreference -AttackSurfaceReductionRules_Ids <RuleID> -AttackSurfaceReductionRules_Actions Enabled

# Enable Windows Defender Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1

# Enable Windows Defender Application Guard (if applicable)
Enable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard"

Write-Output "Domain Controller hardening complete."
