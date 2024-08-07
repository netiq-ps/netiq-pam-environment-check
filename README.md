# Get-PAMEnvironment

Retrieves environment details relating to integration with PAM from local Windows system.

Retrieves environment and remote desktop configuration from local system. Includes the OS environment, Network Authentication Level, Security Layer, Secure Boot, NetBIOSName, etc. Also verifies connectivity for AppSSO feature.

## Install

1. Download [Get-PAMEnvironment.ps1](https://github.com/netiq-ps/netiq-pam-environment-check/raw/master/Get-PAMEnvironment.ps1)
2. Source `Get-PAMEnvironment` function into Powershell session: `. .\Get-PAMEnvironment.ps1`

## Run

### Example 1 - RDP

```ps
. .\Get-PAMEnvironment.ps1
Get-PAMEnvironment -RDP 1
```

Output:

```log
-------------------------------
Environment
-------------------------------
Caption                 : Microsoft Windows Server 2012 R2 Standard
OSArchitecture          : 64-bit
ServicePackMajorVersion : 0
Version                 : 6.3.9600
BuildNumber             : 9600
CSName                  : COMPUTERNAME
SecureBoot              : False
NetBIOSName             : DOMAIN (i.e. DOMAIN\User)

-------------------------------
RDP
-------------------------------
PSComputerName                   : COMPUTERNAME
TerminalProtocol                 : Microsoft RDP 8.0
TerminalName                     : RDP-Tcp
UserAuthenticationRequired (NLA) : False
SecurityLayer                    : 1
MinEncryptionLevel               : 2
```

### Example 2 - OS Hotfixes

```ps
. .\Get-PAMEnvironment.ps1
Get-PAMEnvironment -Hotfix 1
```

### Example 3 - AppSSO

```ps
. .\Get-PAMEnvironment.ps1
Get-PAMEnvironment -AppSSO 1
```

### Example 4 - Password Management

```ps
. .\Get-PAMEnvironment.ps1
Get-PAMEnvironment -PasswordManagement 1
```

### Example 5 - Multiple Reports

```ps
. .\Get-PAMEnvironment.ps1
Get-PAMEnvironment -RDP 1 -AppSSO 1
```

### Example 6 - Output report to file

```ps
. .\Get-PAMEnvironment.ps1
Get-PAMEnvironment -RDP 1 *> report.log
```
