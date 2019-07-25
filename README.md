# Get-Environment
Retrieves environment details relating to integration with PAM from local Windows system.

Retrieves environment and remote desktop configuration from local system. Includes the OS environment, Network Authentication Level, Security Layer, Secure Boot, NetBIOSName, etc. Also verifies connectivity for AppSSO feature.

## Install
1. Download `Get-Environment.ps1`
2. Source `Get-Environment` function into Powershell: `. .\Get-Environment.ps1`

## Run
#### Example 1
```
PS > Get-Environment -RDP 1
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

#### Example 2 (with Hotfixes)
```
PS > Get-Environment -Hotfix 1
...
```

#### Example 3 (with AppSSO)
```
PS > Get-Environment -AppSSO 1
...
```

#### Example 4 (with multiple)
```
PS > Get-Environment -RDP 1 -AppSSO 1
...
```

#### Example 5 (output to report)
```
PS > Get-Environment -RDP 1 *> report.log
```