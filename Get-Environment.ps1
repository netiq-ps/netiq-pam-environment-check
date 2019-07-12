Function Get-Environment {
    <#
    .SYNOPSIS
        Retrieves environment details relating to integration with PAM from local system.

    .DESCRIPTION
        Retrieves environment and remote desktop configuration from local system.
        Includes the OS environment, Network Authentication Level, Security Layer, Secure Boot, NetBIOSName, etc.

    .PARAMETER  Hotfix
    Retrieve the hotfixes that are installed from local system.

    .EXAMPLE
        PS > Get-Environment
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

    #>
    [CmdletBinding()]
    Param(
      [Parameter(
         Mandatory=$false,
         Position=1,
         HelpMessage="Retrieve Hotfix history?"
      )]
      [bool]$Hotfix
    )

    Begin {
        $Lines = "-------------------------------`r`n"
        $Properties = 'PSComputername', 'TerminalProtocol', 'TerminalName',
        @{L='UserAuthenticationRequired (NLA)';E={[bool]$RDP.UserAuthenticationRequired}},
        'SecurityLayer', 'MinEncryptionLevel'
        
        $WMIParams = @{
            Class = 'Win32_TSGeneralSetting'
            Namespace = 'root\CIMV2\TerminalServices'
            Filter = "TerminalName='RDP-Tcp'"
            ErrorAction = 'Stop'
        }

        $SecureBootParams = @{
            ErrorAction = 'Stop'
        }
    }

    Process {
        # General Environment Info
        Try {
            Write-Output "$Lines Environment`r`n$Lines"

            # Is Secure Boot enabled?
            Try {
                $SecureBoot = Confirm-SecureBootUEFI @SecureBootParams
            } Catch [System.PlatformNotSupportedException] {
                 $SecureBoot = $false
            } Catch {
                Write-Error "[SecureBoot] $_"
            }
            
            # Gather more environment info
            $Environment = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, OSArchitecture, ServicePackMajorVersion, Version, BuildNumber, CSName
            $NetBIOSName = (Get-ADDomain -Current LocalComputer).NetBIOSName

            # Consolidate for report
            $Environment | Add-Member -NotePropertyName "SecureBoot" -NotePropertyValue $SecureBoot
            $Environment | Add-Member -NotePropertyName "NetBIOSName" -NotePropertyValue $NetBIOSName

            $Environment
        } Catch {
            Write-Error "[Environment] $_"
        }

        # RDP Configuration
        Try {
            Write-Output "$Lines RDP`r`n$Lines"
            $RDP = Get-WMIObject @WMIParams
            $RDPReport = $RDP | Select-Object $Properties
            $RDPReport
        } Catch {
            Write-Error "[RDP] $_"
        }

        # Hotfixes
        if ($Hotfix) {
            Try {
                Write-Output "$Lines Hotfix`r`n$Lines"
                Get-HotFix | Format-Table
            } Catch {
                Write-Error "[Hotfix] $_"
            }
        }
    }
}