Function Get-PAMEnvironment {
    <#
    .SYNOPSIS
        Retrieves environment details relating to integration with PAM from local system.

    .DESCRIPTION
        Retrieves environment and remote desktop configuration from local system.
        Includes the OS environment, Network Authentication Level, Security Layer, Secure Boot, NetBIOSName, etc.
        Also verifies connectivity for AppSSO feature.
    
    .PARAMETER RDP
        Retrieve RDP Environment.

    .PARAMETER Hotfix
        Retrieve the hotfixes that are installed from local system.

    .PARAMETER AppSSO
        Verify connectivity with configured PAM server.

    .EXAMPLE
        PS > Get-PAMEnvironment -RDP 1
        -------------------------------
        Environment
        -------------------------------
        Caption                 : Microsoft Windows Server 2012 R2 Standard
        ServicePackMajorVersion : 0
        OSArchitecture          : 64-bit
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
         HelpMessage="Retrieve RDP Environment?"
      )]
      [bool]$RDP,

      [Parameter(
         Mandatory=$false,
         HelpMessage="Retrieve Hotfix history?"
      )]
      [bool]$Hotfix,
      
      [Parameter(
        Mandatory=$false,
        HelpMessage="AppSSO verification"
      )]
      [bool]$AppSSO
    )

    Begin {
        $Lines = "-------------------------------`r`n"
        $RDP_ConfigProperties = 'PSComputername', 'TerminalProtocol', 'TerminalName',
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

        $RDP_PORT_PATH = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $PAM_SL_PATH_RestEndpoint = 'HKLM:\SOFTWARE\Protocom\SecureLogin\RestCredentials'

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

        # RDP Environment
        if ($RDP) {
            Try {
                Write-Output "$Lines RDP`r`n$Lines"
                $RDP_Config = Get-WMIObject @WMIParams
                $RDP_Report = $RDP_Config | Select-Object $RDP_ConfigProperties
                $RDP_Port = (Get-ItemProperty -PATH $RDP_PORT_PATH).PortNumber
                $RDP_Listening = Get-NetTCPConnection -State LISTEN -LocalPort $RDP_PORT

                # Consolidate for report
                $RDP_Report | Add-Member -NotePropertyName "PortNumber" -NotePropertyValue $RDP_PORT

                $RDP_Report
                $RDP_Listening | Format-Table

            } Catch {
                Write-Error "[RDP] $_"
            }
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

        # AppSSO
        if ($AppSSO) {
            Write-Output "$Lines AppSSO`r`n$Lines"
            $REST_ENDPOINT = (Get-ItemProperty -PATH $PAM_SL_PATH_RestEndpoint).Server
            $URI = [System.Uri]$REST_ENDPOINT
            Write-Output "REST_ENDPOINT: $REST_ENDPOINT`r`n"

            # Connectivity
            Try {
                Write-Output "Connectivity`r`n$Lines"
                $Connectivity = Test-NetConnection $URI.dnsSafeHost -Port $URI.Port
                $Connectivity | Select-Object SourceAddress, ComputerName, RemoteAddress, RemotePort, NameResolutionSucceeded, PingSucceeded, TcpTestSucceeded
            } Catch {
                Write-Error "[AppSSO_Connectivity] $_"
            }

            # Certificate
            Try {
                Write-Output "Certificate`r`n$Lines"
                Get-CertInfoTcp $URI.dnsSafeHost $URI.Port
            } Catch {
                Write-Error "[AppSSO_Certificate] $_"
            }

        }
    }
}

function Get-CertInfoTcp {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory)]
        [string] $ComputerName,

        [Parameter(Position = 1)]
        [int] $Port = 443,

        [Parameter()]
        [int] $Timeout = 3000,

        [Parameter()]
        [switch] $ReturnCertificate
    )
    try {
        $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
        $iar = $tcpClient.BeginConnect($ComputerName,$Port,$null,$null)
        $wait = $iar.AsyncWaitHandle.WaitOne($Timeout,$false)
        if (!$wait) {
            $tcpClient.Close()
            Write-Warning 'Connection attempt timed out'
        }
        else {
            $null = $tcpClient.EndConnect($iar)

            if ($tcpClient.Connected) {
                $tcpStream = $tcpClient.GetStream()
                $sslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList ($tcpStream, $false)
                $sslStream.AuthenticateAsClient($ComputerName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
                $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList ($sslStream.RemoteCertificate)
                
                Write-Output "TLS connection has been established."
                if ($ReturnCertificate) {
                    Write-Output $certificate
                }
                else {
                    Write-Output ([PSCustomObject] [Ordered] @{
                        IssuerCN = $certificate.Issuer.Split(', ',[System.StringSplitOptions]::RemoveEmptyEntries)[0].Split('=')[1]
                        SubjectCN = $certificate.Subject.Split(', ',[System.StringSplitOptions]::RemoveEmptyEntries)[0].Split('=')[1]
                        ValidFrom = $certificate.NotBefore
                        ValidTo = $certificate.NotAfter
                    })
                }

                $certificate.Dispose()
                $sslStream.Close()
                $sslStream.Dispose()
                $tcpStream.Close()
                $tcpStream.Dispose()
            }
            else {
                Write-Warning "Unable to establish connection to $ComputerName on port $Port"
            }

            $tcpClient.Close()
        }
    }
    catch {
        Write-Warning $_.Exception.InnerException.Message
    }
}