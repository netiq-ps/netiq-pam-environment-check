# Run this script as the privileged appsso user

function Invoke-WithWebRequest {
    # Setup HTTP request
    $parameters = @{
        Method      = "POST"
        Uri         = $url
        Headers     = @{
            'Cache-Control' = "no-cache"
            Authorization   = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($username):$($password)")))"
        }
        ContentType = "application/json"
        Body        = $jsonText
    }

    # Execute request
    $response = Invoke-WebRequest @parameters

    # Print response
    Write-Host "Response status: $($response.StatusCode)"
    Write-Host "Response body: $($response.Content)"

    # Pretty print JSON response
    # Remove -AsHashTable when working with Windows Powershell (5)
    #$response.Content | ConvertFrom-Json -AsHashTable | ConvertTo-Json -Depth 100
}

function Invoke-WithCurl {
    curl.exe -v -u "$($username):$($password)" -H "Content-Type: application/json" -d "$($jsonText)" "$($url)"
}

# Get URL from registry
$url = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Protocom\SecureLogin\RestCredentials).Server

# PAM Application SSO credential
$username = $env:USERNAME

# Prompt for the password if it is not already set
if (-not $password) {
    $password = Read-Host -AsSecureString "Please enter the password for '$($username)'"
    # Convert secure string to plain text
    $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
}

# No double qoutes around paths with spaces!
#$exe = 'C:\Program Files (x86)\WinSCP\WinSCP.exe'
#$argument = ''
#$exe = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$exe = 'Chrome.exe'
#$argument = 'https://mail.rediff.com/cgi-bin/login.cgi'
$argument = 'https://idmae.efocused.solutions:8543/nps/servlet/portal'

Write-Host "Requesting AppSSO credentials for '$($exe)' with argument '$($argument)' from '$($url)' as '$($username)'" # with password '$($password)'"

# Seconds since epoch
$timestamp = get-date -UFormat %s

# Windows session id
$SessionID = (Get-Process -PID $pid).SessionID

$payload = @{
    method = 'callModule'
    params = @{
        pkt = @{
            metadata = @{
                Localtime = @{
                    seconds = $timestamp
                }
                Passwd    = @{
                    username = $username
                }
                ReqSSO    = @{
                    argument = $argument
                    exe      = $exe
                }
                Session   = @{
                    id = $SessionID
                }
                svcid     = $env:PAM_SVCID
            }
            method   = 'ssoAuth'
            module   = 'cmdctrl'
        }
    }
}

# Serialize HashTable to JSON
$jsonText = $payload | ConvertTo-Json -Depth 100
Write-Host "Request body:"
Write-Host "$($jsonText)"
Write-Host ""

Invoke-WithCurl
#Invoke-WithWebRequest
