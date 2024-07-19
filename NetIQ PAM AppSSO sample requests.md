# NetIQ PAM AppSSO sample requests

Requesting AppSSO credentials for `Chrome.exe` with for URL `https://idmae.efocused.solutions:8543/nps/servlet/portal`.

## request

```json
{
  "params": {
    "pkt": {
      "metadata": {
        "svcid": "p21p07gaYWOpEhL9II8V6/ZfRFE=",
        "Passwd": {
          "username": "appssosvc"
        },
        "Session": {
          "id": 8
        },
        "ReqSSO": {
          "argument": "https://idmae.efocused.solutions:8543/nps/servlet/portal",
          "exe": "Chrome.exe"
        },
        "Localtime": {
          "seconds": "1721387634"
        }
      },
      "module": "cmdctrl",
      "method": "ssoAuth"
    }
  },
  "method": "callModule"
}
```

## response

```json
{
    "vrm": "4.4.0",
    "status": 0,
    "message": null,
    "svc": "pam.universe.org",
    "Identity": "eJzj8ExJzSvJLKlkyOd0LC3JCMnPTs1jKGbJS8xN5UwsKCguzi8uSy7mKAGJx2emMBTzQZhliaU5JSCBTN7igrT4RKDe+JLKgtTUYs7cxIKU\/NzEzDyO0rzMstSi4tRMjsy8xOQSIKePo5gpJU8tOc8WbrhOfqltQWKuTkqyLUw9iJ1flO7JVlJckphb0Lbl5ZSiYu6i1Nz8ktT4jPziEoZiTqBVRWC2AFCzHkynHlBbPktocWoRpieItxirH9D8mc\/l6BwSH+AYHBzuwlDMWpaYU5pqHOzhaGRqpqxdmONYnOPirh\/hb2IRUFQY5pYf6GNk5u+c7FSV5unjHe6S5efllRWal1Juy5DPExDuEu\/jGBwS7+zhzuAJMapty9WubKAcyBIXz2BHJx9XoDVsoFDMz2MuTi1JgqhjYMjnBqlxDnJ1DEFTgmoUN8ga14gAzyBXuINZ0xJzilMZ8oVBRoCdEBzq7Bzv4+\/u74dwyZN7ugz5HCAlvo4BwQz5UJsTmYGhBLQwLxEUs8QGLTNQWjwnJbGg2EpfPyUZJeYYgCCfOcDZhaGKKblE4etXFYP9Sx16M6sMGM\/evff0ZaTNLbu7ol4P5t1M+tD4Sa+KKbNMYCOve\/z2oBnmr2Yuyz94Z8udYu7kzIIMYNoAxRJ3YmqxLjBGdJOTkvOZUrOB5mamiOy9cvb7W07vRXd\/zt+81EHen+sk9+4qoGwTQ2ji2uDXNfJTTuhvvTzlpmFd39xdnRcu\/Lizjanbxtyq1F917UIdoUsVTE921vFmyMftvuJs7yUR6TPFRl1kv7F98u95hvvD1XbmLpqxYNs3179C5hkX7I8JWeo0pR2qONnntshkRcDVZfluHr07JSonPHl1IN7C+OBs9oMX9z2pqV7iwX9jSbJDwd726eryIe13uMWFRG8ui1sboXDGtk+g8O67+b9Oy1aIqOrFPpqyacoJ7VdX1Oo7\/fYfSf5ac9sldqbYxH0tsuzurw\/Z6vGUSrisO3Dyq+NM0dXHLXgLmrfPlK9grl127mP7kiSF3WILpPmVVnBd35ZbaDBHwIVdmet45QcOY0G\/p0FCDAyJLEH5OakMxcy5+SmcBUVlyUUpZTklxSxFQFHO5KLUFMeU3Mw8YDRxBmemA2O+tCiVoYq5ODO9iWHbxNd7LDRd3rTtz7r07+MDyTl3ru\/Y8PLv\/ydfNtafT\/\/VxPbeTzzCVH5ZXiF3yJJffHxXpToNpc77iF77uWPRnsxD3mufP\/6TdvdfxiETQ45ZF36seX+LMezBdPGG2J8ZojybvhaxMcg7veN8q8y4u+PirWNnf+VdTBB7vC3Uwys\/lqHgA9fpxUc2qLxvcYo0E2befuqogGL55\/KGytyDf\/iMHkfMSw4+J7TrxxReX95HQfe\/\/REXU+Nff2D1tHfqjldWvV4RfyDiuKzH5V\/1z0J0YxMOfLp1eM221Cfvsyz5d137vC5w7bbfpldfuJsuej1fy3QuXwDfFJbOE7EdBfWiPZ55E5VFN3vs\/WE9I5MzI7EYUjo4gNPZdu+5elNOTqi9uDnTOGDNjxk+we9XMjAAAB41QKQ=",
    "metadata": {
        "SSOCredential": {
            "id": "c06d2eb0-2424-11ef-b806-45079e3d0adc",
            "vault": "b4a4491a-2424-11ef-b806-45079e3d0adc",
            "account": "admin.sa.system",
            "type": "passwd",
            "cipher_type": "AES-256-CBC",
            "domainId": 0,
            "passwordManaged": 0,
            "serviceAccount": "no",
            "is_reconcileAccount": 0,
            "CFG": {},
            "ACL": {
                "Role": {}
            },
            "Vault": {
                "id": "b4a4491a-2424-11ef-b806-45079e3d0adc",
                "name": "AppSSo-Chrome-iManager",
                "path": 0,
                "type": "SSO",
                "profile": 10002,
                "CFG": {
                    "RemoteApp": 0,
                    "AgentLess": {
                        "KeyboardLayout": "de-de-qwertz",
                        "TerminalType": ""
                    },
                    "Connect": {
                        "region": "",
                        "ScriptArgs": {
                            "SSO": {
                                "appType": 1,
                                "filePath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                "host": "",
                                "policyhost": false,
                                "remoteapplicationcmdline": "",
                                "remoteapplicationprogram": "",
                                "publishapplication": "no",
                                "commandLineAllow": 2,
                                "remoteApp": 0,
                                "dispName": "",
                                "reqCmdLine": "https:\/\/idmae.efocused.solutions:8543\/nps\/servlet\/portal"
                            }
                        }
                    },
                    "Connector": {
                        "port": 11521,
                        "dbport": 1521,
                        "ssl": 0,
                        "sslversion": -2,
                        "networkPktSize": 4097,
                        "useOldCiphers": true,
                        "all_dbaudit_modules": "1"
                    },
                    "RDP": {
                        "host": "",
                        "port": 3389
                    }
                },
                "ACL": {
                    "Role": {}
                }
            },
            "PCD": {
                "ct": "tETEc2aC3I9RTfIECDFsTjpfSfiFTW1CW2u7rKtRYaTEBJrlf+dLTYJFFGuG2hnpcLXejl1SQpQ2uvcOJAsNrKEQvAR+5CNp38irsg81tjc=",
                "iv": "GXU9qzEjyhfPNtz1FPgNkw==",
                "cipher_type": "AES-256-CBC",
                "ek": {
                    "id": "vdTN9+0JS6Ld+Z+zpUAfTwrJC7s=",
                    "ek": "F5PL6pv7k86gRedVf\/5Zood+THHwQQ3duu84j4r8gGPzlgOoXU0WLCtfwKxy6rD3\/fgL3cG4Rly0wMAeMnT5m8N4Ukr9v1jmC1LMD\/hDi0S2gU5Jsks3t9CqMPHzLW2MgtNctdX+1ApAq9S4Y2R1mr\/XDqmBo0qLaPyOwrbmOZKLizQIzp6RGLOniF+pL2u10ohAmY+Sg8PHS7JifIo+p8Oy9sOEuV1gGDyRJDmgQFZoHM6KTG+Gy0pMuk3kppLbY1CQcxNv47m2CvXq5RHZYW8ufOGooWLdPS5ALTYPQjhyp07IgfZjr2hdR7MJKI+arj1Z+rLUdVTyqj1V7zpDZg=="
                }
            },
            "serviceAccountDetails": {},
            "decryptedPCD": {
                "xxxsensitivexxx": true,
                "PCD": {
                    "passwd": "secret",
                    "cipher_type": "AES-256-CBC",
                    "xxxsensitivexxx": true
                }
            }
        }
    }
}
```
