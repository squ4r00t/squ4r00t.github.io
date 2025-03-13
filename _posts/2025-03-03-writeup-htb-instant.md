---
title: "Instant"
description: "Writeup for the 'Medium' rated machine: Instant"
date: 2025-03-03 00:00:00 +0100
categories: [CTFs, HackTheBox]
tags: [writeup, hackthebox]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/htb/instant/tn.png
---

### Overview
___
Instant is a medium difficulty machine covering Reverse Engineering of an android apk, API hacking and decryption of encrypted PuTTY session data.

It starts off by downloading the apk of a banking/finance app. After some static analysis, we find some endpoints in the source code. One of these endpoints contains the documentation of the API that the app communicates with. Reading that documentation allows us to spot vulnerability in one of the endpoints allowing us to read local files on the server. By leveraging that vulnerability, we are able to read the private key of a user on the box.

After login in as that user, we find a certain file containing encrypted data of a PuTTY session which we are able to decrypt using a python script allowing us to get a root shell.

### Nmap
___

```bash
rustscan -a 10.10.11.37 -- -A -T4 -oN nmap

<SNIP>

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMM6fK04LJ4jNNL950Ft7YHPO9NKONYVCbau/+tQKoy3u7J9d8xw2sJaajQGLqTvyWMolbN3fKzp7t/s/ZMiZNo=
|   256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL+zjgyGvnf4lMAlvdgVHlwHd+/U4NcThn1bx5/4DZYY
80/tcp open  http    syn-ack Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From the scan results, we see that we have 2 ports open:
- 22 running ssh
- 80 running an Apache server redirecting to `http://instant.htb`

Let's add it to our host file

```bash
echo -e "<IP>\tinstant.htb" >> /etc/hosts
```

### instant.htb
___
Now let's navigate to `http://instant.htb`

![](/assets/img/htb/instant/website.png)

This seems to be a website for a mobile application. Clicking on 'Download Now', we can download the apk.

![](/assets/img/htb/instant/download_apk.png)


### APK Reversing
___
We can use [jadx](https://github.com/skylot/jadx) to decompile the apk and get access to the source code. 

After opening the apk in jadx, we can use the search feature to look for endpoints that the application communicates with. We can try to search for `.instant.htb` for example:

![](/assets/img/htb/instant/api_endpoints.png)

We can see in the results different API endpoints in the `mywalletv1` subdomain. Let's add it to our hosts file and take look at the api.

In the second and third search results, we can see a token being set to the `Authorization` header:

![](/assets/img/htb/instant/auth_header.png)

If we try to access an endpoint without the token, we get a 401:

```bash
curl http://mywalletv1.instant.htb/api/v1/view/profile

{"Description":"Unauthorized!","Status":401}
```

After adding the token:

```bash
curl http://mywalletv1.instant.htb/api/v1/view/profile -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"Profile":{"account_status":"active","email":"admin@instant.htb","invite_token":"instant_admin_inv","role":"Admin","username":"instantAdmin","wallet_balance":"10000000","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},"Status":200}
```

This confirms the validity of the token. Now let's see if there is a documentation for this api. Documentation pages are usually found in endpoints like:
- `/api`
- `/swagger/index.html`
- `/openapi.json`

Unfortunately, we don't get any results with these. Let's do another search with jadx, but this time adding more elements to our search such as classes, comments, etc:

![](/assets/img/htb/instant/jadx_extended_search.png)

Now we have another vhost: `swagger-ui.instant.htb`.


### Swagger UI
___
Navigating to this website, we get the access to the documentation of the api:

![](/assets/img/htb/instant/swagger-page.png)

Let's add our token by clicking on 'Authorize':

![](/assets/img/htb/instant/adding_token.png)

Looking at the different endpoints, we can see one that stands out: `/api/v1/admin/read/log`

![](/assets/img/htb/instant/read_logs.png)

![](/assets/img/htb/instant/possible_lfi.png)

This could potentially lead to an LFI, allowing us to read local files on the server. Let's first try to send a valid request to see what the response looks like:

![](/assets/img/htb/instant/1log.png)


### Foothold - User
___
Not only did we get the file, but also its full path. We could try to get access to the user's private key by leveraging a path traversal as follows:

```
../.ssh/id_rsa
```

![](/assets/img/htb/instant/idrsa.png)

We got the private key. However, we'll need to clean it up for it to be usable. We can do that with the following command:

```bash
cat key | sed 's/^    "//' | sed 's/\\n".*$//' | tee id_rsa
```

I copied the private key inside `key` and used `sed` to remove anything unnecessary and write the output to `id_rsa`. After that we can just change the permissions of the file (`chmod 600 id_rsa`) and log in:

![](/assets/img/htb/instant/user.png)

### Root
___
Inside `/opt/backups/Solar-PuTTY`, there is a file called `sessions-backup.dat`. After a little bit of research, we see that we can use [this script](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5) to decrypt the session file:

![](/assets/img/htb/instant/rootpass.png)

With this password, we can switch to root

![](/assets/img/htb/instant/root.png)