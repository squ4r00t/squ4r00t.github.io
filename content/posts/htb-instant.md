+++
title = "HTB - Instant"
date = "2025-03-18T21:14:52+01:00"
#dateFormat = "2006-01-02" # This value can be configured for per-post date formatting
author = ""
authorTwitter = "squ4r00t" #do not include @
cover = "/img/htb/instant/tn.png"
tags = ["ctf", "htb"]
keywords = ["", ""]
description = "Writeup for the 'Medium' rated machine: Instant"
showFullContent = false
readingTime = true
hideComments = false
+++

Instant is a medium difficulty machine covering Reverse Engineering of an android apk, API hacking and decryption of encrypted PuTTY session data.

It starts off by downloading the apk of a banking/finance app. After some static analysis, we find some endpoints in the source code. One of these endpoints contains the documentation of the API that the app communicates with. Reading that documentation allows us to spot vulnerability in one of the endpoints allowing us to read local files on the server. By leveraging that vulnerability, we are able to read the private key of a user on the box.

After login in as that user, we find a certain file containing encrypted data of a PuTTY session which we are able to decrypt using a python script allowing us to get a root shell.

### Nmap Results
___

```bash
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

### Website
___
Now let's navigate to `http://instant.htb`

{{<figure src="/img/htb/instant/website.png" position=center caption="Home Page">}}

This seems to be a website for a mobile application. Clicking on 'Download Now', we can download the apk.

{{<figure src="/img/htb/instant/download_apk.png" position=center caption="Downloading apk file">}}


### APK Reversing
___
We can use [jadx](https://github.com/skylot/jadx) to decompile the apk and get access to the source code. 

After opening the apk in jadx, we can use the search feature to look for endpoints that the application communicates with. We can try to search for `.instant.htb` for example:

{{<figure src="/img/htb/instant/api_endpoints.png" position=center caption="Searching for API endpoints">}}

We can see in the results different API endpoints in the `mywalletv1` subdomain. Let's add it to our hosts file and take look at the api.

In the second and third search results, we can see a token being set to the `Authorization` header:

{{<figure src="/img/htb/instant/auth_header.png" position=center caption="JWT token">}}

If we try to access an endpoint without the token, we get a 401:

{{<code language="bash" title="Accessing API without the token">}}
curl http://mywalletv1.instant.htb/api/v1/view/profile

{"Description":"Unauthorized!","Status":401}
{{</code>}}

After adding the token:

{{<code language="bash" title="Accessing API with the token">}}
curl http://mywalletv1.instant.htb/api/v1/view/profile -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"Profile":{"account_status":"active","email":"admin@instant.htb","invite_token":"instant_admin_inv","role":"Admin","username":"instantAdmin","wallet_balance":"10000000","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},"Status":200}
{{</code>}}

This confirms the validity of the token. Now let's see if there is a documentation for this api.

Documentation pages are usually found in endpoints like:
- `/api`
- `/swagger/index.html`
- `/openapi.json`

Unfortunately, we don't get any results with these. Let's do another search with jadx, but this time adding more elements to our search such as classes, comments, etc:

{{<figure src="/img/htb/instant/jadx_extended_search.png" position=center caption="Extended search in jadx">}}

Now we find have another vhost: `swagger-ui.instant.htb`.


### Swagger UI
___
Navigating to this website, we get the access to the documentation of the api:

{{<figure src="/img/htb/instant/swagger-page.png" position=center caption="Documentation page">}}

Let's add our token by clicking on 'Authorize':

{{<figure src="/img/htb/instant/adding_token.png" position=center caption="Adding the JWT token">}}

Looking at the different endpoints, we can see one that stands out: `/api/v1/admin/read/log`

{{<figure src="/img/htb/instant/read_logs.png" position=center caption="Endpoint to read log files">}}

{{<figure src="/img/htb/instant/possible_lfi.png" position=center caption="Parameter needed">}}

This could potentially lead to a LFI, allowing us to read local files on the server. Let's first try to send a valid request to see what the response looks like:

{{<figure src="/img/htb/instant/1log.png" position=center caption="Sending a valid request">}}


### Foothold - User
___
Not only did we get the file, but also its full path. We could try to get access to the user's private key by leveraging a path traversal as follows:

```text
../.ssh/id_rsa
```

{{<figure src="/img/htb/instant/idrsa.png" position=center caption="Reading private ssh key">}}

We got the private key. However, we'll need to clean it up for it to be usable. We can do that with the following command:

{{<code language="bash" title="Cleaning up key file">}}
cat key | sed 's/^    "//' | sed 's/\\n".*$//' | tee id_rsa
{{</code>}}

We copied the private key inside `key` and used `sed` to remove anything unnecessary and write the output to `id_rsa`. After that we can just change the permissions of the file (`chmod 600 id_rsa`) and log in:

{{<figure src="/img/htb/instant/user.png" position=center caption="User flag obtained !">}}

### Root
___
Inside `/opt/backups/Solar-PuTTY`, there is a file called `sessions-backup.dat`. After a little bit of research, we see that we can use [this script](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5) to decrypt the session file:

{{<figure src="/img/htb/instant/rootpass.png" position=center caption="Root password">}}

With this password, we can switch to root

{{<figure src="/img/htb/instant/root.png" position=center caption="Root flag obtained !">}}
