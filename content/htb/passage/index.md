+++
title = "HTB - Passage"
date = "2025-04-27T00:00:00+00:00"
tags = ["ctf", "htb", "web", "cutenews", "cms", "rce", "hashcat", "password reuse", "vim", "vim history", "dbus"]
description = "Writeup for the 'Medium' rated machine: Passage"
+++

{{<lead>}}
Passage is a medium difficulty Linux machine that hosts a CuteNews web application. This is found to suffer from a remote command execution vulnerability, which is leveraged to gain a foothold. A CuteNews password hash for the application user `paul` is discovered and cracked. Owing to password reuse, we can use this to move laterally to the `paul` system user. A private SSH key is found to be shared between the system users, which allows us to move laterally to `nadav`. This user is found to be a member of the sudo group. Enumeration of the vim command line history reveals that the `com.ubuntu.USBCreator.conf` policy has been edited, in order to allow users of the `sudo` group to invoke methods of the `usb-creator` service. The D-Bus service USBCreator is found to suffer from a vulnerability, allowing the password security policy imposed by `sudo` binary to be bypassed. This is leveraged in order to read privileged files as root.
{{</lead>}}

## Port Scanning

From the results of the nmap scan, we see that we have 2 ports open: 22 and 80

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Passage News
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

## Website

### Recon

Navigating to `http://10.10.10.226`, we get this page:

{{<figure src="/img/htb/passage/homepage.png" position=center caption="Home Page">}}

At the bottom of the passage we can see that it is running ["CuteNews"](https://cutephp.com/)

{{<figure src="/img/htb/passage/pwd_by.png" position=center caption="Powered by CuteNews">}}

Hovering over some of the author names, we can see that they point to some email addresses revealing potential usernames and the domain name of the box:

{{<figure src="/img/htb/passage/nadav_mail.png" position=center caption="Nadav's email">}}

{{<figure src="/img/htb/passage/paul_mail.png" position=center caption="Paul's email">}}

Let's note the usernames somewhere and add `passage.htb` to our hosts file.

After examining the page source carefully, we find the `/CuteNews` endpoint containing a login page which also discloses the version of CuteNews which is `2.1.2`:

{{<figure src="/img/htb/passage/cn_version.png" position=center caption="Login page disclosing CuteNews version">}}

### Exploitation

Googling 'CuteNews 2.1.2 exploit', we find this [POC](https://www.exploit-db.com/exploits/48800) for [CVE-2019-11447](https://nvd.nist.gov/vuln/detail/CVE-2019-11447):

{{<figure src="/img/htb/passage/rce_poc.png" position=center caption="Running CuteNews RCE exploit POC">}}

After running it, we get a shell as `www-data`:

{{<figure src="/img/htb/passage/www-data-shell.png" position=center caption="Shell as www-data">}}

## Privesc

### www-data -> paul

In `/var/www/html/CuteNews/cdata/users`, we can find different php files, which we can assume correspond to the data of the each user of the site.

{{<figure src="/img/htb/passage/users_b64.png" position=center caption="Users data files">}}
![](/assets/img/htb/passage/users_b64.png)

The file `lines` contains all of the user data in base64 format. Using the following command, we can filter the base64 data and decode it:

```bash
for line in `cat lines | grep -v "access denied"`; do printf "\n";echo $line | base64 -d; printf "\n"; done
```

We get the password hashes of some users:

{{<figure src="/img/htb/passage/pass_hash_users.png" position=center caption="Password hashes">}}

```text
nadav:7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
sid-meier:4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
paul-coles:e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
kim-swift:f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
egre55:4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
```

We can try to crack them with hashcat:

```bash
hashcat -m 1400 hashes /usr/share/wordlists/rockyou.txt --username
```

Only `paul`'s hash was cracked:

{{<figure src="/img/htb/passage/nadav_hash.png" position=center caption="Paul's password cracked!">}}

Using this password we can switch to `paul` and retrieve the user flag:

{{<figure src="/img/htb/passage/user.txt.png" position=center caption="User flag obtained!">}}

> We could not log in via ssh with a password
>
> {{<figure src="/img/htb/passage/paul_ssh_login.png" position=center caption="Cannot login with password">}}

### paul -> nadav

Trying to get `paul`'s ssh key in order to login via ssh, we notice that his key pair is tied to `nadav`:

{{<figure src="/img/htb/passage/paul_ssh_key.png" position=center caption="Paul's ssh key shared with nadav">}}

Using the corresponding private key, we were able to login as nadav:

{{<figure src="/img/htb/passage/nadav_shell.png" position=center caption="Shell as nadav">}}

### nadav -> root

In the `.viminfo` file, we can see that `nadav` edited `/etc/dbus-1/system.d/com.ubuntu.USBCreator.conf`

{{<figure src="/img/htb/passage/nadav_viminfo.png" position=center caption="Nadav's .viminfo history">}}

And in the command line history, we can see that they edited the `AdminIdentities` from the root group to the sudo group.

{{<figure src="/img/htb/passage/viminfo_cmdline_history.png" position=center caption="Nadav's vim command history">}}

After some research about the USBCreator D-Bus interface, we find [this article](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) describing a vulnerability allowing an attacker with access to  the sudoer group to bypass the password security policy imposed by the sudo program, essentially getting root privileges.

The `com.ubuntu.USBCreator` service is found to contain an implementation of the `dd` command, allowing us to copy files between locations. This allows a user to overwrite arbitrary files on the filesystem, as root, with no password prompting.

For example we can copy the private ssh key of the root user as follows:

```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/id_rsa true
```

{{<figure src="/img/htb/passage/root_idrsa.png" position=center caption="Root's private ssh key">}}

With this key, we can log in as root and retrieve the root flag.

{{<figure src="/img/htb/passage/root.txt.png" position=center caption="Root flag obtained !">}}
![](/assets/img/htb/passage/root.txt.png)
