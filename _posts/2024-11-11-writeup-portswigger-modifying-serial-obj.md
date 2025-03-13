---
title: "Modifying Serialized Objects"
description: "Editing a serialized object in session cookie in order to gain administrative privileges"
date: 2024-11-11 00:00:00 +0100
categories: [Portswigger Labs, Deserialization]
tags: [writeup, portswigger]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/portswigger/insecure_deserial/modifying_serial_obj/tn.png
---

### Lab Info
___

| **Lab name** | Modifying Serialized Objects |
| **Level** | Apprentice |
| **Link** | https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects |

This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

### Solving the lab
___

To solve the lab, let's first login as wiener with the provided credentials.

![](/assets/img/portswigger/insecure_deserial/modifying_serial_obj/login.png)

Once logged in, we notice that we get a base64 encoded cookie:

![](/assets/img/portswigger/insecure_deserial/modifying_serial_obj/cookie.png)

After decoding it, we get the following PHP serialized object:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

This is an object of the class `User` containing 2 attributes: `username` (string) and `admin` (boolean). In this case the `admin` attribute is set to `False` (`0`).

Let's try to set it to `True`, re-encode the object and update the value of our cookie:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

![](/assets/img/portswigger/insecure_deserial/modifying_serial_obj/new-cookie.png)


If we refresh the page, we can see that we now have access to the admin panel where we can delete the user `carlos` and solve the lab:

![](/assets/img/portswigger/insecure_deserial/modifying_serial_obj/delete_carlos.png)

![](/assets/img/portswigger/insecure_deserial/modifying_serial_obj/congrats.png)



