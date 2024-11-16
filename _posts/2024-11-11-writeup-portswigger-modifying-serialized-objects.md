---
title: "Portswigger Lab: Modifying Serialized Objects"
description: "Editing a serialized object in session cookie in order to gain administrative privileges"
author: "squ4r00t"
date: 2024-11-11 00:00:00 +0800
categories: [Web, Deserialization]
tags: [writeup, portswigger]
pin: false
math: true
mermaid: true
image:
  path: http://localhost:4000/assets/img/portswigger.png
---

### Lab Info
___

| **Lab name** | Modifying Serialized Objects |
| **Level** | Apprentice |
| **Link** | [https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects) |

This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

### Solving the lab
___

To solve the lab, let's first login as wiener with the provided credentials.

![](http://localhost:4000/assets/img/2024-11-11-writeup-portswigger-modifying-serialized-objects/login.png)

Once logged in, we notice that we get a base64 encoded cookie:

![](http://localhost:4000/assets/img/2024-11-11-writeup-portswigger-modifying-serialized-objects/cookie.png)

After decoding it, we get the following PHP serialized object:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

This is an object of the class `User` containing 2 attributes: `username` (string) and `admin` (boolean). In this case the `admin` attribute is set to `False` (`0`).

Let's try to set it to `True`, re-encode the object and update the value of our cookie:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

![](http://localhost:4000/assets/img/2024-11-11-writeup-portswigger-modifying-serialized-objects/new-cookie.png)


If we refresh the page, we can see that we now have access to the admin panel where we can delete the user `carlos` and solve the lab:

![](http://localhost:4000/assets/img/2024-11-11-writeup-portswigger-modifying-serialized-objects/delete_carlos.png)

![](http://localhost:4000/assets/img/2024-11-11-writeup-portswigger-modifying-serialized-objects/congrats.png)



