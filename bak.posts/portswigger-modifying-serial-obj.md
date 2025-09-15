+++
title = "Modifying Serialized Objects"
date = "2024-11-11T00:00:00+00:00"
#dateFormat = "2006-01-02" # This value can be configured for per-post date formatting
author = ""
authorTwitter = "" #do not include @
cover = "/img/portswigger/insecure_deserial/modifying_serial_obj/tn.png"
tags = ["deserialization", "portswigger"]
keywords = ["", ""]
description = "In this lab, we'll modified the serialized object in our session token in order to elevate our privileges"
showFullContent = false
readingTime = false
hideComments = false
+++

This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

### Solving the lab
___

To solve the lab, let's first login as `wiener` using the provided credentials.

{{<figure src="/img/portswigger/insecure_deserial/modifying_serial_obj/login.png" position=center caption="Login page">}}

Once logged in, we notice that we get a base64 encoded cookie:

{{<figure src="/img/portswigger/insecure_deserial/modifying_serial_obj/cookie.png" position=center caption="Base64 encode cookie">}}

After decoding it, we get the following PHP serialized object:

```text
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

This is an object of the class `User` containing 2 attributes: 
- `username`: string set to the value "wiener"
- `admin`: boolean set to False (0)

Let's try to set the `admin` attribute to `True`, re-encode the object and update the value of our cookie:

```text
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

{{<figure src="/img/portswigger/insecure_deserial/modifying_serial_obj/new-cookie.png" position=center caption="Updating cookie">}}

If we refresh the page, we can see that we now have access to the admin panel where we can delete the user `carlos` and solve the lab:

{{<figure src="/img/portswigger/insecure_deserial/modifying_serial_obj/delete_carlos.png" position=center caption="Deleting user carlos">}}

{{<figure src="/img/portswigger/insecure_deserial/modifying_serial_obj/congrats.png" position=center caption="Lab solved">}}
