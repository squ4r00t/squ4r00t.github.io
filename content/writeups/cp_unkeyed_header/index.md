+++
title = "Portswigger - Cache Poisoning with an Unkeyed Header"
date = "2026-02-20T00:00:00+00:00"
tags = ["portswigger", "cache_poisoning"]
description = "In this lab, we exploit a cache poisoning vulnerability via the `X-Forwarded-Host` header used to dynamically generate links to import resources"
series = ["Web Cache Poisoning"]
series_order = 1
+++

## Lab Description

This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

> [!TIP]- Hint
> This lab supports the `X-Forwarded-Host` header.

Access [here](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header)
## Finding Unkeyed Inputs

The first step is to find unkeyed headers. For this we can use the [param miner]() extension in Burp Suite. After running the extension to find unkeyed headers on the home page, we see that `X-Forwarded-Host` is an unkeyed header:

{{<figure src="/img/portswigger/cp_unkeyed_header/unkeyed_header.png" position=center caption="X-Forwarded-Host header found by Param Miner">}}

To confirm this, we can send a request containing the `X-Forwarded-Host` header set to an arbitrary value and see where it is reflected in the response:

{{<figure src="/img/portswigger/cp_unkeyed_header/confirm-unkeyed-header.png" position=center caption="Confirming that X-Forwarded-Host is reflected">}}

We can see that its value is used to generate the link of the `tracking.js` script.

## Exploitation

To exploit this, we can host a malicious `tracking.js` script on our exploit server, and poison the cache with the hostname of the exploit server so that the script is fetched from there.

{{<figure src="/img/portswigger/cp_unkeyed_header/hosting-malicious-script.png" position=center caption="Configuring exploit server to host malicious script">}}

{{<figure src="/img/portswigger/cp_unkeyed_header/poisoning-cache-with-exploit-server-hostname.png" position=center caption="Poisoning the cache with the exploit server's hostname">}}

Now if we go back to the homepage, we can see that we solved the lab:

{{<figure src="/img/portswigger/cp_unkeyed_header/lab-solved.png" position=center caption="Lab solved!">}}
