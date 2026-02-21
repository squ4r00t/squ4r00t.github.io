+++
title = "Portswigger - Cache Poisoning with multiple headers"
date = "2026-02-21T00:00:00+00:00"
tags = ["portswigger", "cache_poisoning"]
description = "In this lab, we exploit a cache poisoning vulnerability by leveraging multiple unkeyed inputs"
series = ["Web Cache Poisoning"]
series_order = 3
+++

## Lab Description

This lab contains a web cache poisoning vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser. 

> [!TIP]- Hint
> This lab supports both the `X-Forwarded-Host` and `X-Forwarded-Scheme` headers. 

Access [here](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers)

## Solve

Using [param miner]() to guess headers, we find that `X-Forwarded-Scheme` is an unkeyed headers:

{{<figure src="/img/portswigger/cp_multiple_headers/x-forwarded-scheme-unkeyed.png" position=center caption="X-Forwarded-Scheme header found by Param Miner">}}

If we send a request to the homepage containing the `X-Forwarded-Scheme: http`, we get a 302 redirect:

{{<figure src="/img/portswigger/cp_multiple_headers/x-forwarded-scheme-redirect.png" position=center caption="X-Forwarded-Scheme redirection">}}

Let's see if we can alter the location of the redirect using the `X-Forwarded-Host` header:

{{<figure src="/img/portswigger/cp_multiple_headers/altering-redirect-location.png" position=center caption="Redirect location altered with X-Forwarded-Host header">}}

As we can see, we can redirect to any domain we want. All we have to do now is to host a script that executes `alert(document.cookie)` on the exploit server at the path `/exploit/resources/js/tracking.js` and change the redirect domain to the exploit server's. This way, whenever a user tries to import the `tracking.js` script they will instead load our malicious script:

{{<figure src="/img/portswigger/cp_multiple_headers/configuring-exploit-server.png" position=center caption="Configuring exploit server">}}

{{<figure src="/img/portswigger/cp_multiple_headers/poisoning-the-cache.png" position=center caption="Poisoning the cache">}}

The lab is solved after a few seconds:

{{<figure src="/img/portswigger/cp_multiple_headers/lab-solved.png" position=center caption="Lab solved!">}}

