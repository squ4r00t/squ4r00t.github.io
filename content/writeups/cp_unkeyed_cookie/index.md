+++
title = "Portswigger - Cache Poisoning with an Unkeyed Cookie"
date = "2026-02-20T00:00:00+00:00"
tags = ["portswigger", "cache_poisoning"]
description = "In this lab, we exploit a cache poisoning vulnerability via the `X-Forwarded-Host` header used to dynamically generate part of the response"
series = ["Web Cache Poisoning"]
series_order = 2
+++

## Lab Description

This lab is vulnerable to web cache poisoning because cookies aren't included in the cache key. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(1)` in the visitor's browser. 

Access [here](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie)

## Solve

Intercepting the request to the homepage, we find a cookie `fehost=prod-cache-01` which is reflected in the response inside a javascript object:

{{<figure src="/img/portswigger/cp_unkeyed_cookie/cookie-reflected.png" position=center caption="`fehost` cookie reflected">}}

To exploit, we can set the cookie value to `prod-cache-01"}%3balert(1)%3b//` allowing us to break out of the string and the javascript object and inject our own code `alert(1)`.


{{<figure src="/img/portswigger/cp_unkeyed_cookie/poisoning-the-cache.png" position=center caption="Poisoning the cache">}}

Going back to the homepage, we see that we solved the lab:

{{<figure src="/img/portswigger/cp_unkeyed_cookie/lab-solved.png" position=center caption="Lab solved!">}}
