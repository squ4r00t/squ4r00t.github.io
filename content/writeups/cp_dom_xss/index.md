+++
title = "Portswigger - Cache Poisoning to DOM XSS"
date = "2025-12-06T00:00:00+00:00"
tags = ["portswigger", "cache_poisoning", "dom_xss", "xss"]
description = "In this lab, we exploit a cache poisoning vulnerability to distribute a DOM XSS to other users"
series = ["Web Cache Poisoning"]
series_order = 10
+++

## Lab Description

 This lab contains a DOM-based vulnerability that can be exploited as part of a web cache poisoning attack. A user visits the home page roughly once a minute. Note that the cache used by this lab has stricter criteria for deciding which responses are cacheable, so you will need to study the cache behavior closely.

To solve the lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser. 

Access [here](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-to-exploit-a-dom-vulnerability-via-a-cache-with-strict-cacheability-criteria)

## Finding an unkeyed input

First, we start by looking for an unkeyed input that can be used to elicit a malicious response. For this, we can use the Burp extension [Param Miner](https://github.com/PortSwigger/param-miner).

After scanning the home page (which is cacheable), we find that the `X-Forwarded-Host` header is an unkeyed input:

{{<figure src="/img/portswigger/cp_dom_xss/unkeyed_header.png" position=center caption="X-Forwarded-Host header found by Param Miner">}}

Next, we need to figure out in which way does this header affect the response. 

For this, we can send the header with an arbitrary value set and see if it is reflected in the response:

{{<figure src="/img/portswigger/cp_dom_xss/reflected_forwarded_host.png" position=center caption="Value of the X-Forwarded-Host header reflected in the response">}}

We can see that the value that we entered was set to the `host` attribute of the `data` object. Let's see where else this object is used:

{{<figure src="/img/portswigger/cp_dom_xss/where_data_used.png" position=center caption="Value used inside initGeoLocate()">}}

We can see above that the value is passed as an argument to the `initGeoLocate()` function, which is imported from `/resources/js/geolocate.js`:

{{<figure src="/img/portswigger/cp_dom_xss/initgeo_function.png" position=center caption="Value used inside initGeoLocate()">}}

This function will fetch some json data from the given url, then it will append the value of the `country` attribute directly (without sanitization) to the `innerHTML` sink. This is vulnerable to a DOM XSS if the json data can be altered.

Thanks to the `X-Forwarded-Host` header, we can specify from which url the json data is imported and that response is cacheable. This means that we can alter that url for other users as well, making the DOM XSS distributed.

## Conducting the attack

All we need to do is to serve the following json on the exploit server at `/resources/json/geolocate.json`:

```json
{
    "country": "<img src=x onerror=alert(document.cookie)>"
}
```

> We also need to add the `Access-Control-Allow-Origin: *` header to allow cross origin resource sharing.

{{<figure src="/img/portswigger/cp_dom_xss/exploit_server.png" position=center caption="Exploit Server">}}

After storing the exploit, we need to poison the cache with the exploit server's domain using the `X-Forwarded-Host` header:

{{<figure src="/img/portswigger/cp_dom_xss/poison_cache.png" position=center caption="Poisonning the cache">}}

After refreshing the home page, we see the alert and we solved the lab:

{{<figure src="/img/portswigger/cp_dom_xss/lab_solved.png" position=center caption="Lab solved!">}}
