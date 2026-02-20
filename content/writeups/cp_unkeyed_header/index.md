+++
title = "Portswigger - Cache Poisoning with an Unkeyed Header"
date = "2026-02-20T00:00:00+00:00"
tags = ["portswigger", "cache_poisoning"]
description = "In this lab, we exploit a cache poisoning vulnerability via an unkeyed header"
series = ["Web Cache Poisoning"]
series_order = 1
+++

## Lab Description

This lab is vulnerable to web cache poisoning because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

> [!TIP]- Hint
> This lab supports the `X-Forwarded-Host` header.

Access [here](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header)
