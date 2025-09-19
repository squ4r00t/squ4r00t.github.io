#!/bin/bash

type=$1
name=$2
cap_name=$(echo "${name^}")
case $type in
  "htb")
    if [[ -d "./static/img/htb/$name" ]] || [[ -d "./content/htb/$name/index.md" ]]; then
      echo "[-] already exists"
      exit 1;
    fi
    echo "Creating ./static/img/htb/$name and ./content/htb/$name/index.md"
    mkdir ./static/img/htb/$name
    mkdir ./content/htb/$name
    cat > ./content/htb/$name/index.md << EOF
---
title: "HTB - $cap_name"
date: "2025-00-00T00:00:00+00:00"
tags: ["ctf", "htb"]
description: "Writeup for the '' rated machine: $cap_name"
draft: true
---

{{<lead>}}
$cap_name is a ...
{{</lead>}}

## Recon

### Port Scanning

## Foothold

## Privesc    

EOF

    ;;
  "thm")
    echo "You chose thm"
    ;;
  "portswigger")
    echo "You chose portswigger"
    ;;
  *)
    echo "[-] Unknown post type"
    ;;
  esac
