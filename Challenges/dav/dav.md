# Dav - TryHackMe Write-up

## Overview

The **Dav** challenge is a TryHackMe room focused on directory enumeration, WebDAV exploitation, unrestricted file upload, and reverse shells. It is a great exercise for beginners to understand how to enumerate ports and directories, upload a reverse shell, and use sudo misconfigurations to escalate privileges.

In this write-up, I walk through each step of the process, explaining the methodology and tools used to solve the challenge.

## Enumeration

The first step is to enumerate all open ports on the target machine. For this, I used my own script which automates the scan with nmap and generates two output files.

![ports](/Challenges/dav/img/dav_port_scan.png)

The port 80 is open, so we can access the web server.

![web](/Challenges/dav/img/dav_web.png)

Is shown just an Apache2 Ubuntu Default Page. Since the default page didn’t reveal useful information, directory enumeration was performed to discover hidden endpoints

```bash
gobuster dir -u http://10.80.169.21 -w /usr/share/wordlists/dirb/big.txt
```

![gobuster](/Challenges/dav/img/dav_gobuster.png)

## Exploitation

This directory listing shows a `/webdav` directory, if we try to access to it, we can see a login popup, first I tried with `admin` and `admin`, but it doesn't work.

![webdav](/Challenges/dav/img/dav_login_popup.png)

Therefore doing a little reseach about webdav, were found that it is an HTTP Extension that lets web developers update their content remotely from a client, also assuming that default credentials still in use, were searched some default credentials, if that is so, we can get access to the webdav server.

![credentials](/Challenges/dav/img/dav_credentials.png)
![webdav](/Challenges/dav/img/dav_webdav.png)

Since WebDAV allows the PUT method, it was possible to upload a PHP reverse shell directly to the server usign `curl`.

```bash
curl -u wampp:xampp -T /usr/share/webshells/php/php-reverse-shell.php http://10.80.169.21/webdav/
```

![upload](/Challenges/dav/img/dav_upload.png)

> **Note:**
> Before upload the reverse shell, you have to change the IP address and port to your own IP and port.

![reverse](/Challenges/dav/img/dav_reverse.png)

Using `netcat` we can catch the reverse shell.

```bash
nc -lvp 443
```

![reverse](/Challenges/dav/img/dav_reverse_shell.png)

With the reverse shell we can get the user flag.

![user](/Challenges/dav/img/dav_user_flag.png)

## Privilege Escalation

Looking for a way to escalate privileges, it is found that the user www-data has permissions to run `cat` command with sudo.

![sudo](/Challenges/dav/img/dav_sudo.png)

Using this information, is easy to get the root flag, only using cat with sudo is possible to read any file as root.

```bash
sudo cat /root/root.txt
```

![root](/Challenges/dav/img/dav_root_flag.png)

## Final Thoughts

This room is was very easy, but it was a good exercise, especially for beginners, it helps to start thinking like a pentester, because if you doesn't have any experience with webdav or any other service, helps you to search for information about it and try to find a way to get access to it. Therefore it is a good way to start learning about pentesting and think like a pentester.

Overall, the Dav room is simple but effective. It reinforces core concepts like enumeration, researching unfamiliar services, and abusing misconfigurations, skills that are essential in real-world pentesting

Thanks for reading — I hope this write-up was helpful
