# NetSec Challenge - TryHackMe Write-up

## Overview

NetSec Challenge is a VIP room on TryHackMe focused on assessing practical network security skills. This CTF-style challenge is part of the Network Security module and requires enumeration, service analysis, and basic exploitation techniques to retrieve several flags.

In this write-up, I walk through each task, explaining the methodology and tools used to solve the challenge.

## Task 1: Introduction

The first task is straightforward: start the target machine and ensure it is reachable before beginning the enumeration process.

## Task 2: Challenge Questions

### Port Enumeration

The first step is to enumerate all open ports on the target machine. For this, I used Nmap with a SYN scan and an increased rate to speed up the process.

```bash
nmap -p- -sS --min-rate 5000 -Pn -n 10.80.148.26
```

![ports](/Writeups/Challenges/netsec/img/ports.png)

This scan reveals all open TCP ports, including those running on nonstandard port numbers.

From this output, we can immediately answer the following questions:

**Q1: What is the highest port number being open less than 10,000?**

**Q2: There is an open port outside the common 1000 ports; it is above 10,000. What is it?**

**Q3: How many TCP ports are open?**

All the required information is visible in the scan results, so we simply need to analyze and count the discovered ports.

### HTTP and Service Enumeration

**Q4: What is the flag hidden in the HTTP server header?**

To retrieve the HTTP server headers, I used two different approaches.

The first approach uses curl to request only the headers:

```bash
curl -I http://10.80.148.26
```

![http_header](/Writeups/Challenges/netsec/img/http_header.png)

The second approach leverages Nmap’s default scripts and version detection to gather more detailed information about all discovered services:

```bash
nmap -p 22,80,139,445,8080,10021 -sC -sV -Pn -n 10.80.148.26
```

![nmap_services_output](/Writeups/Challenges/netsec/img/nmap_services_output.png)

Both methods reveal the flag hidden in the HTTP server header, along with useful details about the other running services.

**Q5: hat is the flag hidden in the SSH server header?**

Since the SSH banner was already retrieved using Nmap scripts, the flag is visible in the previous scan output. Alternatively, we can manually connect to the SSH service using `telnet` to grab the banner:

```bash
telnet 10.80.148.26 22
```

### FTP Service Analysis

**Q6: We have an FTP server listening on a nonstandard port. What is the version of the FTP server?**

The FTP service is running on a nonstandard port. Again, Nmap already provides the version information, but we can also verify it by connecting directly via FTP:

```bash
ftp 10.80.148.26 10021
```

![ftp_version](/Writeups/Challenges/netsec/img/ftp_version.png)

**Q7: We learned two usernames using social engineering: `eddie` and `quinn`. What is the flag hidden in one of these two account files and accessible via FTP?**

We are given two usernames obtained through social engineering: eddie and quinn. To find their passwords, I used `Hydra` with the rockyou.txt wordlist.

```bash
hydra -l eddie -P /usr/share/wordlists/rockyou.txt 10.80.148.26 ftp -s 10021
```

```bash
hydra -l quinn -P /usr/share/wordlists/rockyou.txt 10.80.148.26 ftp -s 10021
```

The image below shows the password obtained for both users.

![hydra_eddie](/Writeups/Challenges/netsec/img/hydra_eddie.png)
![hydra_quinn](/Writeups/Challenges/netsec/img/hydra_quinn.png)

With those credentials, I logged into the FTP service and located the file containing the flag.

```bash
ftp 10.80.148.26 10021
```

![ftp_file](/Writeups/Challenges/netsec/img/ftp_file.png)

After downloading the file, the flag can be read directly:

```bash
cat ftp_flag.txt
```

### Stealth Scanning Challenge

**Q8: Browsing to http://MACHINE_IP:8080 displays a small challenge that will give you a flag once you solve it. What is the flag?**

Browsing to http://MACHINE_IP:8080 presents a challenge that requires performing a scan while avoiding detection.

![challenge](/Writeups/Challenges/netsec/img/challenge.png)

To remain as stealthy as possible, I experimented with different TCP scan types. The scan that successfully bypassed detection was a NULL scan, which sends packets without any TCP flags set.

```bash
nmap -sN 10.80.148.26
```

Once the scan was executed, the challenge page revealed the final flag.

![challenge_solved](/Writeups/Challenges/netsec/img/challenge_solved.png)

## Final Thoughts

This room is an excellent exercise in network enumeration and service analysis. It reinforces the importance of:

- Full port scanning
- Banner grabbing
- Using multiple tools to confirm findings
- Understanding stealth scanning techniques

If you’re learning network security or preparing for entry-level pentesting roles, NetSec Challenge is definitely worth completing.

Thanks for reading — I hope this write-up was helpful
