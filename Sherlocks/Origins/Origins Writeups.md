# 1. Origins Writeups

- [1. Origins Writeups](#1-origins-writeups)
  - [1.1. Scenario](#11-scenario)
  - [1.2. Skills Learnt](#12-skills-learnt)
  - [1.3. Initial Analysis](#13-initial-analysis)
- [2. Questions](#2-questions)
- [3. Incident Response](#3-incident-response)
  - [3.1 Containment](#31-containment)
  - [3.2 Root Cause Analysis](#32-root-cause-analysis)
  - [3.3 Eradication](#33-eradication)
  - [3.4 Recovery](#34-recovery)

## 1.1. Scenario

This Sherlock case is relatively simple, involving the **theft of approximately 20 GB of data** were stolen from internal **s3 buckets**. During the root cause analysis, an **FTP server** was suspected to be the initial point of compromise.

In this scenario, we are provided with a minimal **PCAP file**, and our objective is to find evidence of brute-force attempts and data exfiltration.

## 1.2. Skills Learnt 
- PCAP analysis using tools like Wireshark to detect brute-force attacks and data exfiltration patterns.
- Network protocol understanding, especially FTP, to identify unauthorized file transfers.
- Detection of Indicators of Compromise (IoCs) and attacker behavior through network traffic inspection.

## 1.3. Initial Analysis 
We have been provided with a `.pcap` file that contains network traffic. By analyzing this file, we can find information about the attacker, including evidence of brute-force attempts and data exfiltration.
To investigate the file, we will use `Wireshark`. As a first step, we need to identify suspicious activity in order to determine the attacker's IP and behavior.

# 2. Questions
---
**1. What is the attacker's IP address?**

While examining the `ftp.pcap` file, we find suspicious activity from the IP `15.206.185.207`. As shown below, there are **multiple SYN/SYN-ACK packages ocurring within less than a second**, with the port 21 as either ther source or destination.

Another important observation is that the IP `15.206.185.207` was **alternating source ports**, as if attempting **multiple sessions in parallel**. It is also worth noting that this is a **public IP** (owned by AWS), which suggests that the attacker was likely **operating from a cloud server**, that is a common tactic used to hide their real identity and location.

![IMAGE](/Writeups/Sherlocks/Origins/img/Attacker's%20IP.jpg)

Examining the file further, we identified a **brute-force attemp** from this IP. The attacker repeatedly used the `USER` command with different usernames such as `admin`, `backup` and `sysaccount`. These attemps were separeted by only a few milliseconds, and the server responded with `331 Please specify the password`. This behavior strongly suggest a brute-force attack trying to find valid usernames.

![IMAGE](/Writeups/Sherlocks/Origins/img/Brute-Force%20Attemps.jpg)

With this evidence, we can confirm the attacker's IP address.

**ANSWER: `15.206.185.207`**

---
**2. It's critical to get more knowledge about the attackers, even if it's low fidelity. Using the geolocation data of the IP address used by the attackers, what city do they belong to?**

Once we have the attacker's IP address, we can use geolocation tools to determine the city it belongs to. In this case, I used [iplocation.net](https://www.iplocation.net/) to find the city associated with the IP.

![IMAGE](/Writeups/Sherlocks/Origins/img/Geolocation%20Data.jpg)

According to the geolocation results, the IP address is registered in Mumbai, Maharashtra, India.

**ANSWER: `Mumbai`**

---
**3. Which FTP application was used by the backup server? Enter the full name and version.**

While examining the file, we found that the FTP application used was `vsFTPd 3.0.5`, as shown below.

![IMAGE](/Writeups/Sherlocks/Origins/img/FTP%20application.jpg)

vsFTPd (*Very Secure FTP Daemon*) is a popular and secure FTP server for Unix-like systems. It presence suggests the server was likely running on a Linux-based system. Although vsFTPd is known for its security, FTP transmits data in plaintext, making it vulnerable to brute-force attacks and credential sniffing if not properly secured. 

**ANSWER: `vsFTPd 3.0.5`**

---
**4. The attacker has started a brute force attack on the server. When did this attack start?**

By analyzing the file we identified the moment when the brute-force attack began. As shown below, the attack started on **2024-05-03 at 04:12:54** with the username `admin`.

![IMAGE](/Writeups/Sherlocks/Origins/img/Start%20of%20the%20Attack.jpg)

**ANSWER: `2024-05-03 04:12:54`**

---
**5. What are the correct credentials that gave the attacker access? (Format username:password)**

Searching through the file, we identified several connections attempts, but one was successful, using the username `forela-ftp` and password `ftprocks69$`.

![IMAGE](/Writeups/Sherlocks/Origins/img/Credentials.jpg)

**ANSWER: `forela-ftp:ftprocks69$`**

---
**6. The attacker has exfiltrated files from the server. What is the FTP command used to download the remote files?**

The common command used to download files from an FTP server is `RETR`, so we filtered the file data to search for occurrences of this command.

![IMAGE](/Writeups/Sherlocks/Origins/img/FTP%20command.jpg)

Indeed, the command used was `RETR`, and was used to download the files **Maintenance-Notice.pdf** and **s3_buckets.txt**

**ANSWER: `RETR`**

**7. Attackers were able to compromise the credentials of a backup SSH server. What is the password for this SSH server?**

In order to find this information, we searched within the files downloaded by the attacker, which may contain sensitive data.
To do this, we go to **File** -> **Export Objects** -> **FTP-DATA** in Wireshark.

![IMAGE](/Writeups/Sherlocks/Origins/img/Export%20FTP-DATA.jpg)

![IMAGE](/Writeups/Sherlocks/Origins/img/SSH%20password.jpg)

While analyzing the **Maintenance-Notice.pdf** file, we identified a temporary SSH server password that could potentially be used by the attacker.

**ANSWER: `**B@ckup2024!**`**

---
**8. What is the s3 bucket URL for the data archive from 2023?**

To obtain the 2023 S3 bucket URL, we examined the **s3_buckets.txt** file. In this file, we found the URL we were looking for, as shown below.

![IMAGE](/Writeups/Sherlocks/Origins/img/2023S3%20link.jpg)

**ANSWER: `https://2023-coldstorage.s3.amazonaws.com`**

---
**9. The scope of the incident is huge as Forela's s3 buckets were also compromised and several GB of data were stolen and leaked. It was also discovered that the attackers used social engineering to gain access to sensitive data and extort it. What is the internal email address used by the attacker in the phishing email to gain access to sensitive data stored on s3 buckets?**

To find the phishing email used to gain access to sensitive data stored on s3 buckets, we analyze the **s3_buckets.txt** file. Within the file, we found an email address that may have been used by the attacker.

![IMAGE](/Writeups/Sherlocks/Origins/img/Phishing%20email.jpg)

**ANSWER: `archivebackups@forela.co.uk`**

---
# 3. Incident Response

Briefly summarizing the incident, an FTP server was compromised through a brute-force attack perfomed from the IP `15.206.185.207`. After gaining access, the attacker download two files: **Maintenance-Notice.pdf** and **s3_buckets.txt**. These files contained a temporary SSH password, s3 bucket URLs, and an internal email address. This information was likely used to access additional resources, which resulted in the theft of approximately 20 GB of data.

## 3.1 Containment

1. Disable the affected FTP server
2. Disable the SSH password
3. Revoke compromised email credentials
4. Block access to the affected S3 bucket
5. Segregate affected host from the rest of the network
6. Apply temporary firewall rules to limit outbound traffic 

## 3.2 Root Cause Analysis

1. Analyze the FTP server
2. Check for lateral movement from the FTP server to internal systems
3. Examine AWS access patterns
4. Build a timeline of events
5. Identify tools or methods used

## 3.3 Eradication 

1. Rebuild the system from secure backups
2. Patch known vulnerabilities
3. Change all system passwords
4. Apply least privilege policies

## 3.4 Recovery

1. Restore services
2. Monitor restored systems closely for anomalies
3. Inform affected users and/or departments
4. Enforce security awareness, especially phishing and password hygiene