# Smoke and Mirrors
## Scenario

This is a very easy sherlock in which we have to investigating a stealthy post-breach attack where several expected security logs and Windows Defender alerts appear to be missing. 

Is suspected the attacker employed **defense evasion techniques to disable or manipulate security controls**, significantly complicating detection efforts. We have to **analyze the provided event logs and forensic artifacts** to uncover how the attacker disabled or altered security features. Our objective is to **identify the tools, commands, or scripts used to reduce visibility** and to reconstruct the methods the attacker employed to operate undetected.

## Skills Learnt

- Understand and recognize malicious use of PowerShell cmdlets
- Analyze and interpret Windows Registry modifications
- Identify how attackers disable or tamper with Windows security features

## Initial Analisys
We have files `.evtx` that contains PowerShell logs, PowerShell Operational Logs and Sysmon Operational logs. Additionally, we know that **LSA protection and Windows Defender** were both disabled. The attacker also **loaded an AMSI patch** written in PowerShell and **disable PowerShell command history logging**. 

# Questions
1. The attacker disabled LSA protection on the compromised host by modifying a registry key. What is the full path of that registry key?

LSA (Local Security Authority) is component of Windows **responsible for users authentication, login management and credential handling** at the local level. It protects confidental data stored and managed within the LSA. If compromised, attackers could **steal credentials** or **inject code** to manipulate it.

Following this line of thought, we searched in the Windows PowerShell Operational logs for **common command used such as `reg add`** which is used to add new subkeys or entries to the Windows Registry, or to modify existing values.

![image](https://github.com/user-attachments/assets/e5924d26-e6de-4faf-8eac-70ac839e0eb0)

As shown above, we found that the attacker used the following command: 

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL /t REG_DWORD /d 0 /f
```

Lets break down this command:

- `reg add`: Modifies or adds a registry key
- `/v RunAsPPL`: Specifies the value to modify or create, in this case `RunAsPPL` which is used to control LSA protection.
- `/t REG_DWORD`: Sets the type of data as DWORD ( a 32-bits integer).
- `/d 0`: Assigns the value `0`, which disables LSA protection.
- `f`: Force the operation without prompting for confirmation.

From this, we can conclude that the attacker modified the registry key `HKLM\SYSTEM\CurrentControlSet\Control\LSA` to disable LSA protection, as shown in the command above.

**ANSWER: `HKLM\SYSTEM\CurrentControlSet\Control\LSA`**

2. Which PowerShell command did the attacker first execute to disable Windows Defender?

The most commonly used PowerShell cmdlet to disable Windows Defender is `Set-MpPreference`. Therefore, we searched for this cmdlet in the Windows PowerShell logs. We found multiples coincidences of its use, however, as shown below, the first execution was recorded at '4-10-2025 1:31:35 AM'

![image](https://github.com/user-attachments/assets/a8781f72-4c29-43d7-95ee-a88a00939546)

As shown above, we found that the attacker used the following command to disable Windows Defender Protections:

 ```
 Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true
 ```

 Lets break down this command:

 - `Set-MpPreference`: Manages Windows Defender settings and preferences.
 - `DisableIOAVProtection $true`: Disable IOAV (Input/Output Antivirus) protection, which scans files when they are opened.
 - `DisableEmailScanning $true`: Disable scanning of email attachments.
 - `DisableBlockAtFirstSeen $true`: Disable the "Block at first sight" feature, which blocks suspicious files the first time they appear on the system.

From this, we can conclude the attacker used this cmdlet to disable the Windows Defender Protections.

**ANSWER: `Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true`**

3. The attacker loaded an AMSI patch written in PowerShell. Which function in the DLL is being patched by the script to effectively disable AMSI?

The Antimalware Scan Interface (AMSI) is a versatile interface standard that **allows your applications and services to integrate with any antimalware product**. In other words, AMSI functions as an intermediary between applications and antivirus software. Therefore, an **AMSI patch is a offensive technique used to disable AMSI**. This is typically done by modifiying an internal function of the AMSI DLL (*usually AmsiScanBuffer*). 

Aditionally, a Dynamic Link Library (DLL) is `.dll` file that **stores reusable code, functions or resources that can be used by different programs simultaneously**. Windows and its applications rely on hundreds of these DLLs.

As shown below, the attackers modified the `amsi.dll` file, which contains functions related to antivirus scanning. Also the patched function was `AmsiScanBuffer`, this function analyzes the content of a script or command. By modifiying this function, any subsequent malicious code can be executed without being detected by the antivirus.

![image](https://github.com/user-attachments/assets/ec70d87e-7756-4193-8d72-3e54fef84925)

**ANSWER: `AmsiScanBuffer`**

4. Which command did the attacker use to restart the machine in Safe Mode?

To restart a windows machine in Safe Mode, the command must include `safeboot`. Searching for this we confirm that the attacker executed the command `bcdedit.exe /set safeboot network` to initiate a Safe Mode reboot.

![image](https://github.com/user-attachments/assets/7ac61a01-447c-4d66-9b33-b1127c031f60)

**ANSWER: `bcdedit.exe /set safeboot network`**

5. Which PowerShell command did the attacker use to disable PowerShell command history logging? 

The cmdlet `Set-PSReadlineOption` allows us modify the behavior of the PSReadLine module during command-line editing. Searching for its used, it is reveals that the attacker executed the following command to disable the history logging.

![image](https://github.com/user-attachments/assets/bf5a2659-008f-4120-8afb-c58f7b79123e)

**ANSWER: `Set-PSReadlineOption -HistorySaveStyle SaveNothing`**

# Incident Response
Briefly summarizing the incident, the system was compromised, and the attacker disabled or manipulated several security controls.

Once the analysis is complete, we can respond to the incident by following the steps below:

1. Isolate the system from the network to prevent further damage or lateral movement.
2. Search for any signs of persistence, including malware, payloads, backdoors and suspicious scripts.
3. Eradicate all traces of the attacker, such us scripts, malware, payloads or backdoors.
4. Restore critical components as manipulated DLLs.
5. Change all system passwords.
6. Restore the system from a secure backup and apply security patches.
7. Monitor the system to ensure there are no signs of reinfection.
