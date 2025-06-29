# Scenario
This is a very easy sherlock that demostrates some of the common virtualization detection techniques used by attackers. Is suspected that the threat actor carried out **anti-virtualization checks to avoid detection in sandboxed enviroments**, so we have to **analyze the event logs** and **identify the specific techniques** used for virtualization detection. It also require evidence of the registry checks or processes the attacker executed to perform these checks.

## Skills Learnt
We'll gain the ability to create detection rules by identifying specific WMI queries, comparing processes for virtual machine detection, and analyzing registry keys or file paths associated with virtual environments.

## Initial Analysis
We have provided two `.evtx` files to examine the incident logs. In these files, we observe only Windows PowerShell event logs, indicating that PowerShell was used.

---

# Questions

1. **Which WMI class did the attacker use to retrieve model and manufacturer information for virtualization detection?**
   
As mentioned above, PowerShell was used, so we can assume that the attacker used the `Get-WmiObject` command to retrieve information, as it is one of the most common ways to do so through WMI classes in PowerShell.

Therefore, we can use the **Find** tool to search for this in the event log. As shown in the images below, the `Win32_ComputerSystem` class is used to obtain model and manufacturer details.

![image](https://github.com/user-attachments/assets/712e97ed-abe1-4fcd-abde-3ce994aea90e)

![image](https://github.com/user-attachments/assets/edbf252b-83d4-4caf-85dc-cd1d04336373)

**ANSWER `Win32_ComputerSystem`**

2. **Which WMI query did the attacker execute to retrieve the current temperature value
of the machine?**

Following the same approach, we searched for `Get-WmiObject` and found the query `SELECT * FROM MSAcpi_ThermalZoneTemperature`, which is used to retrieve the current temperature value, as shown in the image below.

![image](https://github.com/user-attachments/assets/dc4e7550-320f-4a32-9f0a-d44e2f8d4485)

**ANSWER: `SELECT * FROM MSAcpi_ThermalZoneTemperature`**

3. **The attacker loaded a PowerShell script to detect virtualization. What is the function name of the script?**

In order to search for the PowerShell script, we filtered logs by **Event ID 4104**. These types of logs contain the PowerShell scripts that were executed. Upon reviewing those logs we found that the attacker loaded a virtualization detection script which contains the function `Check-VM` as shown below.

![image](https://github.com/user-attachments/assets/6f822b5f-aeed-4472-9c29-b34ff772b417)

![image](https://github.com/user-attachments/assets/98eec794-fc2a-4554-a7c9-52755359ad8c)

**ANSWER: `Check-VM`**

4. Which registry key did the above script query to retrieve service details for virtualization detection?

Upon analyzing the script we find that it retrieves services details from `HKLM:\SYSTEM\ControlSet001\Services`. This registry key contains information about the installed services and drivers that start when the system boots.

Taking into account that **hypervisors have their own services** to facilitate integration between the host and the VM, this key is used to **detec those services** that are asociated with different virtualization platforms. It is also a silent and reliable method, as accessing the registry is **less intrusive** than other techniques, and the presence of those services it is a **strong indicator** that the system is virtualized.

![image](https://github.com/user-attachments/assets/d216f820-8179-407e-9d43-9e369594885c)

**ANSWER: `HKLM:\SYSTEM\ControlSet001\Services`**

5. The VM detection script can also identify VirtualBox. Which processes is it comparing to determine if the system is running VirtualBox?

We continued searching until we found the VirtualBox-related part of the script. Just below that section, we observed that the script uses the `Get-Process` command to retrive and then compare running processes with `vboxservice.exe` and `vboxtray.exe` to determine if the system is running in a VirtualBox enviroment.

![image](https://github.com/user-attachments/assets/32664025-c92b-4e34-b3d4-9613bb11097a)

**ANSWER: `vboxservice.exe, vboxtray.exe`**

6. The VM detection script prints any detection with the prefix 'This is a'. Which two virtualization platforms did the script detect?

BY analyzing the script, we noticed that it prints virtual machine detection results using the phrase 'This is a', followed by the name of the virtualization platform. To identify which virtualization platforms were detected by the script, we searched for the string 'This is a'.

![image](https://github.com/user-attachments/assets/f0a72e1b-7450-4244-a1d8-0d6fcbdbc92b)

As shown above, the script detects that the system is running inside either `Hyper-V` or `VMware` platform.

**ANSWER: `Hyper-V, VMware`**

---
# Incident Response

Briefly summarizing the incident a threat performed anti-virtualization checks to avoid detection in sandboxed enviroments. This is important as a **indicador of compromise (IoC)**, since such check can be a preliminary step to a real infection or indicate the **execution of malware**.

Once we confirm that the script was executed, it is important to:

1. Analyze the origin (Who user executed the script and if it was authorized)
2. Check the integrity of the system and isolate it until its integrity is confirmed.
3. If the system was compromised, determine how was compromised.
4. If compromised, restore teh system from a secure backup
5. Restrict the use of PowerShell to prevent future incidents.
