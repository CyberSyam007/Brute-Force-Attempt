# 🔍**Brute Force Attempts on Internet Facing Servers**

![image (5)](https://github.com/user-attachments/assets/8a686a3b-791e-40f5-89dd-5d6586bb47d1)

## Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have been Compramised. The goal is to identify potential brute-force login attempts/successes from external sources. 
---

----
## Brute Force Attempts Detection

Several bad actors have been discovered attempting to log into the target machine.

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize attempts= count() by ActionType, RemoteIP, DeviceName
| order by attempts desc
```

![Brute Force Attempt](https://github.com/CyberSyam007/Brute-Force-Attempt/blob/main/Media/1.png)

---

The top 5 most failed login attempt IP addresses have not been able to successfully break into VM.

```kql
let susIps = dynamic(["218.92.0.186", "218.92.0.187","58.33.67.164"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "Remote Interactive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any (susIps)

```

**<Query no results>**

---

The targeted devices or accounts are not compromised and the threat wasn't able to login to the network devices.

```kql
let susIps = dynamic(["218.92.0.186", "218.92.0.187","58.33.67.164"]);
let imposters= dynamic(["root","administrators","admin","scan","enterprise"]);
DeviceLogonEvents
| where AccountName has_any (imposters) and RemoteIP has_any(imposters)
| where ActionType == "LogonSuccess"

---
The linux target-1 system is being attacked by various attackers. And none of the users “root” gained access to this machine.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```

---

We checked all of the successful login IP addresses for the 'labuser' account to see if any of them were unusual or from an unexpected location. All were normal.

```kql
DeviceLogonEvents
| where AccountName == "root"
| where ActionType == "LogonSuccess"
| summarize by RemoteIP, DeviceName

```

![Successful Logins](https://github.com/CyberSyam007/Brute-Force-Attempt/blob/main/Media/2.png)

---

Though the devices were exposed to clear brute force attempts, there is no evidence of any brute force success or unauthorized access.

Here's how the relevant TTPs and detection elements can be organized into a chart for easy reference:

---

# 🛡️ MITRE ATT&CK TTPs for Incident Detection

| **TTP ID** | **TTP Name**                     | **Description**                                                                                          | **Detection Relevance**                                                         |
|------------|-----------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| T1071      | Application Layer Protocol        | Observing network traffic and identifying misconfigurations (e.g., device exposed to the internet).       | Helps detect exposed devices via application protocols, identifying misconfigurations. |
| T1075      | Pass the Hash                     | Failed login attempts suggesting brute-force or password spraying attempts.                               | Identifies failed login attempts from external sources, indicative of password spraying.  |
| T1110      | Brute Force                       | Multiple failed login attempts from external sources trying to gain unauthorized access.                 | Identifies brute-force login attempts and suspicious login behavior.            |
| T1046      | Network Service Scanning          | Exposure of internal services to the internet, potentially scanned by attackers.                         | Indicates potential reconnaissance and scanning by external actors.            |
| T1021      | Remote Services                   | Remote logins via network/interactive login types showing external interaction attempts.                   | Identifies legitimate and malicious remote service logins to an exposed device.  |
| T1070      | Indicator Removal on Host         | No indicators of success in the attempted brute-force attacks, showing system defenses were effective.     | Confirms the lack of successful attacks due to effective defense measures.      |
| T1213      | Data from Information Repositories| Device exposed publicly, indicating potential reconnaissance activities.                                  | Exposes possible adversary reconnaissance when a device is publicly accessible.  |
| T1078      | Valid Accounts                    | Successful logins from the legitimate account ('labuser') were normal and monitored.                      | Monitors legitimate access and excludes unauthorized access attempts.           |

---

This chart clearly organizes the MITRE ATT&CK techniques (TTPs) used in this incident, detailing their relevance to the detection process.

**📝 Response:**  
- Did a Audit, Malware Scan, Vulnerability Management Scan, Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access), Implemented account lockout policy, Implemented MFA, awaiting further instructions.

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address.
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint.
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Supplemental:
- **More on "Shared Services" in the context of PCI DSS**: [PCI DSS Scoping and Segmentation](https://www.pcisecuritystandards.org%2Fdocuments%2FGuidance-PCI-DSS-Scoping-and-Segmentation_v1.pdf)

---

## Created By:
- **Author Name**: Syam Prakash  
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/syam-prakash-maddineni/)  
- **Date**: April,25 2025

## Validated By:
- **Reviewer Name**: Josh Madakor  
- **Reviewer Contact**: [LinkedIn](https://www.linkedin.com/in/joshmadakor/)  
- **Validation Date**: Apr 2025

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `Apr 2025`    | `Syam Prakash`   |
```
