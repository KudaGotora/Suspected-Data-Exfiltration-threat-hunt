# Suspected-Data-Exfiltration-threat-hunt

- [Scenario Creation](https://github.com/KudaGotora/Suspected-Data-Exfiltration-threat-hunt/blob/main/threat-hunt-scenario-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


##  Scenario

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. 

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any Look for any file activity, based on the Timestamp from any discovered process activity
- **Check `DeviceProcessEvents`** for any signs of any kind of archive activity.
- **Check `DeviceNetworkEvents`** for any network activity, based on the Timestamp from the process or file activity

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I did a search within MDE DeviceFileEvents for any activities with zip files, and found a lot of regular activity of archiving stuff and moving to a backup folder


**Query used to locate events:**

```kql
IDeviceFileEvents
| where DeviceName == "kuda-hunt"
| where FileName endswith ".zip"
| order by Timestamp desc

```

![Screenshot (18)](https://github.com/user-attachments/assets/993637b3-e90a-4e68-af5d-46c4ef36daf0)

---

### 2. Searched the `DeviceProcessEvents` Table

I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before and after the archive was created. 

**Query used to locate event:**

```kql

let VMName = "kuda-hunt";
let specificTime = datetime(2025-05-09T07:10:21.7540198Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

```

![Screenshot (19)](https://github.com/user-attachments/assets/149186a7-77e3-413e-9903-c9a7dd8af8fa)

---

### 3. Searched the `DeviceNetworkEvents` Table 

I took one of the instances of a zip file being created, took the timestamp and searched under DeviceNetworkEvents for anything happening 10 minutes before and after the archive was created  to see if there was any evidence for network exfiltration from the network

**Query used to locate events:**

```kql
let VMName = "kuda-hunt";
let specificTime = datetime(2025-05-09T07:10:21.7540198Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType

```

![Screenshot (20)](https://github.com/user-attachments/assets/b36c976e-cefc-463a-84bd-980db999d5f2)

---



---

---

## Summary

The attacker appears to have gathered data, compressed it into zip files, and potentially attempted to exfiltrate it—a classic data theft or espionage pattern.

---

## Response Taken


. The device was isolated, and the user's direct manager was notified.

---
