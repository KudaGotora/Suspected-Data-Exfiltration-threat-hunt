# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Generate Fake Employee Data:
Creates a CSV file (employee-data-<timestamp>.csv) containing synthetic employee information, including names, Social Security Numbers (SSNs), phone numbers, salaries, and dates of birth.
GitHub
+1
GitHub
+1

2. Download and Install 7-Zip:

Downloads the 7-Zip installer from a specified URL and installs it silently to enable file compression capabilities.
GitHub

3. Compress the Data:

Uses 7-Zip to compress the generated CSV file into a ZIP archive (employee-data-<timestamp>.zip).
GitHub
+1
GitHub
+1

4. Upload to Azure Blob Storage:

Utilizes hardcoded Azure storage account credentials to upload the ZIP file to a specified Azure Blob Storage container, simulating data exfiltration to an external cloud service.
GitHub

4. Cleanup and Logging:

Moves the original CSV and ZIP files to a backup directory (C:\ProgramData\backup) and logs each step of the process to a log file (C:\ProgramData\entropygorilla.log).
GitHub
+1
GitHub
+1


---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Look for any file activity, based on the Timestamp from any discovered process activity
. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Look for any kind of archive activity.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Look for any network activity, based on the Timestamp from the process or file activity.|

---

## Related Queries:
```kql
DeviceFileEvents
| where DeviceName == "kuda-hunt"
| where FileName endswith ".zip"
| order by Timestamp desc

//2025-05-09T02:32:32.1623254Z
// Look for any network activity, based on the Timestamp from the process or file activity
let VMName = "kuda-hunt";
let specificTime = datetime(2025-05-09T07:10:21.7540198Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine


let VMName = "kuda-hunt";
let specificTime = datetime(2025-05-09T07:10:21.7540198Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType

```

---

## Created By:
- **Author Name**: Kuda Gotora
- **Author Contact**: www.linkedin.com/in/kudakwashe-gotora-a740a1316
- **Date**: May 12, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | ` May 12, 2025`  | `Kuda Gotora`   
