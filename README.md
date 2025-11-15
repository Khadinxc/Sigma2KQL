# Sigma2KQL - Working as of 15/11/2025
Sigma Queries turned into KQL for Defender and Microsoft Snetinel using [pysigma-backend-KQL-backend](https://github.com/AttackIQ/pySigma-backend-kusto/tree/main)

```
├───rules
│   └───KQL
│       ├───Collection
│       ├───Command and Control
│       ├───Credential Access
│       ├───Defense Evasion
│       ├───Discovery
│       ├───Execution
│       ├───Exfiltration
│       ├───Impact
│       ├───Initial Access
│       ├───Lateral Movement
│       ├───Persistence
│       ├───Privilege Escalation
│       ├───Reconnaissance
│       └───Resource Development
├───rules-emerging-threats
│   └───KQL
└───rules-threat-hunting
    └───KQL
```

## How do I use the helper to do this locally or in a Detection as Code pipeline?

I've included a pip freeze of required librararies and as per standard practice for Python development I suggest creating a virtual environment not to _break_ system wide package management. 

### Run the following commands to get started:

**Clone the sigma rules repository:**

```
git clone https://github.com/SigmaHQ/sigma.git
```

```
python -m venv .venv
```

**With Windows:**
```
.\.venv\Scripts\Activate.ps1
```

**With Linux**
```
./.venv/bin/activate
```
**Once in your Python virtual env:**

```
pip install -r requirements.txt
```

**Then you can use the script like this:**

```
..\.venv\Scripts\python.exe .\helper.py --sigma-dir "C:/Users/Kaiber/sigma" --output-dir "C:/Users/Kaiber/Sigma2KQL-2025/KQL"
```

### Sample Rule Summary:

```
rules-threat-hunting Summary:
  Successful: 96
  Failed: 33
  Tactics covered: 13

================================================================================
OVERALL CONVERSION COMPLETE!
================================================================================
Total files processed: 3637
Total successful conversions: 2225
Total failed conversions: 1412

Output base directory: D:\Projects\SigmaTerraform\Sigma2KQL-2025\KQL

Folder structure created:
  rules/
  rules-emerging-threats/
  rules-threat-hunting/
```

### Sample Rule:

```
// Title: 7Zip Compressing Dump Files
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-27
// Level: medium
// Description: Detects execution of 7z in order to compress a file with a ".dmp"/".dump" extension, which could be a step in a process of dump file exfiltration.
// MITRE Tactic: Collection
// Tags: attack.collection, attack.t1560.001
// False Positives:
//   - Legitimate use of 7z with a command line in which ".dmp" or ".dump" appears accidentally
//   - Legitimate use of 7z to compress WER ".dmp" files for troubleshooting

DeviceProcessEvents
| where (ProcessCommandLine contains ".dmp" or ProcessCommandLine contains ".dump" or ProcessCommandLine contains ".hdmp") and (ProcessVersionInfoFileDescription contains "7-Zip" or (FolderPath endswith "\\7z.exe" or FolderPath endswith "\\7zr.exe" or FolderPath endswith "\\7za.exe") or (ProcessVersionInfoOriginalFileName in~ ("7z.exe", "7za.exe")))
```

