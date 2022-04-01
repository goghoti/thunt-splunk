# Scheduled Task/Job (T1053.005) 

Adversaries are known to use schedule tasks to gain persistence on a host after power off or during specific conditions met on the host. 

## Description

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. 

An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account. 

## Data Required 

- Event ID 106, 140, 141, 4698, 4700, 4701
- Powershell Logging
- Endpoint process logging (Commandline parameters)
- Sysmon

### Executing program

CAR-2013-05-004 At.exe creation of tasks (Baseline)

```
index="sysmon" Image="C:\\Windows\\*\\at.exe"|stats values(CommandLine) as "Command Lines" by ComputerName
```

CAR-2013-08-001 schtasks.exe actions

```
index="sysmon" EventCode="1" process="*\schtasks.exe" (cmdline="*/create*" OR cmdline="*/run*" OR cmdline="*/query*" OR cmdline="*/delete*" OR "*/change*" OR cmdline="*/end*")
```

CAR-2020-09-001 Windows task file creation

```
index="sysmon" EventCode="11" process="C:\\WINDOWS\\system32\\svchost.exe" (file_path="C:\\Windows\\System32\\Tasks\\*" OR file="C:\\Windows\\Tasks\\*")
```

CAR-2021-12-001 Creation of Suspicious Scheduled Tasks 

```
(((EventCode="4688" OR EventCode="1") CommandLine="*SCHTASKS*" (CommandLine="*/CREATE*" OR CommandLine="*/CHANGE*")) ((CommandLine="*.cmd*" OR CommandLine="*.ps1*" OR CommandLine="*.vbs*" OR CommandLine="*.py*" OR CommandLine="*.js*" OR CommandLine="*.exe*" OR CommandLine="*.bat*") OR (CommandLine="*javascript*" OR CommandLine="*powershell*" OR CommandLine="*wmic*" OR CommandLine="*rundll32*" OR CommandLine="*cmd*" OR CommandLine="*cscript*" OR CommandLine="*wscript*" OR CommandLine="*regsvr32*" OR CommandLine="*mshta*" OR CommandLine="*bitsadmin*" OR CommandLine="*certutil*" OR CommandLine="*msiexec*" OR CommandLine="*javaw*") OR (CommandLine="*%APPDATA%*" OR CommandLine="*\\AppData\\Roaming*" OR CommandLine="*%PUBLIC%*" OR CommandLine="*C:\\Users\\Public*" OR CommandLine="*%ProgramData%*" OR CommandLine="*C:\\ProgramData*" OR CommandLine="*%TEMP%*" OR CommandLine="*\\AppData\\Local\\Temp*" OR CommandLine="*\\Windows\\PLA\\System*" OR CommandLine="*\\tasks*" OR CommandLine="*\\Registration\\CRMLog*" OR CommandLine="*\\FxsTmp*" OR CommandLine="*\\spool\\drivers\\color*" OR CommandLine="*\\tracing*"))) OR ((EventCode="4698" OR EventCode="4702") ((TaskContent="*.cmd*" OR TaskContent="*.ps1*" OR TaskContent="*.vbs*" OR TaskContent="*.py*" OR TaskContent="*.js*" OR TaskContent="*.exe*" OR TaskContent="*.bat*") OR (TaskContent="*javascript*" OR TaskContent="*powershell*" OR TaskContent="*wmic*" OR TaskContent="*rundll32*" OR TaskContent="*cmd*" OR TaskContent="*cscript*" OR TaskContent="*wscript*" OR TaskContent="*regsvr32*" OR TaskContent="*mshta*" OR TaskContent="*bitsadmin*" OR TaskContent="*certutil*" OR TaskContent="*msiexec*" OR TaskContent="*javaw*") OR (TaskContent="*%APPDATA%*" OR TaskContent="*\\AppData\\Roaming*" OR TaskContent="*%PUBLIC%*" OR TaskContent="*C:\\Users\\Public*" OR TaskContent="*%ProgramData%*" OR TaskContent="*C:\\ProgramData*" OR TaskContent="*%TEMP%*" OR TaskContent="*\\AppData\\Local\\Temp*" OR TaskContent="*\\Windows\\PLA\\System*" OR TaskContent="*\\tasks*" OR TaskContent="*\\Registration\\CRMLog*" OR TaskContent="*\\FxsTmp*" OR TaskContent="*\\spool\\drivers\\color*" OR TaskContent="*\\tracing*")))
```

Scheduled Task within a short Time frame 

```
index="wineventlog" sourcetype="security" EventCode="4624" (logontype="3" AND EventCode=4698) AND GUID IN _time > "0.01"
```

IPC Share at.exe access

```
index="wineventlog" sourcetype="security" (EventID="5145" file_path="\\\*\\IPC$" target="atsvc")
```

Schtasks creation with possible network connection to domain

```
index="sysmon" EventCode="1" process="schtasks.exe" AND (cmdline="create" AND cmdline="https://" OR cmdline="http://")
```

## Help

Monitor process execution from the svchost.exe in Windows 10 and the Windows Task Scheduler taskeng.exe for older versions of Windows. 

If scheduled tasks are not used for persistence, then the adversary is likely to remove the task when the action is complete. 

Monitor Windows Task Scheduler stores in %systemroot%\System32\Tasks for change entries related to scheduled tasks that do not correlate with known software, patch cycles, etc.

Scheduled Tasks are also a great tool for adversaries to use, since they are present on all Windows operating systems, they are easy to use, and most users do not even realize they’re present. 

Data sets at https://github.com/OTRF/Security-Datasets can be used to mimic advesary behaviors for T1053.005 for analytic testing 

## Authors

goghoti - 4/1/2022

## References

- https://attack.mitre.org/techniques/T1053/005/
- https://www.us-cert.gov/ncas/alerts/TA18-201A
- https://redcanary.com/threat-detection-report/techniques/scheduled-task/
- https://www.socinvestigation.com/threat-hunting-using-windows-scheduled-task/
- https://car.mitre.org/analytics/CAR-2013-05-004/
- https://car.mitre.org/analytics/CAR-2013-08-001/
- https://car.mitre.org/analytics/CAR-2021-12-001/
- https://github.com/OTRF/Security-Datasets
- https://threathunterplaybook.com/library/windows/task_scheduler_service.html

## Version History

* 0.1
    * Initial Release
