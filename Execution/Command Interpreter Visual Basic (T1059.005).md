# Command and Scripting Interpreter: Visual Basic (T1059.005) 

A common method of initial compromise and execution of threat actors is VB macros that are imbedded in emails. Detection of VB in the network can allow a defender to trace back the timeline of a phishing campaign. And can provide context and potential outlying executions of this type of code. 

## Description

Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as Component Object Model and the Native API through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core.

Derivative languages based on VB have also been created, such as Visual Basic for Applications (VBA) and VBScript. VBA is an event-driven programming language built into Microsoft Office, as well as several third-party applications. VBA enables documents to contain macros used to automate the execution of tasks and other functionality on the host. VBScript is a default scripting language on Windows hosts and can also be used in place of JavaScript on HTML Application (HTA) webpages served to Internet Explorer (though most modern browsers do not come with VBScript support).

Adversaries may use VB payloads to execute malicious commands. Common malicious usage includes automating execution of behaviors with VBScript or embedding VBA content into Spearphishing Attachment payloads.

## Data Required 

- Process Logs
- Endpoint logging
- api calls from applications/dev environments where vb is used
- DNS Query info 

### Executing program

RAT deployed via powershell with VBA Macros (APT29 cmdline from intel in report)

```
(source="WinEventLog:*" (Image="*\\powershell.exe") CommandLine="*ExecutionPolicy*" CommandLine="*Bypass*" CommandLine="*Users\\Public*" CommandLine="*Run+++++++++.ps1*") | table Image,CommandLine
```

Scheduled task -> wscript -> execution of malicious vb

```
(source="WinEventLog:*" CommandLine="*schtasks*" CommandLine="*create*" CommandLine="*wscript*" CommandLine="*CSIDL*") | table Image,CommandLine
```

EDR Tool file extension query

```
process="outlook.exe" filemod="*.vbs"
```

VBS script execution query 

```
index="process" where (parent_process_name = "wscript.exe" AND parent_process = "*//e:vbscript*") OR (process_name = "wscript.exe" AND process= "*//e:vbscript*") by parent_process_name parent_process process_name process_id 
```

## Help

Validation of email receipt taken from timestamp of vbs execution is a large indicator to pivot to IR or more in depth analysis. 

Monitor for events associated with VB execution, such as Office applications spawning processes, usage of the Windows Script Host (typically cscript.exe or wscript.exe), file activity involving VB payloads or scripts, or loading of modules associated with VB languages (ex: vbscript.dll). VB execution is likely to perform actions with various effects on a system that may generate events, depending on the types of monitoring used. Monitor processes and command-line arguments for execution and subsequent behavior. Actions may be related to network and system information Discovery, Collection, or other programable post-compromise behaviors and could be used as indicators of detection leading back to the source.

Understanding standard usage patterns is important to avoid a high number of false positives. If VB execution is restricted for normal users, then any attempts to enable related components running on a system would be considered suspicious. If VB execution is not commonly used on a system, but enabled, execution running out of cycle from patching or other administrator functions is suspicious. Payloads and scripts should be captured from the file system when possible to determine their actions and intent.

## Authors

goghoti - 3/28/2022

## References

- https://attack.mitre.org/techniques/T1059/005/
- https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/
- https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf
- https://cdn2.hubspot.net/hubfs/3354902/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty.pdf
- https://www.politoinc.com/post/2017/10/18/the-simplicity-of-vba-malware-part-1-of-2
- https://ieeexplore.ieee.org/abstract/document/9054390
- https://www.sciencedirect.com/science/article/pii/S1877050918317757?via%3Dihub

## Version History

* 0.1
    * Initial Release
