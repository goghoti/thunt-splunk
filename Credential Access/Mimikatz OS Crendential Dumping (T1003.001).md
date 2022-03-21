# Mimikatz OS Crendential Dumping (T1003.001) 

Advesaries are known to use mimikatz tools on victims to dump LSASS process memeory and gather OS credentials.  

## Description

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material.

## Data Required 

- LSASS Process logs
- Endpoing telemetry
- Windows Event Logs 4688 (Process Creation)
- File integrity monitoring 

### Executing program

Running queries agaisnt domain controllers behind DMZ for 7 days then repeat for following seven days to compare a baseline of events. 

Finds 

```
index="windowseventlog" sourcetype=`powershell*` EventCode=4104 Message IN (*mimikatz*, *-dumpcr*, *sekurlsa::pth*, *kerberos::ptt*, *kerberos::golden*) 
| stats count min(_time) as firstTime max(_time) as lastTime by OpCode ComputerName User EventCode Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_mimikatz_with_powershell`
```

Query used for gathering a baseline of lsass operations in the network

```
index="windowseventlog" parent_process="lsass*" EventCode="4688" | stats count by user 
```

Indicates presence of lsass dmp file creation in the temp directory

```
index="filemod" OR index="FIM" commandline="C:\Users\*\AppData\Local\Temp\lsass.DMP*"
```

## Help

The SSP configuration is stored in two Registry keys: 
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages 
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages

SSP Credential Access:
Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.
Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
CredSSP: Provides SSO and Network Level Authentication for Remote Desktop Services.

Common credential dumpers such as Mimikatz access LSASS.exe by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details are stored.

On Windows 8.1 and Windows Server 2012 R2, monitor Windows Logs for LSASS.exe creation to verify that LSASS started as a protected process.

## Authors

goghoti - 3/21/2022

## References

- https://attack.mitre.org/techniques/T1003/001/
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-credentials-from-lsass.exe-process-memory
- https://www.youtube.com/watch?v=wH2kE527cwQ
- https://adsecurity.org/?p=1729
- https://pentestlab.blog/2013/03/25/dumping-clear-text-credentials-with-mimikatz/
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/windows-powershell.log

## Version History

* 0.1
    * Initial Release