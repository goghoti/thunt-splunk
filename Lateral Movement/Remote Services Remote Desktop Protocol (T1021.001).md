# Remote Services: Remote Desktop Protocol (T1021.001)

RDP exposure to the internet continues to be a prevalent route for initial compromise for all industries. Use of RDP in an environment can be legitimate causing noise and monitoring of RDP authentication and usage to be important for detection and response. 

## Description

Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the Accessibility Features technique for Persistence.

## Data Required 

- Terminal Services Logs (EventID 1149, 4624, 4625, 21) - If 1149 event is found, it doesn’t mean that user authentication has been successful. 
    Network Connection
    Authentication
    Logon
    Session Disconnect/Reconnect
    Logoff
- Network share cmdline params (Second step after rdp exploit)

### Executing program

CAR-2016-04-005: Remote Desktop Logon

```
index="wineventlog" sourcetype="security" EventCode="4624" (LogonType="10" AND sev="Information*" AND Auth="Negotiate*")
```

CAR-2013-07-002: RDP Connection Detection

```
index="netflow" sourcetype="connections" (src_port="3389" OR dst_port="3389")
| stats count flow_start, flow_end by src_ip, dst_ip, src_port, dst_port  
```

Changing RDP Port to Non Standard Port via registry 

```
index="EDR" OR index="process" process="regmod.exe" filemod_cmdline="HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp*" AND regmod="0"  
```

Changing RDP Port to Non Standard Port via Powershell

```
index="EDR" OR index="process" process="powershell.exe" cmdline="Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name PortNumber -Value*"
```

Changing RDP Port to Non Standard Port via Command Prompt 

```
index="EDR" OR index="process" process="cmd.exe" cmdline="reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d" 
```

RDP Connections by user

```
source="WinEventLog:Security" EventCode=4624 OR EventCode=4634  Account_Name=*  action=success NOT | eval User=if(mvcount(Account_Name)>1, mvindex(Account_Name,1), mvindex(Account_Name, 0))    | eval User=lower(User) | search NOT User=*$ | transaction User maxevents=2 startswith="EventCode=4624" endswith="EventCode=4634" maxspan=-1   | stats  sum(duration) As Duration by User, ComputerName, Source_Network_Address   | eval  Duration(M)=round((Duration/60), 0)    | table  User,Source_Network_Address,Duration(M),ComputerName
```

Network Traffic Baseline for RDP

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_port=3389 AND All_Traffic.dest_category!=common_rdp_destination AND All_Traffic.src_category!=common_rdp_source by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name("All_Traffic")` | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` | `remote_desktop_network_traffic_filter` 
```

RDP Access Timeline 

```
index=main source="wineventlog:microsoft-windows-terminalservices-localsessionmanager/operational" NOT Message="*arbitration*" NOT Message="Session *" host="<your-host-here>"
| eval Message = replace(Message,"[\n\r]+", " ")
| eval userstring = mvindex(User, -1)
| eval Domain = mvindex(split(userstring,"\\"),0)
| eval Domain=mvfilter(NOT match(Domain,"NOT_TRANSLATED") )
| eval User = mvindex(split(userstring,"\\"),1)
| transaction Session_ID, User, Source_Network_Address startswith=( ( Message="*logon succeeded*") OR (Message="*reconnection succeeded*") ) endswith=( ( Message="*logoff succeeded*") OR (Message="*Session has been disconnected*") )
| eval start_time = strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval end_time = strftime(_time+duration, "%Y-%m-%d %H:%M:%S")
| table start_time, end_time, Session_ID, Domain, User, Source_Network_Address, duration
| rename Session_ID as "Session ID", Source_Network_Address as "Source Address", duration as "Duration", start_time as "Start Time", end_time as "End Time"
```

## Help

This pattern of attack involves an adversary that uses stolen credentials to leverage remote services such as RDP, telnet, SSH, and VNC to log into a system. Once access is gained, any number of malicious activities could be performed.

Monitor for the behavior that RDP exhibits on the endpoints. The most relevant is leveraging taskmgr.exe to gain elevated execution, which means that taskmgr.exe is creating unexpected child processes.

Mitigation: Disable RDP, telnet, SSH and enable firewall rules to block such traffic. Limit users and accounts that have remote interactive login access. Remove the Local Administrators group from the list of groups allowed to login through RDP. Limit remote user permissions. Use remote desktop gateways and MFA authentication for remote logins.

Pay attention to the LogonType value in the event description.

LogonType = 10 or 3 — if the Remote Desktop service has been used to create a new session during log on;
LogonType = 7, means that a user has reconnected to the existing RDP session;
LogonType = 5 – RDP connection to the server console (in the mstsc.exe /admin mode).

"The Axiom threat actor group has also demonstrated the operational flexibility of leveraging
systems administration tools available within targeted organizations (e.g., Remote Desktop
Protocol (RDP), remote administration tools). It has been observed several times that Axiom
operators have even leveraged these capabilities as a means of maintaining additional
persistence via setting “sticky keys” for RDP sessions." - Novetta Axiom Report

The Carbanak backdoor enables concurrent RDP sessions on endpoints it has infected. - Manident report on Carbanak

Cobalt group uses rdp to connect to another computer, copy the module, and run it; delete the module. - GroupIB Report

Atomic Red team @ https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md can be used to mimic this activity for detection testing 


## Authors

goghoti - 3/27/2022

## References

- https://attack.mitre.org/techniques/T1021/001/
- https://capec.mitre.org/data/definitions/555.html
- https://car.mitre.org/analytics/CAR-2016-04-005/
- https://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf
- https://www.mandiant.com/resources/behind-the-carbanak-backdoor
- https://blog.group-ib.com/cobalt
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md
- https://www.13cubed.com/downloads/rdp_flowchart.pdf
- https://docs.splunksecurityessentials.com/content-detail/remote_desktop_network_traffic/

## Version History

* 0.1
    * Initial Release
