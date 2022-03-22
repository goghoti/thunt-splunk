# ProxyShell Webshell (T1505.003).

Adversaries are known to exploit CVE's (CVE-2021-26855, 26858, 27065, 26857) and deploy webshells to Microsoft Exchange one of the most common mail servers in production environments. Threat intelligence has shown use of these webshells to gain a foothold in OWA services. 

## Description

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server 

Attackers intent:

- gain access to confidential information in corporate emails
- launch a malicious mailing from the victim company’s addresses to infiltrate the infrastructure of another organization
- compromise user accounts with the use of Exchange components (successful bruteforce attack or detection of credentials in email correspondence) to infiltrate the company’s network via one of the corporate services
- gain foothold into the company network (e.g. by using a web shell on the OWA service)
- escalate privileges in the domain by using the Exchange server
- disable the Exchange server in order to disrupt internal business processes (e.g. by fully encrypting server data)

## Data Required 

- Endpoint process telemetry (EDR)
- Windows Event Logs 4688 (Process Creation)
- Proxy (bluecoat, zscaler, etc)
- Powershell windows events (4104)

### Executing program

Identification of exchange powershell module use

```
index="wineventlog" sourcetype="powershell*" EventCode=4104 Message IN ("*New-MailboxExportRequest*", "*New-ManagementRoleAssignment*") 
```

Identification of suspicious aspx files created in known proxyshell locations

```
index="EDR" sourcetype="process*" | search ("*\\HttpProxy\\owa\\auth\\*" OR "*\\inetpub\\wwwroot\\aspnet_client\\*" OR "*\\HttpProxy\\OAB\\*") AND file_name="*.aspx" 
```

New-ExchangeCertificate cmdlet creation of a web shell for target mailbox 

```
(index="EDR" OR (index="wineventlog" EventCode="4104") (c_process_cmdline="New-ExchangeCertificate" AND c_process_cmdline="-GenerateRequest" AND c_process_cmdline="-RequestFile" c_process_cmdline="\Program Files\Exchange Server\" AND c_process_cmdline="\FrontEnd\HttpProxy\owa\auth\" AND c_process_cmdline=".aspx" AND c_process_cmdline="SubjectName" AND c_process_cmdline="-BinaryEncoded" AND c_process_cmdline="-DomainName"))
```

Detection taken from: https://www.socinvestigation.com/proxyshell-vulnerability-large-exploitation-of-microsoft-exchange-servers/

```
((c-uri="*/autodiscover.json*" (c-uri="*/powershell*" OR c-uri="*/mapi/nspi*" OR c-uri="*/EWS*" OR c-uri="*X-Rps-CAT*")) OR (c-uri="*autodiscover.json?@*" OR c-uri="*autodiscover.json%3f@*" OR c-uri="*%3f@foo.com*" OR c-uri="*Email=autodiscover/autodiscover.json*" OR c-uri="*json?@foo.com*"))
```

Query to identify use of embedded urls for proxyshell by SquirrelWaffle actor (IOC Check may be out of date/rotated)

```
index="proxy" direction="outbound" policy="DMZ" (responsecode!="4*" OR "5*") AND (url="headlinepost.net" OR url="dongarza.com" OR url="taketuitions.com" OR url="constructorachg.cl" OR url="oel.tg" OR  url="imprimija.com.br" OR  url="stunningmax.com" OR  url="decinfo.com.br" OR  url="omoaye.com.br" OR  url="mcdreamconcept.ng" OR  url="agoryum.com" OR  url="arancal.com" OR  url="iperdesk.com" OR  url="grandthum.co.in")
```

## Help

Identifiers in logs:

zipFilter = ".7z", ".zip", ".rar"
dmpFilter = "lsass.*dmp"
dmpPaths = "c:\root", "$env:WINDIR\temp"
Oabgen = "$exchangePath\Logging\OABGeneratorLog" 
Ecp = "$exchangePath\Logging\ECP\Server\*.log" 
 AutodProxy = "$exchangePath\Logging\HttpProxy\Autodiscover" 
EasProxy = "$exchangePath\Logging\HttpProxy\Eas" 
EcpProxy = "$exchangePath\Logging\HttpProxy\Ecp" 
EwsProxy = "$exchangePath\Logging\HttpProxy\Ews" 
MapiProxy = "$exchangePath\Logging\HttpProxy\Mapi" 
OabProxy = "$exchangePath\Logging\HttpProxy\Oab" 
OwaProxy = "$exchangePath\Logging\HttpProxy\Owa" 
OwaCalendarProxy = "$exchangePath\Logging\HttpProxy\OwaCalendar" 
PowershellProxy = "$exchangePath\Logging\HttpProxy\PowerShell" 
RpcHttpProxy = "$exchangePath\Logging\HttpProxy\RpcHttp" 

Registry Key location validate file modifications have not occurred at this location:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup 

Here are the configuration files you should check:

C:\Windows\System32\inetsrv\Config\applicationHost.config
C:\inetpub\temp\apppools\MSExchangeECPAppPool\MSExchangeECPAppPool.config

Recommended solution: Install the security patch

This method is the only complete mitigation and has no impact to functionality.
The following has details on how to install the security update: https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2021-exchange-server-security-updates/ba-p/2175901
This will not evict an adversary who has already compromised a server.

Interim mitigation's if unable to patch Exchange Server 2013, 2016, and 2019:

Implement an IIS Re-Write Rule to filter malicious https requests
Disable Unified Messaging (UM)
Disable Exchange Control Panel (ECP) VDir
Disable Offline Address Book (OAB) VDir

Check the local Exchange server only and save the report:
.\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs

Check the local Exchange server, copy the files and folders to the outpath\<ComputerName>\ path
.\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs -CollectFiles

Check all Exchange servers and save the reports:
Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs

Check all Exchange servers, but only display the results, don't save them:
Get-ExchangeServer | .\Test-ProxyLogon.ps1 -DisplayOnly

## Authors

goghoti - 3/22/2022

## References

- https://www.digitalshadows.com/blog-and-research/microsoft-exchange-server-exploit-what-happened-next/
- https://cyberpolygon.com/materials/okhota-na-ataki-ms-exchange-chast-1-proxylogon/
- https://attack.mitre.org/techniques/T1505/003/
- https://github.com/praetorian-inc/proxylogon-exploit
- https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html
- https://www.justice.gov/usao-sdtx/pr/justice-department-announces-court-authorized-effort-disrupt-exploitation-microsoft
- https://github.com/microsoft/CSS-Exchange/tree/main/Security
- https://www.trendmicro.com/content/dam/trendmicro/global/en/research/21/k/squirrelwaffle-exploits-proxyshell-and-proxylogon-vulnerabilities-in-microsoft-exchange-to-hijack-email-chains/IOCs-squirrelwaffle-exploits-proxyshell-and-proxylogon-microsoft-exchange-vulnerabilities-to-hijack-email-chains.txt
- https://research.splunk.com/stories/proxyshell/

## Version History

* 0.1
    * Initial Release