# Multi-hop Proxy (T1090.003)

Adversaries may chain together multiple proxies. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. 

## Description

This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source. A particular variant of this behavior is to use onion routing networks, such as the publicly available TOR network.

Attackers intent:

- Obfuscation of originating ip address to invalidate analysis efforts
- Tunnel traffic via encrypted channels to avoid inspection by network traffic tools 
- Implement custom c2 traffic or protocols towards assets that do not provide context to investigators 

## Data Required 

- Netflow (east -> west)
- Windows Event Logs 4688 (Process Creation)
- Proxy Logs and Reverse Proxy Logs
- DNS Records
- Endpoint Logs 

### Executing program

Identification of wanacry tor service setup rename and url connections on local loopback

```
((index="endpoint_telemetry" OR index="EDR") c_ip="127.0.0.1" c_port="9050" process="taskhsvc.exe*" OR app="tor" AND (url="gx7ekbenv2riucmf.onion" OR url="57g7spgrzlojinas.onion" OR url="xxlvbrloxvriy2c5.onion" OR url="76jdd2ir2embyv47.onion" OR url="cwwnhwhlz52maqm7.onion"))

```

Winevent log msbuild live off the land binary attempt

```
(source="WinEventLog:*" ParentImage="*wmiprvse.exe" Image="*msbuild.exe" CommandLine="*programdata*") 
| table ParentImage,Image,CommandLine
```
New outbound network connections table/dashboard (average flows x standard deviation of average)

```
| tstats sum(Flows) as sum_flows WHERE (index=cidds src_ip="10.0.0.0/8" OR src_ip="172.16.0.0/12" OR src_ip="192.168.0.0/16") BY _time span=5m
| eval HourOfDay=strftime(_time, "%H"), DayOfWeek=strftime(_time, "%A")
| eval Weekday=if(DayOfWeek="Saturday" OR DayOfWeek="Sunday","No","Yes") 
| eventstats avg("sum_flows") as avg_f stdev("sum_flows") as stdev  by "HourOfDay", "Weekday" 
| eval lower_bound=(avg_f-stdev*exact(3)), upper_bound=(avg_f+stdev*exact(3)) 
| eval isOutlier=if('avg' < lowerBound OR 'avg' > upperBound, 1, 0)
| table _time sum_flows lower_bound upper_bound
```

Probability Density of new outbound network connections

```
| tstats sum(Flows) as sum_flows WHERE (index=cidds src_ip="10.0.0.0/8" OR src_ip="172.16.0.0/12" OR src_ip="192.168.0.0/16") BY _time span=5m
| eval HourOfDay=strftime(_time, "%H"), DayOfWeek=strftime(_time, "%A")
| eval Weekday=if(DayOfWeek="Saturday" OR DayOfWeek="Sunday","No","Yes") 
| fit DensityFunction sum_flows by "Weekday,HourOfDay" as outlier into df_192_168_220_15 threshold=0.003
```

TOR table for usage detection

```
index="network" OR index="netflow" sourcetype="firewall_product" AND (app="tor" OR app="TOR") NOT (dst_ip="10.0.0.0/8" OR dst_ip="172.16.0.0/12" OR dst_ip="192.168.0.0/16")  
| table _time, src_ip, src_port, dest_ip, dest_port, bytes, app 
```

Accelerated Tor Query for usage 

```
| tstats summariesonly=t allow_old_summaries=t count sum(All_Traffic.bytes) as All_Traffic.bytes from datamodel=Network_Traffic where All_Traffic.app=tor by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| rename All_Traffic.* as *
| table _time src_ip dest_ip dest_port bytes app
```

## Help

The anonymity of TOR makes it the perfect place for hackers who want to anonymize command and control or network connections. Keying in on obfuscation/privacy based applications can give you a head start on detection of proxy hopping/endpoint hopping. 

Initial construction of a network connection, such as capturing socket information with a source/destination IP and port(s) (ex: Windows EID 5156, Sysmon EID 3, or Zeek conn.log) is valuable to catalog and baseline new connection attempts/abnormalities 

Commonality between malware families using c2 servers

"Dridex and other prevalent malware families such as Emotet and Ursnif. Malicious documents share common indicators when used for the delivery of all the malware mentioned above. Some C2 servers – or to be precise, proxy servers – are used both by Dridex and Emotet, though ports and connection types are different." - from dridex paper 

"Multi-hop proxies can also be detected by alerting on traffic to known anonymity networks (such as Tor) or known adversary infrastructure that uses this technique. In context of network devices, monitor traffic for encrypted communications from the Internet that is addressed to border routers." - from splunk article 

## Authors

goghoti - 3/24/2022

## References

- https://attack.mitre.org/versions/v10/techniques/T1090/003/
- https://attack.mitre.org/versions/v10/tactics/TA0011/
- https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html
- https://research.checkpoint.com/2021/stopping-serial-killer-catching-the-next-strike/
- https://www.secureworks.com/research/wcry-ransomware-analysis
- https://www.splunk.com/en_us/blog/it/understanding-and-baselining-network-behaviour-using-machine-learning-part-ii.html

## Version History

* 0.1
    * Initial Release