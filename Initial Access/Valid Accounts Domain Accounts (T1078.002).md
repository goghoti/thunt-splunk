# Valid Accounts: Domain Accounts (T1078.002)

Adversaries are known to abuse commonly named/formatted accounts to get access to resources they should not be able to manipulate. Domain accounts held in breaches and publicly available lists are common methods of collection for default user names and passwords.  

## Description

Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as OS Credential Dumping or password reuse, allowing access to privileged resources of the domain.

## Data Required 

- Domain controller/sensitive servers Log on/Log off windows event ids 4624/4625/4627 
- Service Logs for known externally facing assets 
- Logon Session Values/User Auth logs
- Breached user list
- Healthy dose of skepticism (;

### Executing program

Run queries against common/default usernames for 7 days then repeat for following 7 days to compare a baseline of events. 

Baseline of user logon times (use this to measure against for logons during off hours)

```
sourcetype=WinEventLog:Security EventCode=4624
| eventstats avg("_time") AS avg stdev("_time") AS stdev 
| eval lowerBound=(avg-stdev*exact(2)), upperBound=(avg+stdev*exact(2))
| eval isOutlier=if('_time' < lowerBound OR '_time' > upperBound, 1, 0)
| table _time body isOutlier
```

AWS Cloudtrail Impossible Travel (Macro is for curvature of the earth)

```
index=* sourcetype=aws:cloudtrail user=* | sort 0 user, _time | streamstats window=1 current=f values(_time) as last_time values(src) as last_src by user | lookup PrivilegedRiskScores user | where risk_score>0 AND last_src != src AND _time - last_time < 8*60*60 | iplocation last_src | rename lat as last_lat lon as last_lon | eval location = City . "|" . Country . "|" . Region | iplocation last_src | rename lat as last_lat lon as last_lon | eval location = City . "|" . Country . "|" . Region | iplocation src  | eval rlat1 = pi()*last_lat/180, rlat2=pi()*lat/180, rlat = pi()*(lat-last_lat)/180, rlon= pi()*(lon-last_lon)/180 | eval a = sin(rlat/2) * sin(rlat/2) + cos(rlat1) * cos(rlat2) * sin(rlon/2) * sin(rlon/2) | eval c = 2 * atan2(sqrt(a), sqrt(1-a)) | eval distance = 6371 * c, time_difference_hours = round((_time - last_time) / 3600,2), speed=round(distance/ ( time_difference_hours),2) | fields - rlat* a c | eval day=strftime(_time, "%m/%d/%Y") | stats values(accountId) values(awsRegion) values(eventName) values(distance) values(eval(mvappend(last_Country, Country))) as Country values(eval(mvappend(last_City, City))) as City values(eval(mvappend(last_Region, Region))) as Region  values(lat) values(lon)  values(userAgent) max(speed) as max_speed_kph min(time_difference_hours) as min_time_difference_hours by day user distance
```

Generic Impossible Travel Search 

```
| index=x OR index=y OR index=z src_ip!=192.168.* src_ip!=172.* src_ip!=127.0.0.1 src_ip!=*:* user!=*test*
| lookup src_ips.csv src_ip as src_ip outputnew description
| where isnull(description)
| lookup users.csv attr1 as user outputnew email 
| lookup users.csv attr2 as user outputnew email 
| eval src_user='email'
| dedup src_user src_ip index _time
| rex field=_time "(?<dest_time>^\d+)"
| rename src_ip as dest_ip
| sort 0 src_user dest_time
| streamstats values(dest_ip) as src_ip values(dest_time) as src_time by src_user window=1 current=false <the window and current options are KEY here>
| where isnotnull(src_ip) AND (NOT 'src_ip'=='dest_ip')
| `geodistance(src_ip,dest_ip)`
| where mph>575 AND 'src_region'!='dest_region'
| stats values(src_ip) as src_ip values(dest_ip) as dest_ip list(src_city) as src_city list(src_region) as src_region list(src_country) as src_country list(dest_city) as dest_city list(dest_region) as dest_region list(dest_country) as dest_country avg(miles) as miles avg(hours) as hours avg(mph) as mph by src_user
| eval miles=round(miles,2)
| eval km=round(km,2)
| eval hours=round(hours,2)
| eval mph=round(mph,2)
| eval kph=round(kph,2)
| eval src_ip=mvdedup(split((mvjoin((mvzip(src_ip,dest_ip)),",")),","))
| eval src_city=mvdedup(split((mvjoin((mvzip(src_city,dest_city)),",")),","))
| eval src_region=mvdedup(split((mvjoin((mvzip(src_region,dest_region)),",")),","))
| eval src_country=mvdedup(split((mvjoin((mvzip(src_country,dest_country)),",")),","))
| table src_user src_ip src_city src_region src_country miles km hours mph kph
```

Standard Brute Force Rule (Pulled from the splunk blog)

```
index=web_idx sourcetype=web_st (AuthType="AuthReject" OR AuthType="Lockout" OR 
        AuthType="AuthAccept")
2.	| stats count as total_count count(eval(AuthType=="Lockout")) as lockout_count count(eval
        (AuthType=="AuthReject")) as reject_count count(eval(AuthType=="AuthAccept")) 
        as accept_count dc(client_ip) as count_ips by userid
3.	| eval total_denied = lockout_count + reject_count
4.	| eval denied_thresh = 
5.	| search accept_count>0 AND total_denied>denied_thresh 
6.	| eval percent_denied = round((total_denied / total_count) * 100, 2) 
7.	| table userid percent_denied total_count total_denied accept_count lockout_count reject_count 
        count_ips 
8.	| sort 0 - percent_denied total_denied
```

## Help

A table of known users and work locations in your environment is invaluable to detect abuse of known accounts in your domain. 

Queries around use of default or known users are best suited to assets categorized as "crown jewels" or business critical. This will lead you to the low hanging fruit as you get an understanding of the environment.

Detection and analysis of user logons and failures by time or geolocation is the best route to determine outliers/anomalies in account use. Privileged access actions such as additions of rights in group policy or manipulation of rights on a local host can be categorized as suspicious in conjunction with other data points. 

There are many methods for an attacker to gain access to a valid account on a network in this threat hunt we will focus on credential breaches/brute forcing of credentials. 

Identification of a list of users attempting to authenticate to host inside your network can be an indication that your ad environment has been dumped and an actor has access to usernames.  

Identification of breached users can be done at haveibeenpwnd.com. Gather this list of users and measure it against the data in your network a match and a subsequent identifier (odd logon times out of hours, odd geo location logons, abnormal use of privileges/rights) can indicate someone is abusing an account. 

## Authors

goghoti - 4/18/2022

## References

- https://attack.mitre.org/techniques/T1078/002/
- https://capec.mitre.org/data/definitions/70.html
- https://www.eisac.com/public-news-detail?id=115909
- https://www.mandiant.com/resources/apt-groups#apt34
- https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf
- https://www.dragos.com/threat/xenotime/
- https://www.splunk.com/en_us/blog/partners/detecting-brute-force-attacks-with-splunk.html

## Version History

* 0.1
    * Initial Release
