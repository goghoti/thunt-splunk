# Data Encoding: Standard Encoding (T1132.001) 

Multiple methods of encoding commands & traffic are present in toolkits used by adversaries to obfuscate the true intention of actions taken on an endpoint. Standard encoding types such as base64 and XOR are common because they are used in normal operations and can potentially blend into the noise in logs. 

## Description

Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME. Some data encoding systems may also result in data compression, such as gzip.

## Data Required 

- Process Creation Logs (4688)
- Endpoint logging
- EDR Process Info (Cross proc is valuable here)
- DNS Query info 

### Executing program

Network Traffic with .ps1 domains

```
index=* sourcetype=stream:http
| where like(uri, "%.ps1")
| rex field=uri "\/(?<script_name>[^\/]+(?=$))"
| eval dest_content=substr(dest_content,1,100)
| stats VALUES(dest_content) VALUES(uri) by dest_ip
```

Script interpreter executing Base64 string 

```
index=* EventCode=4688
| rex field=Process_Command_Line "-((?i)enc|encodedcommand|encode|en)\s\'?(?<base64_command>\w{20,1000}\=?\=?)\'?"
| decrypt field=base64_command atob()
emit('base64_decoded_command')
| stats count by base64_decoded_command
```

Encoded DNS traffic (High FP Rate DNS sucks and always will)

```
sourcetype="dns" (message_type=RESPONSE OR message_type=TXT) | rex field=query "(?<subdomain>.*?)\..*" | regex subdomain="^(([A-Za-z0-9+/]{4})+)$|^([A-Za-z0-9+/]{4})+(([A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)|([A-Za-z0-9+/][AQgw]==)).*$" | stats count by subdomain
```

## Help

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

Regex Pattern for Base64:
/^(?:[A-Za-z\d+/]{4})*(?:[A-Za-z\d+/]{3}=|[A-Za-z\d+/]{2}==)?$/

Powershell/script interpreters are commonalty used along with base64 and are a good starting place for process based encoding 

Examine DNS query fields of the dns events to find subdomain streams that contain only Base64 valid characters.

Automated testing of these rules and other scenarios can be done via Atomic red team. 

## Authors

goghoti - 3/25/2022

## References

- https://attack.mitre.org/techniques/T1132/001/
- https://attack.mitre.org/techniques/T1059/
- https://unit42.paloaltonetworks.com/new-attacks-linked-to-c0d0s0-group/
- https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
- https://www.splunk.com/en_us/blog/tips-and-tricks/hellsbells-lets-hunt-powershells.html
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md

## Version History

* 0.1
    * Initial Release
