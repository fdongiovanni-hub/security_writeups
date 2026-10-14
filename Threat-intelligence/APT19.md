# APT19 threat intelligence analysis
> APT: organized group, often linked to a state, and attacks in a targeted and sustained manner.

## Overview
ID: G0073, Associated Groups: Codoso, C0d0so0, Codoso Team, Sunshop Group

Origin: China-based. FireEye assesses it as freelancers with some degree of government sponsorship. Some analysts consider it the same group as Deep Panda (G0009), but this is unconfirmed.

Targeted sectors: defense, finance, energy, pharmaceutical, telecommunications, high tech, education, manufacturing, legal services.

Likely motivation: cyber espionage and data theft for economic advantage (inferred by FireEye).

Tools: custom malware (HTTP and Port 22 variants) plus public tools such as Empire (S0363) and Cobalt Strike (S0154).

| Tactic | Technique | Procedure |
| :--- | :--- | :--- |
| Resource Development | T1588.002 Obtain Capabilities: Tool | Obtained and used public tools such as Empire |
| Initial Access | T1566.001 Spearphishing Attachment | Emails with RTF/XLSM attachments containing exploits |
| Initial Access | T1189 Drive-by Compromise | Watering hole attack on forbes.com (2014) |
| Execution | T1059.001 PowerShell | Payload execution |
| Execution | T1204.002 User Execution | Requires the user to open the attachment |
| Persistence | T1547.001 Registry Run Keys | `HKCU\...\Run` key |
| Persistence | T1543.003 Windows Service | "Port 22" variant registered as a service |
| Defense Evasion | T1218.010 / T1218.011 Regsvr32 / Rundll32 | Regsvr32 used to bypass application control; payload injected into rundll32.exe |
| Defense Evasion | T1574.001 DLL Hijacking | Legitimate executable loading a malicious DLL |
| Defense Evasion | T1027 / T1140 / T1564.003 | Base64 and XOR obfuscation; hidden PowerShell windows |
| Discovery | T1082 / T1016 / T1033 | Collection of host, network and user information |
| Command and Control | T1071.001 / T1132.001 | HTTP communications with Base64-encoded data |
> (why, how, how this specific group did it)

## IOCs (Indicators of Compromise) (> 10)


## Vulnerabilities and Exploits


## Recent Campaigns
2017: spearphishing against law and investment firms. Seven firms were targeted with RTF and XLSM attachments delivering exploits. The attackers used PowerShell to run payloads and Regsvr32 to bypass application control. Source: FireEye, "Phished at the Request of Counsel" (June 2017).

Earlier activity: 2014, watering hole osn forbes.com. Source: Palo Alto Unit 42 (2016).

>Note: these are the most recent campaigns documented in the MITRE ATT&CK entry. No newer activity is attributed to APT19 there.

## Attack Surface and Recommendations
