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

## IOCs (Indicators of Compromise)

| # | Type | Value | Context | Source |
|---|---|---|---|---|
| 1 | Domain | `autodiscover[.]2bunny[.]com` | Cobalt Strike C2 | [1] |
| 2 | Domain | `lyncdiscover[.]2bunny[.]com` | Hosts the script loaded via Regsvr32 | [1] |
| 3 | Domain | `tk-in-f156[.]2bunny[.]com` | Hosts the RTF lure document | [1] |
| 4 | Domain | `sfo02s01-in-f2[.]cloudsend[.]net` | Cobalt Strike C2 | [1] |
| 5 | MD5 | `0bef39d0e10b1edfe77617f494d733a8` | RTF attachment | [1] |
| 6 | MD5 | `30f149479c02b741e897cdb9ecd22da7` | Malicious XLSM | [1] |
| 7 | MD5 | `38125a991efc6ab02f7134db0ebe21b6` | Malicious XLSM (PowerShell macro) | [1] |
| 8 | Domain | `supermanbox[.]org` | C2 of the Port 22 variant | [2] |
| 9 | Domain | `jbossas[.]org` | C2 of the Port 22 variant | [2] |
| 10 | Domain | `microsoft-cache[.]com` | C2 of the HTTP variant | [2] |
| 11 | IP | `121[.]54[.]168[.]230` | Hong Kong IP behind the three C2 domains above | [2] |
| 12 | SHA-256 | `3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa` | Port 22 variant DLL | [2] |
| 13 | SHA-256 | `b690394540cab9b7f8cc6c98fd95b4522b84d1a5203b19c4974b58829889da4c` | HTTP variant DLL | [2] |

> Note: values are defanged (`[.]`) so they cannot be clicked by mistake. Most domains and IPs date from 2015–2017 and are probably no longer active; the hashes are still valid for identifying the files.

## Vulnerabilities and Exploits

| CVE | Product | How it was used | Source |
|---|---|---|---|
| CVE-2017-0199 | Microsoft Office / WordPad | RTF attachments in the May 2017 phishing campaign downloaded a remote file and ran code | [1], [5] |
| CVE-2014-9163 | Adobe Flash Player | Zero-day used in the 2014 Forbes.com watering hole | [4], [5] |
| CVE-2015-0071 | Internet Explorer 9+ | Second zero-day, used with the Flash exploit to bypass ASLR | [4] |

> Note: the Mandiant post contains a typo ("CVE-2017-1099") in the RTF section, while its summary says CVE-2017-0199, which is the correct one.
> Note: CVE-2015-0071 is documented here only by press coverage of iSIGHT research; check it on NVD.

## Recent Campaigns

- **2017: spearphishing against law firms.** Seven law and investment firms were targeted in May–June with RTF and XLSM attachments (PowerShell, Regsvr32). FireEye later reported further waves against law firms until December 2017. Sources: [1], [3].
- **2015–2016: C0d0so0 attacks.** Telecom, high-tech, education, manufacturing and legal targets, with two custom malware variants (HTTP and port 22). Source: [2].
- **2014: Forbes.com watering hole.** Visitors from defense and financial companies were infected via the Flash widget. Source: [4].

> Note: 2017 is the most recent activity I could attribute to APT19 in reliable sources.

## Attack Surface and Recommendations

| TTP | Attack surface | Mitigation |
|---|---|---|
| Spearphishing attachment | Email, Office users | Email attachment scanning, antivirus, SPF/DKIM/DMARC, user training (M1031, M1049, M1054, M1017); patch CVE-2017-0199 |
| Drive-by compromise | Web browser and plugins (Flash, IE) | Keep software updated, exploit protection (M1050), remove Flash† |
| PowerShell | Windows endpoints | Restrict or disable PowerShell, allow only signed scripts, application control (M1042, M1045, M1038) |
| Regsvr32 / Rundll32 | Windows endpoints | Exploit Protection / ASR rules (M1050); monitor Regsvr32 command lines |
| DLL hijacking, Run keys, services | Application folders, registry | Restrict write permissions, monitor Run keys and new services† |
| HTTP / port 22 C2 | Network egress | Egress filtering, network intrusion prevention (M1031), restrict outbound port 22† |

> Note: mitigations marked † are my own suggestions based on the technique, not copied from the MITRE page. The others come from each technique's "Mitigations" section on MITRE ATT&CK.

## References

1. Mandiant/FireEye, "Privileges and Credentials: Phished at the Request of Counsel", 6 June 2017. https://cloud.google.com/blog/topics/threat-intelligence/phished-at-the-request-of-counsel (original: https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html)
2. Palo Alto Networks Unit 42, "New Attacks Linked to C0d0so0 Group", 22 January 2016. https://unit42.paloaltonetworks.com/new-attacks-linked-to-c0d0s0-group/
3. CyberScoop, "Roy Moore scandal used for phishing schemes aimed at U.S. law firms", 4 December 2017. https://cyberscoop.com/roy-moore-scandal-phishing-attacks-apt19-fireeye-harvey-weinstein/
4. Security Affairs, "Chinese hackers hit Forbes visitors with zero-day exploits", 12 February 2015. https://securityaffairs.com/33417/cyber-crime/chinese-hackers-hit-forbes.html
5. NVD, CVE-2017-0199 and CVE-2014-9163. https://nvd.nist.gov/vuln/detail/CVE-2017-0199 and https://nvd.nist.gov/vuln/detail/CVE-2014-9163
6. MITRE ATT&CK, APT19 (G0073) and technique pages T1566.001, T1059.001, T1218.010. https://attack.mitre.org/groups/G0073/