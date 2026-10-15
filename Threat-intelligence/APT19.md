# APT19 threat intelligence analysis
> APT (Advanced Persistent Threat): an organized group, often linked to a state, that attacks in a targeted and sustained manner.

## Overview
ID: G0073, Associated Groups: Codoso, C0d0so0, Codoso Team, Sunshop Group

Origin: China-based. FireEye assesses it as freelancers with some degree of government sponsorship. Some analysts consider it the same group as Deep Panda (G0009), but this is unconfirmed.

Targeted sectors: defense, finance, energy, pharmaceutical, telecommunications, high tech, education, manufacturing, legal services.

Likely motivation: cyber espionage and data theft for economic advantage (based on FireEye's previous observations of APT19 stealing data from law and investment firms).

Tools: custom malware (HTTP and Port 22 variants) plus public tools such as Empire (S0363) and Cobalt Strike (S0154).

Sources: [1], [6]

## TTPs (Tactics, Techniques, Procedures)
> Tactic = why (the attacker's goal); Technique = how; Procedure = how this specific group did it. Source: [6]

| Tactic | Technique | Procedure |
| :--- | :--- | :--- |
| Resource Development | T1588.002 Obtain Capabilities: Tool | Obtained and used public tools such as Empire |
| Initial Access | T1566.001 Spearphishing Attachment | Emails with RTF/XLSM attachments containing exploits |
| Initial Access | T1189 Drive-by Compromise | Watering hole attack on forbes.com (2014) |
| Execution | T1059.001 PowerShell | Payload execution |
| Execution | T1059 Command and Scripting Interpreter | Downloaded and launched code within an SCT file |
| Execution | T1204.002 User Execution | Requires the user to open the attachment |
| Persistence | T1547.001 Registry Run Keys | HTTP variant sets a `HKCU\...\Run` key |
| Persistence | T1543.003 Windows Service | "Port 22" variant registered as a service |
| Defense Evasion | T1218.010 / T1218.011 Regsvr32 / Rundll32 | Regsvr32 used to bypass application control; payload injected into rundll32.exe |
| Defense Evasion | T1574.001 Hijack Execution Flow: DLL | Legitimate executable loading a malicious DLL |
| Defense Evasion | T1027.010 Command Obfuscation / T1027.013 Encrypted/Encoded File | Base64 used to obfuscate commands and payloads |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | HTTP variant decrypts strings with single-byte XOR keys |
| Defense Evasion | T1564.003 Hidden Window | PowerShell run with `-W Hidden` |
| Defense Evasion | T1112 Modify Registry | Port 22 variant modifies several Registry keys |
| Discovery | T1082 System Information Discovery / T1016 System Network Configuration Discovery / T1033 System Owner/User Discovery | Collection of host (hostname, CPU, architecture), network (MAC and IP address) and user information |
| Command and Control | T1071.001 Web Protocols / T1132.001 Standard Encoding | HTTP communications with Base64-encoded data |

## IOCs (Indicators of Compromise)
> Traces left by an attack. Companies take a group's list of IOCs and check whether any of those traces appear on their computers or networks.

| # | Type | Value | Context | Source |
|---|---|---|---|---|
| 1 | Domain | `autodiscover[.]2bunny[.]com` | Cobalt Strike C2 | [1] |
| 2 | Domain | `lyncdiscover[.]2bunny[.]com` | Hosts the script loaded via Regsvr32 | [1] |
| 3 | Domain | `tk-in-f156[.]2bunny[.]com` | File (Agreement.doc) downloaded by the RTF attachments | [1] |
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

<!--
C2 server (Command and Control): gives orders to the malware
Cobalt Strike: tool to control a computer remotely
The XLSM macro starts PowerShell, which downloads the Cobalt Strike BEACON; the BEACON then contacts the C2 server
MD5 and SHA-256: file fingerprints
-->

> note: values are defanged (`[.]`) so they cannot be clicked by mistake. Most domains and IPs date from 2015–2017 and are probably no longer active; the hashes are still valid for identifying the files.
> note: checked on VirusTotal on 15 October 2026: the IP `121[.]54[.]168[.]230` is flagged as malicious by 1 of 95 vendors and does not respond to a connection (error), so it appears to be inactive today.

## Vulnerabilities and Exploits

| CVE | Product | How it was used | Source |
|---|---|---|---|
| CVE-2017-0199 | Microsoft Office / WordPad | Patched by Microsoft in April 2017, but still exploited in May–June 2017 against systems that had not yet installed the update | [1], [5] |
| CVE-2014-9163 | Adobe Flash Player | Zero-day used in the 2014 Forbes.com watering hole | [4], [5] |
| CVE-2015-0071 | Internet Explorer 9–11 | Second zero-day, used with the Flash exploit to bypass ASLR | [4], [5] |

<!--
CVE-year-number identifies a security flaw
zero-day: the vendor didn't know about that flaw
-->

> note: all three CVEs are listed in CISA's Known Exploited Vulnerabilities catalog [5].

## Recent Campaigns

- **2017: spearphishing against law firms.** At least seven law and investment firms were targeted in May–June with RTF and XLSM attachments (PowerShell, Regsvr32). FireEye later told CyberScoop about further waves against law firms until December 2017. Sources: [1], [3].
- **2015–2016: C0d0so0 attacks.** Telecom, high-tech, education, manufacturing and legal targets, with two custom malware variants (HTTP and port 22). Source: [2].
- **2014: Forbes.com watering hole.** Between 28 November and 1 December 2014, visitors from defense and financial companies were targeted via the Flash widget. Source: [4].

> note: 2017 is the most recent activity attributed to APT19 that I found in reliable sources.

## Attack Surface and Recommendations

| TTP | Attack surface | Mitigation |
|---|---|---|
| Spearphishing attachment | Email, Office users | Email attachment scanning, antivirus, SPF/DKIM/DMARC, user training (M1031, M1049, M1054, M1017); install the Microsoft update for CVE-2017-0199 |
| Unpatched software | Office, Windows, browsers | Install security updates quickly (patch management)*; prioritise flaws already exploited in real attacks, such as those in CISA's Known Exploited Vulnerabilities catalog |
| Drive-by compromise | Web browser and plugins (Flash, IE) | Keep browsers and plugins updated (M1051), exploit protection (M1050), browser sandboxing (M1048), remove Flash* |
| PowerShell | Windows endpoints | Restrict or disable PowerShell, allow only signed scripts, application control (M1042, M1045, M1038) |
| Regsvr32 / Rundll32 | Windows endpoints | Exploit Protection / ASR rules (M1050); monitor Regsvr32 command lines |
| DLL hijacking, Run keys, services | Application folders, registry | Restrict write permissions*, monitor Run keys and new services* |
| HTTP / port 22 C2 | Network egress | Egress filtering*, network intrusion prevention (M1031), restrict outbound port 22* |

> note: mitigations marked * are my own suggestions based on the technique, or on [1] and CISA. Those with an M-code come from the "Mitigations" section of the corresponding MITRE ATT&CK technique page.

## References

1. Mandiant/FireEye, "Privileges and Credentials: Phished at the Request of Counsel", 6 June 2017. Archived copy (20 July 2017): https://web.archive.org/web/20170720172836/https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html. Original URL: https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html
2. Palo Alto Networks Unit 42, "New Attacks Linked to C0d0so0 Group", 22 January 2016. https://unit42.paloaltonetworks.com/new-attacks-linked-to-c0d0s0-group/
3. CyberScoop, "Roy Moore scandal used for phishing schemes aimed at U.S. law firms", 4 December 2017. https://cyberscoop.com/roy-moore-scandal-phishing-attacks-apt19-fireeye-harvey-weinstein/
4. Security Affairs, "Chinese hackers hit Forbes visitors with zero-day exploits", 12 February 2015. https://securityaffairs.com/33417/cyber-crime/chinese-hackers-hit-forbes.html
5. NVD (accessed 15 October 2026): CVE-2017-0199 https://nvd.nist.gov/vuln/detail/CVE-2017-0199, CVE-2014-9163 https://nvd.nist.gov/vuln/detail/CVE-2014-9163, CVE-2015-0071 https://nvd.nist.gov/vuln/detail/CVE-2015-0071
6. MITRE ATT&CK (accessed 15 October 2026): APT19 (G0073) https://attack.mitre.org/groups/G0073/; technique pages https://attack.mitre.org/techniques/T1566/001/, https://attack.mitre.org/techniques/T1189/, https://attack.mitre.org/techniques/T1059/001/, https://attack.mitre.org/techniques/T1218/010/