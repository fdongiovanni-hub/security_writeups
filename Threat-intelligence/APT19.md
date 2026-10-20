# Request for Information (RFI): Analysis of APT19

**To:** CStechnologies, requesting team
**From:** Agent Federico Dongiovanni
**Date:** 13 October 2026
**Subject:** Request for Intelligence on APT19
**Classification:** TLP:RED (inherited from the RFI)

## Key Information Request

### Overview of APT19
- **Identity:** MITRE ID G0073. Also known as Codoso, C0d0so0, Codoso Team and Sunshop Group. Some analysts consider it the same group as Deep Panda (G0009), but this is unconfirmed.
- **Recent activities:** the latest activity documented in reliable sources is the 2017 phishing of law and investment firms (see Recent Campaigns). I found nothing newer attributed to APT19.
- **Motivations:** espionage and theft of data for economic advantage. FireEye had previously seen APT19 steal data from law and investment firms for competitive economic purposes. Targeted sectors: defense, finance, energy, pharmaceutical, telecommunications, high tech, education, manufacturing, legal services.
- **Attribution (my assessment):** China-based origin: **medium** (MITRE, FireEye). Government sponsorship: **low** (FireEye assesses freelancers with some degree of sponsorship; no public proof). Same group as Deep Panda: **low**.

### Tactics, Techniques, and Procedures (TTPs)
Source: MITRE ATT&CK [6].

| Tactic | Technique | Procedure |
| :--- | :--- | :--- |
| Resource Development | T1588.002 Obtain Capabilities: Tool | Obtained and used public tools such as Empire |
| Initial Access | T1566.001 Spearphishing Attachment | Emails with RTF/XLSM attachments containing exploits |
| Initial Access | T1189 Drive-by Compromise | Watering hole attack on forbes.com (2014) |
| Execution | T1059.001 PowerShell / T1059 Command and Scripting Interpreter | Payload execution; code downloaded and launched from an SCT file |
| Execution | T1204.002 User Execution | Requires the user to open the attachment |
| Persistence | T1547.001 Registry Run Keys / T1543.003 Windows Service | HTTP variant sets a `HKCU\...\Run` key; "Port 22" variant registers as a service |
| Defense Evasion | T1218.010 / T1218.011 Regsvr32 / Rundll32 | Regsvr32 bypasses application control; payload injected into rundll32.exe |
| Defense Evasion | T1574.001 Hijack Execution Flow: DLL | Legitimate executable loading a malicious DLL |
| Defense Evasion | T1027.010 / T1027.013 / T1140 | Base64 obfuscation; HTTP variant decrypts strings with single-byte XOR keys |
| Defense Evasion | T1564.003 Hidden Window / T1112 Modify Registry | PowerShell run with `-W Hidden`; Port 22 variant modifies Registry keys |
| Discovery | T1082 / T1016 / T1033 | Host (hostname, CPU), network (MAC, IP) and user information |
| Command and Control | T1071.001 Web Protocols / T1132.001 Standard Encoding | HTTP communications with Base64-encoded data |

<!--
Tactic = why (goal); Technique = how; Procedure = how this group did it.
Regsvr32/Rundll32/PowerShell are legitimate Windows tools abused by attackers (LOLBins).
Base64 is an encoding, not encryption. XOR is a simple cipher.
-->

**How the techniques are evolving:** in 2017 the group changed its lures within weeks: RTF files exploiting CVE-2017-0199 (early May), then macro-enabled Excel files, then a Regsvr32 application-whitelisting bypass [1]. In 2014 it used a watering hole with two browser zero-days [4]. No new methods are documented after 2017. The pattern to watch is abuse of Windows tools and public frameworks (Cobalt Strike, Empire).

### Indicators of Compromise (IOCs)

| # | Type | Value | Context | Source |
|---|---|---|---|---|
| 1 | Domain | `autodiscover[.]2bunny[.]com` | Cobalt Strike C2 | [1] |
| 2 | Domain | `lyncdiscover[.]2bunny[.]com` | Hosts the script loaded via Regsvr32 | [1] |
| 3 | Domain | `tk-in-f156[.]2bunny[.]com` | File (Agreement.doc) downloaded by the RTF attachments | [1] |
| 4 | Domain | `sfo02s01-in-f2[.]cloudsend[.]net` | Cobalt Strike C2 | [1] |
| 5 | MD5 | `0bef39d0e10b1edfe77617f494d733a8` | RTF attachment | [1] |
| 6 | MD5 | `30f149479c02b741e897cdb9ecd22da7` | Malicious XLSM | [1] |
| 7 | Domain | `supermanbox[.]org` | C2 of the Port 22 variant | [2] |
| 8 | Domain | `jbossas[.]org` | C2 of the Port 22 variant | [2] |
| 9 | Domain | `microsoft-cache[.]com` | C2 of the HTTP variant | [2] |
| 10 | IP | `121[.]54[.]168[.]230` | Hong Kong IP behind the three C2 domains above | [2] |
| 11 | SHA-256 | `3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa` | Port 22 variant DLL | [2] |
| 12 | SHA-256 | `b690394540cab9b7f8cc6c98fd95b4522b84d1a5203b19c4974b58829889da4c` | HTTP variant DLL | [2] |

> note: values are defanged (`[.]`). Most domains and IPs date from 2015–2017 and are probably no longer active. Checked on VirusTotal on 15 October 2026: the IP `121[.]54[.]168[.]230` is flagged by 1 of 95 vendors and does not respond (error), so it appears to be inactive today.

**IOCs to integrate immediately:** (1) the file hashes (rows 5, 6, 11, 12) for retro-hunting in endpoint and email logs; (2) behavior rules: `regsvr32.exe` with `/i:<URL>` and `scrobj.dll`, and PowerShell with `-W Hidden`; (3) the Run value `Windows Debug Tools` (HTTP variant) [2]. Use domains and IPs to search old logs, not as blocking rules.

### Vulnerabilities and Exploits

| CVE | Product | How it was used | Source |
|---|---|---|---|
| CVE-2017-0199 | Microsoft Office / WordPad | Patched in April 2017, but exploited in May–June 2017 against systems that had not installed the update | [1], [5] |
| CVE-2014-9163 | Adobe Flash Player | Zero-day used in the 2014 Forbes.com watering hole | [4], [5] |
| CVE-2015-0071 | Internet Explorer 9–11 | Second zero-day, used with the Flash exploit to bypass ASLR | [4], [5] |

- **Patch priority:** CVE-2017-0199 (Office). Flash and the old IE flaw only matter if legacy components remain. All three CVEs are in CISA's Known Exploited Vulnerabilities (KEV) catalog [5].
- **Zero-days:** the two 2014 zero-days are the only ones tied to the group; both are patched. None is known to be currently exploited.

### Recent Campaigns and Operations
- **2017: spearphishing against law firms.** At least seven law and investment firms in May–June, with RTF and XLSM attachments (PowerShell, Regsvr32). FireEye later told CyberScoop about further waves until December 2017. Sources: [1], [3].
- **2015–2016: C0d0so0 attacks** on telecom, high-tech, education, manufacturing and legal targets with two custom malware variants (HTTP and port 22). Source: [2].
- **2014: Forbes.com watering hole**, 28 November to 1 December 2014, aimed at visitors from defense and financial companies. Source: [4].
- **Ongoing or upcoming?** No indication in the sources reviewed.
- **Geopolitical alignment:** the 2017 lures used political news (the Macron email leak, the Roy Moore scandal) [1], [3]. The target choice (law and investment firms) points to economic and deal-related information rather than a specific conflict.

## Additional Context and Questions

### Attack Surface
Assumption: the RFI does not describe our infrastructure, so this assumes a typical organization with email, Windows endpoints, web browsing and an internet connection.

| TTP | Attack surface | Mitigation |
|---|---|---|
| Spearphishing attachment | Email, Office users | Attachment scanning, antivirus, SPF/DKIM/DMARC, user training (M1031, M1049, M1054, M1017) |
| Unpatched software | Office, Windows, browsers | Install security updates quickly*; prioritise CISA KEV flaws |
| Drive-by compromise | Web browser and plugins | Keep software updated (M1051), exploit protection (M1050), browser sandboxing (M1048), remove Flash* |
| PowerShell, Regsvr32 / Rundll32 | Windows endpoints | Restrict PowerShell, signed scripts only, application control (M1042, M1045, M1038); ASR rules (M1050); monitor Regsvr32 command lines |
| Run keys, services, DLL hijacking | Registry, application folders | Monitor Run keys, new services and DLL loads*; restrict write permissions* |
| HTTP / port 22 C2 | Network egress | Egress filtering*, network intrusion prevention (M1031), restrict outbound port 22* |

> note: mitigations marked * are my own suggestions. Those with an M-code come from the "Mitigations" section of the MITRE technique pages.

### Recommendations
1. Block macros from internet-sourced Office files and scan email attachments.
2. Patch known exploited flaws (CVE-2017-0199 first) and remove legacy browser plugins.
3. Alert on abused Windows tools (Regsvr32 with a URL, hidden PowerShell) and on new Run keys or services.
4. Retro-hunt the hashes above and review outbound traffic for HTTP and port 22 C2.

### Any known TTPs: executable programs, IP addresses, etc.
- **Commands and executables:** `powershell.exe -NoP -NonI -W Hidden -Command ...`; `regsvr32.exe /s /n /u /i:<URL> scrobj.dll`; `rundll32.exe` (injection target); Cobalt Strike BEACON; Empire.
- **Files and services:** `Agreement.doc` (downloaded by the RTF); `fakerx86.exe` and `dbgeng.dll` (HTTP variant); `McAltLib.dll` (Port 22 variant); service `Dncp`.
- **IPs:** `121[.]54[.]168[.]230` (see IOCs); also listed by Mandiant, role not specified: `104[.]236[.]77[.]169`, `138[.]68[.]45[.]9`, `162[.]243[.]143[.]145`.

## References
1. Mandiant/FireEye, "Privileges and Credentials: Phished at the Request of Counsel", 6 June 2017. Archived copy (20 July 2017): https://web.archive.org/web/20170720172836/https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html. Original URL: https://www.fireeye.com/blog/threat-research/2017/06/phished-at-the-request-of-counsel.html
2. Palo Alto Networks Unit 42, "New Attacks Linked to C0d0so0 Group", 22 January 2016. https://unit42.paloaltonetworks.com/new-attacks-linked-to-c0d0s0-group/
3. CyberScoop, "Roy Moore scandal used for phishing schemes aimed at U.S. law firms", 4 December 2017. https://cyberscoop.com/roy-moore-scandal-phishing-attacks-apt19-fireeye-harvey-weinstein/
4. Security Affairs, "Chinese hackers hit Forbes visitors with zero-day exploits", 12 February 2015. https://securityaffairs.com/33417/cyber-crime/chinese-hackers-hit-forbes.html
5. NVD (accessed 15 October 2026): https://nvd.nist.gov/vuln/detail/CVE-2017-0199, https://nvd.nist.gov/vuln/detail/CVE-2014-9163, https://nvd.nist.gov/vuln/detail/CVE-2015-0071. CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
6. MITRE ATT&CK (accessed 15 October 2026): APT19 (G0073) https://attack.mitre.org/groups/G0073/

**Best regards,**
Agent Federico Dongiovanni, CTI Analyst