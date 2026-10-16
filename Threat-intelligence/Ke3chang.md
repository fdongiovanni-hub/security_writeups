# Ke3chang (APT15) threat intelligence analysis
> APT (Advanced Persistent Threat): an organized group, often linked to a state, that attacks in a targeted and sustained manner.

## Overview
ID: G0004

Associated Groups (MITRE): APT15, Mirage, Vixen Panda, GREF, Playful Dragon, RoyalAPT, NICKEL, Nylon Typhoon. Symantec tracks it as Flea.

<!--
Why so many names: each security vendor names the same activity differently.
NICKEL was Microsoft's old name; Microsoft now calls the group Nylon Typhoon.
-->

Origin: China-based (MITRE, Mandiant, Microsoft). Active since at least 2010 according to MITRE and Mandiant; Symantec dates the group to at least 2004.

Targeted sectors and regions: ministries of foreign affairs, embassies and diplomatic missions, governments, NGOs, military and oil companies in Europe, North, Central and South America and the Caribbean. In its early years it also hit aerospace, energy, high-tech, consulting and chemicals/manufacturing/mining companies.

Likely motivation: espionage and intelligence collection. Microsoft assesses "economic espionage or traditional intelligence collection"; Symantec points to a geopolitical motive because of the diplomatic targets.

Tools: custom malware (BS2005, RoyalCli, RoyalDNS, TidePool, Okrum/Ketrican, MirageFox, Graphican, EWSTEW) plus public tools such as Mimikatz (S0002), gsecdump and web shells.

Sources: [1], [2], [6], [7]

## TTPs (Tactics, Techniques, Procedures)
> Tactic = why (the attacker's goal); Technique = how; Procedure = how this specific group did it. Source: [1]

| Tactic | Technique | Procedure |
| :--- | :--- | :--- |
| Resource Development | T1587.001 Develop Capabilities: Malware | Developed custom malware to keep access to victim networks for long periods |
| Resource Development | T1588.002 Obtain Capabilities: Tool | Obtained and used public tools such as Mimikatz |
| Resource Development | T1583.005 Acquire Infrastructure: Botnet | Used an ORB (operational relay box) network for reconnaissance and exploitation |
| Initial Access | T1190 Exploit Public-Facing Application | Exploited internet-facing Microsoft Exchange and SharePoint servers |
| Initial Access | T1133 External Remote Services | Accessed VPNs with compromised accounts and stolen VPN certificates |
| Initial Access | T1078 / T1078.004 Valid Accounts: Cloud Accounts | Used stolen credentials, including to sign in to victims' Microsoft 365 accounts |
| Defense Evasion | T1036.002 / T1036.005 Masquerading | Right-to-Left Override character in spearphishing attachment names; malware dropped into legitimate software folders |
| Defense Evasion | T1027 Obfuscated Files or Information / T1140 Deobfuscate/Decode Files or Information | Base64-encoded shellcode strings, decoded before loading |
| Execution | T1059 / T1059.003 Command and Scripting Interpreter: Windows Command Shell | Commands via the command line; batch scripts used to install persistence |
| Execution | T1569.002 System Services: Service Execution | RemoteExec (similar to PsExec) used to run batch scripts and binaries remotely |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | Several backdoors persist through a Run key |
| Persistence | T1543.003 Windows Service | RoyalDNS persists as a service called `Nwsapagent` |
| Credential Access | T1003.001 / .002 / .003 / .004 OS Credential Dumping (LSASS, SAM, NTDS, LSA Secrets) | Dumped credentials with Mimikatz, gsecdump and NTDSDump |
| Credential Access | T1558.001 Steal or Forge Kerberos Tickets: Golden Ticket | Forged Kerberos golden tickets with Mimikatz |
| Credential Access | T1056.001 Input Capture: Keylogging | Used keyloggers |
| Discovery | T1087.001 / .002 Account Discovery; T1069.002 Permission Groups Discovery: Domain Groups | `net localgroup administrators`, `net group /domain` |
| Discovery | T1082 System Information Discovery; T1016 System Network Configuration Discovery; T1049 System Network Connections Discovery; T1057 Process Discovery; T1007 System Service Discovery; T1018 Remote System Discovery; T1083 File and Directory Discovery; T1033 System Owner/User Discovery; T1614.001 System Language Discovery | `systeminfo`, `ipconfig`, `netstat`, `tasklist`, `net start`, ping scans, file searches |
| Lateral Movement | T1021.002 Remote Services: SMB/Windows Admin Shares | Copied files to network shares of other computers to move laterally |
| Collection | T1005 Data from Local System; T1213.002 Data from Information Repositories: SharePoint; T1114.002 Email Collection: Remote Email Collection | Local files, a SharePoint dumping tool (spwebmember), Exchange mailboxes |
| Collection | T1119 Automated Collection; T1560 / T1560.001 Archive Collected Data: Archive via Utility | Scheduled collection; data compressed with password-protected 7-Zip and RAR |
| Command and Control | T1071.001 Web Protocols | RoyalCli and BS2005 talk to the C2 over HTTP through Internet Explorer (COM interface IWebBrowser2) |
| Command and Control | T1071.004 DNS | RoyalDNS uses DNS for C2 |
| Command and Control | T1105 Ingress Tool Transfer; T1090.003 Proxy: Multi-hop Proxy | Downloaded tools to victims; routed traffic through an ORB network |
| Exfiltration | T1041 Exfiltration Over C2 Channel; T1020 Automated Exfiltration | RAR archives sent through the backdoor; frequent, scheduled exfiltration |

<!--
New terms in this table:
- LSASS / SAM / NTDS / LSA Secrets: places where Windows keeps credentials. LSASS is the process that holds logged-in users' passwords in memory, SAM stores local account hashes, NTDS.dit stores domain account hashes on a domain controller. Mimikatz is a public tool that extracts them.
- Kerberos / Golden Ticket: Kerberos is the authentication system of Windows domains. A golden ticket is a forged ticket that gives long-term access as any user. NCC Group notes it let the group persist even after password resets.
- ORB network (operational relay box): a network of compromised devices and rented servers used as relays, so the attack appears to come from an unrelated address.
- Right-to-Left Override (RTLO): an invisible Unicode character that reverses text, so a file named "report" + RTLO + "fdp.exe" is displayed as "reportexe.pdf" while really being an .exe.
- IWebBrowser2: Internet Explorer's programming interface. The malware uses the real browser to contact the C2, so the traffic looks like normal web browsing.
- DNS C2: commands hidden inside DNS queries (RoyalDNS uses TXT records), which firewalls usually allow.
- "Living off the land": using tools already present in Windows (net, tasklist, ipconfig...) instead of extra malware, which makes detection harder.
- SMB / C$ share: Windows file sharing; the group mounted the C$ administrative share of other hosts to copy files to them.
-->

> note: MITRE does not list spearphishing (T1566) for this group, but the 2013 and 2016 vendor reports describe phishing emails with malicious attachments [2], [3]. The RTLO technique above also refers to spearphishing attachments.

## IOCs (Indicators of Compromise)
> Traces left by an attack. Companies take a group's list of IOCs and check whether any of those traces appear on their computers or networks.

| # | Type | Value | Context | Source |
|---|---|---|---|---|
| 1 | Domain | `news.memozilla[.]org` | C2 of the RoyalCli backdoor | [4] |
| 2 | Domain | `run.linodepower[.]com` | C2 of the BS2005 backdoor | [4] |
| 3 | Domain | `andspurs[.]com` | C2 of the RoyalDNS backdoor (DNS TXT records) | [4] |
| 4 | SHA-256 | `6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785` | RoyalCli backdoor | [4] |
| 5 | SHA-256 | `bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d` | RoyalDNS backdoor | [4] |
| 6 | SHA-256 | `750d9eecd533f89b8aa13aeab173a1cf813b021b6824bc30e60f5db6fa7b950b` | BS2005 backdoor | [4] |
| 7 | Domain | `dgtresorgouv[.]com` | NICKEL domain seized by Microsoft (Dec 2021) | [6] |
| 8 | Domain | `palazzochigi[.]com` | NICKEL domain seized by Microsoft (Dec 2021) | [6] |
| 9 | SHA-256 | `02daf4544bcefb2de865d0b45fc406bee3630704be26a9d6da25c9abe906e7d2` | NICKEL malware (family not specified) | [6] |
| 10 | SHA-256 | `0a45ec3da31838aa7f56e4cbe70d5b3b3809029f9159ff0235837e5b7a4cb34c` | NICKEL malware (family not specified) | [6] |
| 11 | SHA-256 | `4b78b1a3c162023f0c14498541cb6ae143fb01d8b50d6aa13ac302a84553e2d5` | Graphican backdoor | [7] |
| 12 | SHA-256 | `617589fd7d1ea9a228886d2d17235aeb4a68fabd246d17427e50fb31a9a98bcd` | Ketrican backdoor | [7] |
| 13 | IP | `172.104.244[.]187` | Network indicator (role not specified) | [7] |
| 14 | Domain | `www.cyclophilit[.]com` | Network indicator (role not specified) | [7] |
| 15 | Service name | `Nwsapagent` | Service created by RoyalDNS for persistence | [4] |
| 16 | Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap`, `IEHarden = 0` | Set by the Leeson, Neoichor and NumbIdea malware to prepare Internet Explorer for C2 | [6] |

<!--
New in this table:
- Rows 1-14 come from three independent vendors (NCC Group 2018, Microsoft 2021, Symantec 2023), so they cover different years and malware families.
- Rows 15-16 are host-based indicators: they are found on the infected computer, not in the network traffic.
- Seized domains: Microsoft obtained a court order to take over these domains, so they no longer belong to the attackers.
- Ketrican, Graphican, RoyalCli, BS2005: different generations of the group's backdoors. Symantec says Graphican evolved from Ketrican, which was itself based on BS2005.
-->

> note: values are defanged (`[.]`). The infrastructure indicators date from 2017–2023, and the Microsoft domains were seized, so they are probably no longer active; hashes are still valid for identifying the files.

## Vulnerabilities and Exploits

| CVE | Product | How it was used | Source |
|---|---|---|---|
| CVE-2010-3333 | Microsoft Office (RTF parsing) | "Older, reliable" Word exploit used in Operation Ke3chang (2013) | [2], [10] |
| CVE-2010-2883 | Adobe Reader and Acrobat 8.x/9.x (CoolType.dll) | Older Adobe Reader exploit used in Operation Ke3chang (2013) | [2], [10] |
| CVE-2012-4681 | Oracle Java SE 7 Update 6 and earlier | Java zero-day used in Operation Ke3chang (2013) | [2], [10] |
| CVE-2015-2545 | Microsoft Office 2007–2013 (EPS images) | Phishing document (MHTML) delivering the TidePool malware to Indian embassies | [3], [10] |
| CVE-2020-1472 | Windows Netlogon ("Zerologon") | Exploited for privilege escalation in the 2022–2023 Graphican campaign | [7], [10] |
| (no CVE) | Microsoft Exchange, SharePoint, VPN appliances | Exploited while unpatched; Microsoft does not name specific CVEs | [6] |
| (no CVE) | Corporate VPN | Re-entry after eviction using a stolen VPN certificate | [4] |

<!--
New terms:
- CVE-2010-3333: stack buffer overflow in how Word parses RTF files.
- CVE-2010-2883: buffer overflow in a font component (CoolType.dll) of Adobe Reader, triggered by a malicious PDF.
- Zero-day: a flaw the vendor did not yet know about.
- CVE-2015-2545: Office flaw in how EPS images are handled; MHTML is a web-page format that Word can open.
- CVE-2020-1472 (Zerologon): a flaw in the Netlogon protocol that allows taking over a domain controller; Microsoft fixed it in phases starting in August 2020.
-->

> note: all five CVEs are listed in CISA's Known Exploited Vulnerabilities catalog [10].
> note: the 2013 CVEs come from press coverage of the Mandiant report [2] and were confirmed on NVD [10].

## Recent Campaigns

| Period | Campaign | Details | Source |
|---|---|---|---|
| 2019 – 2025 (low confidence) | ORB networks | Mandiant says the SPACEHOP ORB network was used by several China-nexus actors, including APT15, for reconnaissance and exploitation. SentinelLABS (2025) tracked part of the infrastructure of a wider intrusion cluster (PurpleHaze) to an ORB network overlapping with APT15 and "loosely" associates some intrusions with APT15-like actors. | [1], [8], [9] |
| Late 2022 – early 2023 | Graphican campaign | Foreign ministries in the Americas, plus a government finance department and a company selling in Central and South America. New Graphican backdoor, Microsoft Graph API/OneDrive for C2, Zerologon exploit, web shells and credential dumpers. | [7] |
| Sep 2019 – Dec 2021 | NICKEL operations | Governments, diplomatic entities and NGOs in 29 countries, with Exchange/SharePoint/VPN exploitation and Microsoft 365 email collection. In Dec 2021 Microsoft seized 42 domains. | [6] |
| 2016 – 2019 | Okrum and Ketrican | ESET found Okrum used against diplomatic missions and governments in Slovakia, Belgium, Brazil, Chile and Guatemala, plus a new Ketrican variant in March 2019. | [5] |
| May 2017 | UK government contractor | RoyalCli and RoyalDNS backdoors; sensitive documents stolen; the group re-entered via VPN with a stolen certificate. | [4] |
| 2015 – 2016 | TidePool | Spearphishing of Indian embassies using CVE-2015-2545. | [3] |
| 2013 | Operation Ke3chang | Nine compromises at ministries in five European countries, with Syria-themed lures. | [2] |

> note: SPACEHOP is shared infrastructure used by several groups, not a campaign owned by Ke3chang; the 2024–2025 link is low confidence. The latest activity attributed with confidence dates to 2022–2023.

## Attack Surface and Recommendations

**Exposed attack surface:** internet-facing Exchange, SharePoint and VPN servers; Microsoft 365 accounts and legacy protocols (EWS); employee email; domain controllers and stored credentials; web servers (web shells).

| TTP | Attack surface | Mitigation |
|---|---|---|
| Exploit public-facing application (T1190) | Exchange, SharePoint, VPN appliances | Patch quickly: Microsoft says NICKEL exploits unpatched systems [6]; prioritise flaws in CISA's KEV catalog* |
| External remote services (T1133) | VPN | Protect and revoke VPN certificates, and reset credentials after an intrusion* |
| Valid accounts / cloud accounts (T1078) | Microsoft 365 accounts | Block legacy authentication (especially EWS), enforce MFA or passwordless sign-in, block traffic from anonymizing services [6] |
| Credential dumping (T1003) | Workstations, servers, domain controllers | Enable the attack surface reduction rule that blocks credential stealing from LSASS [6]; install Zerologon fixes |
| Golden ticket (T1558.001) | Active Directory | Reset the KRBTGT password twice after a compromise* |
| IE-based and DNS C2 (T1071) | Network egress, endpoints | Hunt for the IE registry changes made by the malware [6]; use NCC Group's Suricata and YARA rules [4]; monitor unusual DNS TXT traffic* |
| Collection and exfiltration (T1560, T1041) | File servers, SharePoint, mailboxes | Alert on renamed `rar.exe`/`7z.exe` and data staging [6]; restrict who can dump SharePoint databases* |
| ORB / proxy infrastructure (T1090.003) | Network perimeter | Mandiant advises tracking ORB networks as evolving infrastructure rather than blocking single IPs [8] |

> note: mitigations marked * are my own suggestions based on the technique. The others come from the cited vendor report. MITRE's "Mitigations" tab for each technique can be used to complete the list.

## References

1. MITRE ATT&CK, Ke3chang (G0004) (accessed 16 October 2026). https://attack.mitre.org/groups/G0004/
2. Mandiant/FireEye, "Operation Ke3chang: Targeted Attacks Against Ministries of Foreign Affairs", December 2013. https://www.mandiant.com/resources/operation-ke3chang-targeted-attacks-against-ministries-of-foreign-affairs. Coverage used: Infosecurity Magazine, https://www.infosecurity-magazine.com/news/cyber-espionage-campaign-ahead-of-g20-summit and The Hacker News, 13 December 2013, https://thehackernews.com/2013/12/chinese-hackers-spied-on-european.html
3. Palo Alto Networks Unit 42, "Operation Ke3chang Resurfaces With New TidePool Malware", May 2016. https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
4. NCC Group, "APT15 is Alive and Strong: An Analysis of RoyalCli and RoyalDNS", 10 March 2018. https://www.nccgroup.com/research/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/
5. ESET, "Okrum and Ketrican: An overview of recent Ke3chang group activity", July 2019. https://www.welivesecurity.com/wp-content/uploads/2019/07/ESET_Okrum_and_Ketrican.pdf
6. Microsoft, "NICKEL targeting government organizations across Latin America and Europe", 6 December 2021. https://www.microsoft.com/security/blog/2021/12/06/nickel-targeting-government-organizations-across-latin-america-and-europe
7. Symantec, "Graphican: Flea Uses New Backdoor in Attacks Targeting Foreign Ministries", 21 June 2023. https://www.security.com/threat-intelligence/flea-backdoor-microsoft-graph-apt15
8. Mandiant, "IOC Extinction? China-Nexus Cyber Espionage Actors Use ORB Networks to Raise Cost on Defenders", 22 May 2024. https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks
9. SentinelLABS, "Follow the Smoke: China-nexus Threat Actors Hammer At the Doors of Top Tier Targets", 2025. https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/
10. NVD (accessed 16 October 2026): https://nvd.nist.gov/vuln/detail/CVE-2010-3333, https://nvd.nist.gov/vuln/detail/CVE-2010-2883, https://nvd.nist.gov/vuln/detail/CVE-2012-4681, https://nvd.nist.gov/vuln/detail/CVE-2015-2545, https://nvd.nist.gov/vuln/detail/CVE-2020-1472