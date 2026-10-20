# Request for Information (RFI): Analysis of Ke3chang

**To:** CStechnologies, requesting team
**From:** Agent Federico Dongiovanni
**Date:** 17 October 2026
**Subject:** Request for Intelligence on Ke3chang (APT15)
**Classification:** TLP:RED (inherited from the RFI)

## Key Information Request

### Overview of Ke3chang
- **Identity:** MITRE ID G0004. Also known as APT15, Mirage, Vixen Panda, GREF, Playful Dragon, RoyalAPT, NICKEL (Microsoft's old name) and Nylon Typhoon (its current name). Symantec tracks it as Flea.
- **Recent activities:** the latest activity described directly as APT15/Flea is the 2022–2023 Graphican campaign against foreign ministries [7]. Infrastructure overlap with APT15 appears in 2024–2025 reporting, but with low confidence (see Recent Campaigns).
- **Motivations:** espionage and intelligence collection (Microsoft, Symantec). Targets: ministries of foreign affairs, embassies, governments, NGOs, military and oil companies in Europe, the Americas and the Caribbean. In 2013 Mandiant noted a small number of attacks on aerospace, energy, high-tech, consulting and chemicals/manufacturing/mining companies.
- **Attribution (my assessment):** China-based origin: **high** (MITRE, Mandiant, Microsoft, NCC Group and Symantec agree). State sponsorship: **medium** (targets and aims fit state intelligence collection, but I did not find a verified public government attribution). Active since at least 2010 (MITRE, Mandiant); Symantec's own estimate is 2004.

### Tactics, Techniques, and Procedures (TTPs)
Source: MITRE ATT&CK [1]. † = documented by vendor reports but not listed on MITRE's group page; the ATT&CK ID is my own mapping.

| Tactic | Technique | Procedure |
| :--- | :--- | :--- |
| Resource Development | T1587.001 / T1588.002 / T1583.005 | Custom malware; public tools such as Mimikatz; an ORB (operational relay box) network for reconnaissance and exploitation |
| Initial Access | T1566.001 / T1566.002 Phishing: Attachment / Link † | Emails with a malware attachment or a download link [2]; MHTML phishing documents (TidePool) [3] |
| Initial Access | T1190 Exploit Public-Facing Application | Internet-facing Exchange and SharePoint servers |
| Initial Access | T1133 External Remote Services / T1078 (.004) Valid Accounts | VPN access with compromised accounts and a stolen VPN certificate to re-enter after eviction [4]; stolen credentials for Microsoft 365 |
| Execution | T1203 † / T1059 (.003) / T1569.002 | Exploits in Word, Adobe Reader and Office EPS documents [2], [3]; command line and batch scripts; RemoteExec (PsExec-like) |
| Persistence | T1547.001 / T1543.003 | Run keys; RoyalDNS as service `Nwsapagent` |
| Defense Evasion | T1036.002 / T1036.005 / T1027 / T1140 | RTLO character hiding .scr/.exe extensions; malware in legitimate software folders; Base64-encoded shellcode |
| Credential Access | T1003.001–.004 / T1558.001 / T1056.001 | Mimikatz, gsecdump, NTDSDump; forged Kerberos golden tickets; keyloggers |
| Discovery | T1087 / T1069.002 / T1082 / T1016 / T1049 / T1018 / T1057 / T1007 / T1083 / T1033 / T1614.001 | `net group /domain`, `systeminfo`, `ipconfig`, `netstat`, `tasklist`, ping scans |
| Lateral Movement | T1021.002 SMB/Windows Admin Shares | Files copied to the network shares of other hosts |
| Collection | T1005 / T1213.002 / T1114.002 / T1119 / T1560.001 | Local files, SharePoint, Exchange mailboxes; scheduled collection; password-protected RAR/7-Zip archives |
| Command and Control | T1071.001 / T1071.004 | RoyalCli and BS2005: HTTP through Internet Explorer (COM interface IWebBrowser2); RoyalDNS: DNS TXT records |
| Command and Control | T1102.001 Dead Drop Resolver † / T1105 / T1090.003 | Graphican reads its encrypted C2 address from OneDrive via the Microsoft Graph API [7]; tool download; ORB relays |
| Exfiltration | T1041 / T1020 | Archives sent through the backdoor; scheduled exfiltration |

<!--
New terms:
- Golden ticket: a forged Kerberos ticket made with the key of the krbtgt account; it lets the attacker impersonate users and was used by the group to keep access after password resets.
- LSASS/SAM/NTDS: where Windows keeps credential material; Mimikatz tries to extract it.
- ORB network: compromised devices and rented servers used as relays to hide the origin.
- RTLO: an invisible Unicode character that reverses text, so "report" + RTLO + "fdp.exe" looks like "reportexe.pdf".
- Dead drop resolver: the malware reads its C2 address from a legitimate service instead of containing it.
-->

**How the techniques are evolving:**
- 2013–2016: phishing and older Office, Adobe and Java exploits; TidePool and CVE-2015-2545 in 2016 [2], [3].
- 2017–2018: RoyalCli/RoyalDNS, golden tickets and VPN re-entry [4].
- 2019–2021: exploitation of Exchange and SharePoint servers and collection of Microsoft 365 email [6].
- 2022–2023: Graphican, which hides its C2 address in OneDrive, and a Zerologon exploit [7].
- **Of concern:** C2 through cloud services, ORB relay networks and abuse of cloud accounts.

### Indicators of Compromise (IOCs)

| # | Type | Value | Context | Source |
|---|---|---|---|---|
| 1 | Domain | `news.memozilla[.]org` | C2 of the RoyalCli backdoor | [4] |
| 2 | Domain | `andspurs[.]com` | C2 of the RoyalDNS backdoor (DNS TXT records) | [4] |
| 3 | SHA-256 | `6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785` | RoyalCli backdoor | [4] |
| 4 | SHA-256 | `bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d` | RoyalDNS backdoor | [4] |
| 5 | Service name | `Nwsapagent` | Service created by RoyalDNS | [4] |
| 6 | Domain | `dgtresorgouv[.]com` | Listed by Microsoft among NICKEL indicators | [6] |
| 7 | Domain | `palazzochigi[.]com` | Listed by Microsoft among NICKEL indicators | [6] |
| 8 | SHA-256 | `02daf4544bcefb2de865d0b45fc406bee3630704be26a9d6da25c9abe906e7d2` | NICKEL malware (family not specified) | [6] |
| 9 | SHA-256 | `4b78b1a3c162023f0c14498541cb6ae143fb01d8b50d6aa13ac302a84553e2d5` | Graphican backdoor | [7] |
| 10 | SHA-256 | `617589fd7d1ea9a228886d2d17235aeb4a68fabd246d17427e50fb31a9a98bcd` | Ketrican backdoor | [7] |
| 11 | IP | `172.104.244[.]187` | Network indicator (role not specified) | [7] |
| 12 | Domain | `www.cyclophilit[.]com` | Network indicator (role not specified) | [7] |

> note: values are defanged (`[.]`). Indicators were copied from the vendor reports; I did not test whether they are still active. They date from 2017–2023. Microsoft also took control of 42 NICKEL domains in December 2021, but its blog does not say which of the listed domains were among them.

**IOCs to integrate immediately:** (1) the SHA-256 hashes for retro-hunting; (2) the service name `Nwsapagent` and renamed `rar.exe`/`7z.exe` used for data staging [6]; (3) the IE registry changes (`ZoneMap`, `IEHarden = 0`) set by the group's malware [6]. Use domains and IPs to search old logs, not as blocking rules.

### Vulnerabilities and Exploits

| CVE | Product | How it was used | Source |
|---|---|---|---|
| CVE-2010-3333 | Microsoft Office (RTF parsing) | Word exploit in the 2012 Olympics-themed BS2005 campaign against one chemicals/manufacturing/mining firm | [2], [10] |
| CVE-2010-2883 | Adobe Reader / Acrobat 8.x–9.x | Adobe Reader exploit in the same 2012 campaign | [2], [10] |
| CVE-2012-4681 | Oracle Java SE 7 Update 6 and earlier | Java zero-day used before a patch existed; not tied to a single campaign | [2], [10] |
| CVE-2015-2545 | Microsoft Office (EPS image handling) | Phishing document delivering TidePool to Indian embassies | [3], [10] |
| CVE-2020-1472 | Windows Netlogon (Zerologon) | Privilege escalation in the 2022–2023 Graphican campaign | [7], [10] |

- **Patch priority:** CVE-2020-1472 and the Office flaws (CVE-2015-2545, CVE-2010-3333), plus unpatched Exchange, SharePoint and VPN appliances (Microsoft names no CVEs) [6]. All five CVEs are in CISA's KEV catalog [10].
- **Zero-days:** the only one tied to the group is the Java flaw CVE-2012-4681 (2012). None is known to be currently exploited.

### Recent Campaigns and Operations
- **2019–2025 (low confidence): ORB infrastructure.** MITRE links Ke3chang to the SPACEHOP ORB network (Jan 2019 – May 2024); Mandiant says several actors, including APT15, share it. SentinelLABS says ORB infrastructure used in an October 2024 intrusion into a South Asian government entity overlaps with APT15; the actor behind that intrusion is not identified. Sources: [1], [8], [9].
- **Late 2022 – early 2023: Graphican.** Foreign ministries in the Americas, a government finance department, a corporation and one unspecified victim in a European country. Source: [7].
- **Sep 2019 – Dec 2021: NICKEL.** Governments, diplomatic entities and NGOs in 29 countries; in December 2021 Microsoft took control of 42 domains. Source: [6].
- **2016–2019: Okrum and Ketrican.** Diplomatic missions and governments in Slovakia, Belgium, Brazil, Chile and Guatemala. Source: [5].
- **May 2017: UK government contractor** (RoyalCli, RoyalDNS); **2015–2016: TidePool** against Indian embassies; **2012–2013: Operation Ke3chang** (Olympics-themed lure, then a Syria-themed lure sent to European foreign ministries). Sources: [4], [3], [2].
- **Ongoing or upcoming?** Possible ongoing activity through shared ORB infrastructure (low confidence). No source predicts specific future campaigns.
- **Geopolitical alignment:** targeting follows diplomatic interests: a Syria-themed lure in 2013, Indian embassies in 2016 and foreign ministries in Latin America and Europe in 2021–2023. Symantec sees a geopolitical motive [7].

## Additional Context and Questions

### Attack Surface
Assumption: the RFI does not describe our infrastructure, so this assumes email, Microsoft 365, internet-facing Exchange/SharePoint/VPN and a Windows domain.

| TTP | Attack surface | Mitigation |
|---|---|---|
| Phishing (T1566) | Email | Attachment and link scanning, user training* |
| Exploit public-facing app (T1190) | Exchange, SharePoint, VPN | Patch quickly [6]; prioritise CISA KEV flaws* |
| VPN / cloud accounts (T1133, T1078) | VPN, Microsoft 365 | Block legacy authentication (especially EWS), enforce MFA or passwordless sign-in [6]; revoke VPN certificates after an intrusion* |
| Credential theft (T1003, T1558.001) | Workstations, domain controllers | ASR rule against credential stealing from LSASS [6]; install the CVE-2020-1472 updates [10]; reset the KRBTGT password twice after a compromise* |
| C2 and exfiltration (T1071, T1560) | Network egress, file servers, mailboxes | Hunt the IE registry changes [6]; NCC Group's Suricata/YARA rules [4]; alert on renamed `rar.exe`/`7z.exe` [6]; track ORB networks as evolving infrastructure [8] |

> note: mitigations marked * are my own suggestions; the others come from the cited vendor report.

### Recommendations
1. Patch internet-facing Exchange, SharePoint and VPN devices and the Zerologon flaw first.
2. Harden Microsoft 365: block legacy authentication, require MFA.
3. Protect credentials (LSASS, golden tickets) and monitor service creation and Run keys.
4. Retro-hunt the hashes and the `Nwsapagent` service; monitor DNS TXT and unusual cloud-service traffic.

### Any known TTPs: executable programs, IP addresses, etc.
- **Commands and executables:** `net.exe` (`net group /domain`), `systeminfo`, `ipconfig`, `netstat`, `tasklist`, ping scans, renamed `rar.exe`/`7z.exe`, `iexplore.exe` (used through COM for C2).
- **Tools and malware:** Mimikatz, gsecdump, NTDSDump, RemoteExec, spwebmember (SharePoint); BS2005, RoyalCli, RoyalDNS, TidePool, Okrum, Ketrican, Graphican.
- **Service:** `Nwsapagent`. **IP:** `172.104.244[.]187` (role not specified).

## References
1. MITRE ATT&CK, Ke3chang (G0004) (accessed 19 October 2026). https://attack.mitre.org/groups/G0004/
2. FireEye, "Operation Ke3chang: Targeted Attacks Against Ministries of Foreign Affairs", December 2013. PDF: https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-operation-ke3chang.pdf. Blog: https://www.fireeye.com/blog/executive-perspective/2013/12/operation-ke3chang-targeted-attacks-against-ministries-of-foreign-affairs.html
3. Palo Alto Networks Unit 42, "Operation Ke3chang Resurfaces With New TidePool Malware", May 2016. https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
4. NCC Group, "APT15 is Alive and Strong: An Analysis of RoyalCli and RoyalDNS", 10 March 2018. https://www.nccgroup.com/research/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/
5. ESET, "Okrum: Ke3chang group targets diplomatic missions", 18 July 2019. https://www.welivesecurity.com/2019/07/18/okrum-ke3chang-targets-diplomatic-missions/
6. Microsoft, "NICKEL targeting government organizations across Latin America and Europe", 6 December 2021. https://www.microsoft.com/security/blog/2021/12/06/nickel-targeting-government-organizations-across-latin-america-and-europe
7. Symantec, "Graphican: Flea Uses New Backdoor in Attacks Targeting Foreign Ministries", June 2023. https://www.security.com/threat-intelligence/flea-backdoor-microsoft-graph-apt15
8. Mandiant, "IOC Extinction? China-Nexus Cyber Espionage Actors Use ORB Networks to Raise Cost on Defenders", 22 May 2024. https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks
9. SentinelLABS, "Follow the Smoke: China-nexus Threat Actors Hammer At the Doors of Top Tier Targets", published 9 June 2025, updated 22 July 2026. https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/
10. NVD (accessed 19 October 2026): https://nvd.nist.gov/vuln/detail/CVE-2010-3333, https://nvd.nist.gov/vuln/detail/CVE-2010-2883, https://nvd.nist.gov/vuln/detail/CVE-2012-4681, https://nvd.nist.gov/vuln/detail/CVE-2015-2545, https://nvd.nist.gov/vuln/detail/CVE-2020-1472. CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Best regards,**
Agent Federico Dongiovanni, CTI Analyst