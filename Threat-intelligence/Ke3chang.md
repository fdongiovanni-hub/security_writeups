<!--
REVISION NOTES (second version, checked against the primary sources)
1. Vulnerabilities: CVE-2010-3333 and CVE-2010-2883 are now tied to the 2012 London Olympics-themed BS2005 campaign, not to the 2013 Syria-themed operation. CVE-2012-4681 is a Java zero-day that FireEye does not tie to one campaign.
2. TTPs: added phishing (T1566.001/.002), exploitation for client execution (T1203) and Graphican's dead drop resolver (T1102.001), marked with † because MITRE's group page does not list them. Discovery is split into three rows.
3. IOCs: the Microsoft domains are no longer described as "seized"; Microsoft's indicator list is not stated to be the same set as the 42 seized domains.
4. Recent campaigns: ORB / PurpleHaze attribution made more precise; the European victim of the Graphican campaign and the 2012 campaign were added.
5. Wording fixes: LSASS, Golden Ticket, DNS C2, historical sectors, CVE-2015-2545 products; the stolen VPN certificate was moved out of the vulnerability table.
6. References: official FireEye PDF, verified ESET links, SentinelLABS dates, CISA KEV catalog added; access date 18 October 2026.
-->

# Ke3chang (APT15) threat intelligence analysis
> APT (Advanced Persistent Threat): an organized group, often linked to a state, that attacks in a targeted and sustained manner.

## Overview
ID: G0004

Associated Groups (MITRE): APT15, Mirage, Vixen Panda, GREF, Playful Dragon, RoyalAPT, NICKEL, Nylon Typhoon. Symantec tracks it as Flea.

<!--
Why so many names: each security vendor names the same activity differently.
NICKEL was Microsoft's old name; Microsoft now calls the group Nylon Typhoon.
-->

Origin: China-based (MITRE, Mandiant, Microsoft). Active since at least 2010 according to MITRE and Mandiant; Symantec's own estimate dates the group to at least 2004.

Targeted sectors and regions: ministries of foreign affairs, embassies and diplomatic missions, governments, NGOs, military and oil companies in Europe, the Americas and the Caribbean. Mandiant's 2013 report adds that the group had traditionally also targeted aerospace, energy, high-tech, consulting and chemicals/manufacturing/mining companies, but that the number of attacks in those sectors was small.

<!-- UPDATED: the previous text said the group "also hit" these sectors in its early years; Mandiant stresses that attacks there were few. -->

Likely motivation: espionage and intelligence collection. Microsoft assesses "economic espionage or traditional intelligence collection"; Symantec points to a geopolitical motive because of the diplomatic targets. These are assessments, not proven facts.

Tools: custom malware (BS2005, RoyalCli, RoyalDNS, TidePool, Okrum/Ketrican, MirageFox, Graphican, EWSTEW) plus public tools such as Mimikatz (S0002), gsecdump and web shells.

Sources: [1], [2], [6], [7]

## TTPs (Tactics, Techniques, Procedures)
> Tactic = why (the attacker's goal); Technique = how; Procedure = how this specific group did it. Main source: MITRE ATT&CK [1]. Rows marked † are documented by vendor reports but are not listed on MITRE's Ke3chang page; the ATT&CK ID is my own mapping.

| Tactic | Technique | Procedure |
| :--- | :--- | :--- |
| Resource Development | T1587.001 Develop Capabilities: Malware | Developed custom malware to keep access to victim networks for long periods |
| Resource Development | T1588.002 Obtain Capabilities: Tool | Obtained and used public tools such as Mimikatz |
| Resource Development | T1583.005 Acquire Infrastructure: Botnet | Used an ORB (operational relay box) network for reconnaissance and exploitation |
| Initial Access | T1566.001 Spearphishing Attachment / T1566.002 Spearphishing Link † | Emails with a malware attachment or a link to a malicious download (FireEye [2]); MHTML phishing documents in the TidePool campaign (Unit 42 [3]) |
| Initial Access | T1190 Exploit Public-Facing Application | Exploited internet-facing Microsoft Exchange and SharePoint servers |
| Initial Access | T1133 External Remote Services | Accessed VPNs with compromised accounts; NCC Group also saw re-entry after eviction with a stolen VPN certificate [4] |
| Initial Access | T1078 / T1078.004 Valid Accounts: Cloud Accounts | Used stolen credentials, including to sign in to victims' Microsoft 365 accounts |
| Execution | T1203 Exploitation for Client Execution † | Exploits for Word (CVE-2010-3333), Adobe Reader (CVE-2010-2883) and Office EPS (CVE-2015-2545) documents [2], [3] |
| Execution | T1059 / T1059.003 Command and Scripting Interpreter: Windows Command Shell | Commands via the command line; batch scripts used to install persistence |
| Execution | T1569.002 System Services: Service Execution | RemoteExec (similar to PsExec) used to run batch scripts and binaries remotely |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | Several backdoors persist through a Run key |
| Persistence | T1543.003 Windows Service | RoyalDNS persists as a service called `Nwsapagent` |
| Defense Evasion | T1036.002 / T1036.005 Masquerading | Right-to-Left Override character in attachment names to hide .scr and .exe extensions; malware dropped into legitimate software folders |
| Defense Evasion | T1027 Obfuscated Files or Information / T1140 Deobfuscate/Decode Files or Information | Base64-encoded shellcode strings, decoded before loading |
| Credential Access | T1003.001 / .002 / .003 / .004 OS Credential Dumping (LSASS, SAM, NTDS, LSA Secrets) | Dumped credentials with Mimikatz, gsecdump and NTDSDump |
| Credential Access | T1558.001 Steal or Forge Kerberos Tickets: Golden Ticket | Forged Kerberos golden tickets with Mimikatz |
| Credential Access | T1056.001 Input Capture: Keylogging | Used keyloggers |
| Discovery | T1087.001 / .002 Account Discovery; T1069.002 Permission Groups Discovery: Domain Groups | `net group /domain` and queries about privileged users and groups |
| Discovery | T1082 System Information Discovery; T1016 System Network Configuration Discovery; T1049 System Network Connections Discovery; T1018 Remote System Discovery | `systeminfo`, `ipconfig`, `netstat`, ping scans |
| Discovery | T1057 Process Discovery; T1007 System Service Discovery; T1083 File and Directory Discovery; T1033 System Owner/User Discovery; T1614.001 System Language Discovery | `tasklist`, `net start`, file listings; implants that collect the signed-in username and the system language |
| Lateral Movement | T1021.002 Remote Services: SMB/Windows Admin Shares | Copied files to the network shares of other computers to move laterally |
| Collection | T1005 Data from Local System; T1213.002 Data from Information Repositories: SharePoint; T1114.002 Email Collection: Remote Email Collection | Local files, a SharePoint dumping tool (spwebmember), Exchange mailboxes |
| Collection | T1119 Automated Collection; T1560 / T1560.001 Archive Collected Data: Archive via Utility | Scheduled collection; data compressed with password-protected 7-Zip and RAR |
| Command and Control | T1071.001 Web Protocols | RoyalCli, BS2005 and related backdoors talk to the C2 over HTTP through Internet Explorer (COM interface IWebBrowser2) |
| Command and Control | T1071.004 DNS | RoyalDNS uses DNS for C2 |
| Command and Control | T1102.001 Web Service: Dead Drop Resolver † | Graphican reads its encrypted C2 address from OneDrive through the Microsoft Graph API instead of having a hardcoded address [7] |
| Command and Control | T1105 Ingress Tool Transfer; T1090.003 Proxy: Multi-hop Proxy | Downloaded tools to victims; routed traffic through an ORB network |
| Exfiltration | T1041 Exfiltration Over C2 Channel; T1020 Automated Exfiltration | RAR archives sent through the backdoor; frequent, scheduled exfiltration |

<!--
UPDATED: rows marked † are new; Discovery was one long row and is now three; the VPN certificate detail was moved here from the vulnerability table.
Each tool-specific row describes that malware family, not every campaign of the group. A technique being on MITRE's page does not mean it was seen in every campaign.

New terms in this table:
- LSASS / SAM / NTDS / LSA Secrets: stores of credential material in Windows. LSASS is the process that handles authentication; its memory can contain password hashes, Kerberos tickets and, depending on configuration, cleartext passwords. SAM holds local account hashes, NTDS.dit holds domain account hashes on a domain controller, LSA secrets hold cached secrets. Mimikatz is a public tool that tries to extract this material.
- Kerberos / Golden Ticket: Kerberos is the authentication system of Windows domains. A golden ticket is a forged Kerberos ticket (TGT) created with the secret key of the domain's krbtgt account. It lets the attacker impersonate users and claim privileged group membership, but it does not give access to every resource by itself. NCC Group says the group used it to keep access after remediation steps such as password resets.
- ORB network (operational relay box): a network of compromised devices and rented servers used as relays, so the attack appears to come from an unrelated address.
- Right-to-Left Override (RTLO): an invisible Unicode character that reverses text, so a file named "report" + RTLO + "fdp.exe" is displayed as "reportexe.pdf" while really being an .exe.
- IWebBrowser2: Internet Explorer's programming interface. The malware uses the real browser to contact the C2, so the traffic looks like normal web browsing.
- DNS C2: RoyalDNS uses DNS TXT records for command and control. DNS is normally needed by every network, so defenders watch destinations and unusual TXT traffic rather than block DNS.
- Dead drop resolver: the malware does not contain the C2 address; it reads it from a legitimate service (here OneDrive), so the address can be changed without touching the malware.
- Exploitation for client execution: exploiting a flaw in client software (Word, Adobe Reader, Java) to run code when the victim opens a file.
- "Living off the land": using tools already present in Windows (net, tasklist, ipconfig...) instead of extra malware, which makes detection harder.
- SMB / C$ share: Windows file sharing; the group mounted the C$ administrative share of other hosts to copy files to them.
-->

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
| 7 | Domain | `dgtresorgouv[.]com` | Listed by Microsoft among NICKEL indicators | [6] |
| 8 | Domain | `palazzochigi[.]com` | Listed by Microsoft among NICKEL indicators | [6] |
| 9 | SHA-256 | `02daf4544bcefb2de865d0b45fc406bee3630704be26a9d6da25c9abe906e7d2` | NICKEL malware (family not specified) | [6] |
| 10 | SHA-256 | `0a45ec3da31838aa7f56e4cbe70d5b3b3809029f9159ff0235837e5b7a4cb34c` | NICKEL malware (family not specified) | [6] |
| 11 | SHA-256 | `4b78b1a3c162023f0c14498541cb6ae143fb01d8b50d6aa13ac302a84553e2d5` | Graphican backdoor | [7] |
| 12 | SHA-256 | `617589fd7d1ea9a228886d2d17235aeb4a68fabd246d17427e50fb31a9a98bcd` | Ketrican backdoor | [7] |
| 13 | IP | `172.104.244[.]187` | Network indicator (role not specified) | [7] |
| 14 | Domain | `www.cyclophilit[.]com` | Network indicator (role not specified) | [7] |
| 15 | Service name | `Nwsapagent` | Service created by RoyalDNS for persistence | [4] |
| 16 | Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap`, `IEHarden = 0` | Set by the Leeson, Neoichor and NumbIdea malware to prepare Internet Explorer for C2 | [6] |

<!--
UPDATED: rows 7-8 were previously described as "seized by Microsoft". Microsoft did take control of 42 NICKEL domains in December 2021, but I found no source saying that these listed domains are among them.
Rows 1-14 come from three independent vendors (NCC Group 2018, Microsoft 2021, Symantec 2023), so they cover different years and malware families.
Rows 15-16 are host-based indicators: they are found on the infected computer, not in network traffic.
Symantec says Graphican evolved from Ketrican, which in turn evolved from BS2005.
-->

> note: values are defanged (`[.]`). The indicators were copied from the vendor reports and checked against them on 18 October 2026; I did not test whether they are still active. Infrastructure indicators date from 2017–2023 and may be inactive or reassigned, so check their current status before using them as blocking rules.
> note: hashes identify exactly the published samples. They do not show that a sample is still in use, and a non-matching hash does not exclude a variant of the same malware.
> note: a single indicator, such as the service name `Nwsapagent`, is not proof of compromise on its own and should be assessed with context.

## Vulnerabilities and Exploits

| CVE | Product | How it was used | Source |
|---|---|---|---|
| CVE-2010-3333 | Microsoft Office (RTF parsing) | Word exploit used in the 2012 London Olympics-themed BS2005 campaign against one chemicals/manufacturing/mining firm; FireEye calls it an "older, reliable" exploit | [2], [10] |
| CVE-2010-2883 | Adobe Reader and Acrobat 8.x/9.x (CoolType.dll) | Adobe Reader exploit used in the same 2012 campaign | [2], [10] |
| CVE-2012-4681 | Oracle Java SE 7 Update 6 and earlier | Java zero-day used before a patch was available; FireEye does not tie it to a single campaign | [2], [10] |
| CVE-2015-2545 | Microsoft Office (EPS image handling) | Phishing document (MHTML) delivering the TidePool malware to Indian embassies | [3], [10] |
| CVE-2020-1472 | Windows Netlogon ("Zerologon") | Exploited for privilege escalation in the 2022–2023 Graphican campaign | [7], [10] |
| (no CVE) | Microsoft Exchange, SharePoint, VPN appliances | Exploited while unpatched; Microsoft does not name specific CVEs | [6] |

<!--
UPDATED: the first two CVEs were previously linked to "Operation Ke3chang (2013)". FireEye ties them to the 2012 campaign. The Syria-themed "moviestar" campaign of 2013 used a ZIP file containing an executable disguised as a PDF, not an exploit.
The stolen VPN certificate row was removed: it is an abuse of authentication material, not a vulnerability. It is now in the TTP table (T1133).

New terms:
- CVE-2010-3333: stack buffer overflow in how Word parses RTF files.
- CVE-2010-2883: buffer overflow in a font component (CoolType.dll) of Adobe Reader, triggered by a malicious PDF.
- Zero-day: a flaw the vendor did not yet know about.
- CVE-2015-2545: Office flaw in how EPS images are handled; NVD lists several Office editions (2007 to 2016) as affected. MHTML is a web-page format that Word can open.
- CVE-2020-1472 (Zerologon): a flaw in the Netlogon protocol that allows taking over a domain controller.
-->

> note: all five CVEs are listed in CISA's Known Exploited Vulnerabilities catalog [11]. A CVE existing does not prove that APT15 used it in a given campaign: the attribution comes from the vendor reports.

## Recent Campaigns

| Period | Campaign | Details | Source |
|---|---|---|---|
| Jun 2024 – Mar 2025 (low confidence) | PurpleHaze / ORB infrastructure | SentinelLABS tracks part of the infrastructure used in an October 2024 intrusion into a South Asian government entity as an ORB network that overlaps with APT15. The actor behind that intrusion is not identified. A September 2024 intrusion into a European media organization is loosely associated with UNC5174, not with APT15. | [9] |
| Jan 2019 – May 2024 | SPACEHOP ORB network | MITRE links Ke3chang to this campaign. Mandiant describes SPACEHOP as infrastructure shared by several China-nexus actors, including APT15, so it is not a campaign owned by Ke3chang. | [1], [8] |
| Late 2022 – early 2023 | Graphican campaign | Foreign ministries in the Americas, a government finance department, a corporation selling products in the Americas and one unspecified victim in a European country. New Graphican backdoor (OneDrive/Microsoft Graph API for C2), Zerologon exploit, web shells and credential dumpers. | [7] |
| Sep 2019 – Dec 2021 | NICKEL operations | Governments, diplomatic entities and NGOs in 29 countries, with Exchange/SharePoint/VPN exploitation and Microsoft 365 email collection. In December 2021 Microsoft took control of 42 NICKEL domains. | [6] |
| 2015 – 2019 | Okrum and Ketrican | ESET found Okrum used against diplomatic missions and governments in Slovakia, Belgium, Brazil, Chile and Guatemala, and a new Ketrican version in March 2019. | [5] |
| May 2017 | UK government contractor | RoyalCli and RoyalDNS backdoors; sensitive documents stolen; the group re-entered via VPN with a stolen certificate. | [4] |
| 2015 – 2016 | TidePool | Spearphishing of Indian embassies using CVE-2015-2545. | [3] |
| Aug – Sep 2013 | Operation Ke3chang ("moviestar") | Syria-themed lure sent to European ministries of foreign affairs; nine compromises at ministries in five European countries, eight of them at MFAs. | [2] |
| 2012 | Olympics-themed BS2005 campaign | London Olympics lure against one chemicals/manufacturing/mining firm using CVE-2010-2883 and CVE-2010-3333. | [2] |

<!--
UPDATED: the ORB/PurpleHaze row now separates the infrastructure (ORB network), the intrusion cluster (PurpleHaze) and the attribution to APT15. SentinelLABS says it attributes the whole cluster with high confidence to China-nexus actors, but only loosely to APT15-like actors.
The 2012 row was added because it is the campaign to which two of the CVEs above belong.
ORB = operational relay box (see the TTP comments).
-->

> note: the latest activity described directly as APT15/Flea with group-specific tools in the sources cited is the 2022–2023 Graphican campaign. The 2024–2025 items concern shared infrastructure and are not a definitive attribution.

## Attack Surface and Recommendations

**Exposed attack surface:** employee email; internet-facing Exchange, SharePoint and VPN servers; Microsoft 365 accounts and legacy protocols (EWS); domain controllers and stored credentials; web servers (web shells).

| TTP | Attack surface | Mitigation |
|---|---|---|
| Phishing (T1566) | Employee email | Attachment and link scanning at the email gateway, user awareness training* |
| Exploit public-facing application (T1190) | Exchange, SharePoint, VPN appliances | Patch quickly: Microsoft says NICKEL exploits unpatched systems [6]; prioritise flaws in CISA's KEV catalog* |
| External remote services (T1133) | VPN | Protect and revoke VPN certificates, and reset credentials after an intrusion* |
| Valid accounts / cloud accounts (T1078) | Microsoft 365 accounts | Block legacy authentication (especially EWS), enforce MFA or passwordless sign-in, block traffic from anonymizing services [6] |
| Credential dumping (T1003) | Workstations, servers, domain controllers | Enable the attack surface reduction rule that blocks credential stealing from LSASS [6]; install the Windows updates for CVE-2020-1472 [10] |
| Golden ticket (T1558.001) | Active Directory | Reset the KRBTGT password twice after a compromise* |
| IE-based and DNS C2 (T1071) | Network egress, endpoints | Hunt for the IE registry changes made by the malware [6]; use NCC Group's Suricata and YARA rules [4]; monitor unusual DNS TXT traffic* |
| Collection and exfiltration (T1560, T1041) | File servers, SharePoint, mailboxes | Alert on renamed `rar.exe`/`7z.exe` and data staging [6]; restrict who can dump SharePoint databases* |
| ORB / proxy infrastructure (T1090.003) | Network perimeter | Mandiant advises tracking ORB networks as evolving infrastructure rather than blocking single IPs [8] |

<!-- UPDATED: the Zerologon fix is now cited to NVD [10] and not to Microsoft's NICKEL blog, which does not cover it. A phishing row was added because phishing is now in the TTP table. -->

> note: mitigations marked * are my own suggestions based on the technique. The others come from the cited vendor report. MITRE's "Mitigations" tab for each technique can be used to complete the list.

## References

1. MITRE ATT&CK, Ke3chang (G0004) (accessed 18 October 2026). https://attack.mitre.org/groups/G0004/
2. FireEye, "Operation Ke3chang: Targeted Attacks Against Ministries of Foreign Affairs", December 2013 (report: Villeneuve et al.). PDF: https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-operation-ke3chang.pdf. Blog post: https://www.fireeye.com/blog/executive-perspective/2013/12/operation-ke3chang-targeted-attacks-against-ministries-of-foreign-affairs.html. If a link no longer works, use the Wayback Machine copy.
3. Palo Alto Networks Unit 42, "Operation Ke3chang Resurfaces With New TidePool Malware", May 2016. https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
4. NCC Group, "APT15 is Alive and Strong: An Analysis of RoyalCli and RoyalDNS", 10 March 2018. https://www.nccgroup.com/research/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/
5. ESET, "Okrum: Ke3chang group targets diplomatic missions", 18 July 2019 (summary of the white paper "Okrum and Ketrican: An overview of recent Ke3chang group activity"). https://www.welivesecurity.com/2019/07/18/okrum-ke3chang-targets-diplomatic-missions/ and https://web-assets.esetstatic.com/wls/2019/07/ESET_Okrum_and_Ketrican.pdf
6. Microsoft, "NICKEL targeting government organizations across Latin America and Europe", 6 December 2021. https://www.microsoft.com/security/blog/2021/12/06/nickel-targeting-government-organizations-across-latin-america-and-europe
7. Symantec, "Graphican: Flea Uses New Backdoor in Attacks Targeting Foreign Ministries", June 2023. https://www.security.com/threat-intelligence/flea-backdoor-microsoft-graph-apt15
8. Mandiant, "IOC Extinction? China-Nexus Cyber Espionage Actors Use ORB Networks to Raise Cost on Defenders", 22 May 2024. https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks
9. SentinelLABS, "Follow the Smoke: China-nexus Threat Actors Hammer At the Doors of Top Tier Targets", published 9 June 2025, updated 22 July 2026 (accessed 18 October 2026). https://www.sentinelone.com/labs/follow-the-smoke-china-nexus-threat-actors-hammer-at-the-doors-of-top-tier-targets/
10. NVD (accessed 18 October 2026): https://nvd.nist.gov/vuln/detail/CVE-2010-3333, https://nvd.nist.gov/vuln/detail/CVE-2010-2883, https://nvd.nist.gov/vuln/detail/CVE-2012-4681, https://nvd.nist.gov/vuln/detail/CVE-2015-2545, https://nvd.nist.gov/vuln/detail/CVE-2020-1472
11. CISA, Known Exploited Vulnerabilities Catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog