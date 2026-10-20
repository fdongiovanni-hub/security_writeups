# Request for Information (RFI): Analysis of Volatile Cedar

**To:** CStechnologies, requesting team
**From:** Agent Federico Dongiovanni
**Date:** 19 October 2026
**Subject:** Request for Intelligence on Volatile Cedar (Lebanese Cedar)
**Classification:** TLP:RED (inherited from the RFI)

## Key Information Request

### Overview of Volatile Cedar
- **Identity:** MITRE ID G0123. Also known as Lebanese Cedar (MITRE, ClearSky) and DeftTorero (Kaspersky). Some articles also list "Dancing Salome", but MISP treats it as a different actor, so it is not included.
- **Recent activities:** the latest public reporting is Kaspersky's (October 2022) about intrusions up to mid-2021 [6]. Public reporting was quiet between 2015 and 2020. SentinelOne's later profile summarises the same reports [7].
- **Motivations:** political and ideological interests (MITRE); Check Point saw data collection rather than financial gain, which points to espionage. Targets: telecom companies, ISPs and hosting providers, plus defense contractors, media, education and civil services, mainly in the Middle East, with victims also in the US, UK, Canada and Japan.
- **Attribution (my assessment):** Lebanese origin: **medium** (Check Point found Lebanese Arabic resources and Lebanese domain registrations, but a Check Point researcher noted evidence could be forged). Link to Hezbollah or a political group: **low to medium** (ClearSky and SentinelOne assess it, based on indirect indicators). Active since 2012 (MITRE).

### Tactics, Techniques, and Procedures (TTPs)
The first five rows are MITRE's G0123 list [1]. † = documented by vendor reports but not listed on MITRE's group page; the ATT&CK ID is my own mapping.

| Tactic | Technique | Procedure |
| :--- | :--- | :--- |
| Reconnaissance | T1595.002 / T1595.003 Active Scanning | Vulnerability scans; DirBuster and GoBuster wordlist scans of web directories and DNS subdomains |
| Initial Access | T1190 Exploit Public-Facing Application | Public-facing web servers; no spearphishing or drive-by downloads seen [2], [4] |
| Persistence | T1505.003 Server Software Component: Web Shell | Web shells (Caterpillar, ASPXSpy, a JSP file browser) |
| Command and Control | T1105 Ingress Tool Transfer | Further tools deployed, for example Explosive via the JSP file browser |
| Execution / Defense Evasion | T1059.001 / T1218.010 / T1218.007 † | PowerShell downloaders, Regsvr32 loading a remote script, `msiexec /i` from a URL [6] |
| Credential Access | T1003.001–.003 / T1555 † | Mimikatz, LaZagne, LSASS dumps, `vssadmin` shadow copies to reach SAM and NTDS.dit [6] |
| Discovery | T1033 / T1082 / T1016 / T1087 / T1482 / T1135 † | `whoami`, `systeminfo`, `ipconfig -all`, `net user`, `nltest /domain_trusts`, `net view` [6] |
| Lateral Movement | T1021.001 RDP / T1091 † | Suspected RDP with stolen server credentials [6]; USB infection in Explosive [2] |
| Collection | T1056.001 / T1115 † | Explosive keylogger and clipboard logger [2] |
| Command and Control | T1071.001 / T1573.001 † | Explosive v4 sends RC4-encrypted data over HTTPS [5] |
| Command and Control | T1568.002 DGA / T1008 Fallback Channels † | Hard-coded C2 servers, static update servers and DGA-generated servers [2], [5] |

<!--
New terms:
- Web shell: a small script (ASPX, JSP, PHP) uploaded to a web server that gives the attacker remote control. Caterpillar is the group's own ASPX web shell, a variant of ASPXSpy.
- RAT: Remote Access Trojan. Explosive is the group's custom RAT (keylogger, clipboard logger, command execution, self-destruct).
- DirBuster/GoBuster: tools that try thousands of common names to find hidden pages (brute force with a wordlist).
- DGA: the malware computes new C2 domain names by itself, so blocking one domain is not enough.
- LOLBins: legitimate Windows tools (regsvr32, msiexec, PowerShell) abused to run code; Kaspersky suspects a shift toward "fileless" techniques.
-->

**How the techniques are evolving:**
- 2012–2015: the Explosive RAT on compromised web servers, spreading over USB, with DGA domains [2], [3].
- 2019–2021: more reliance on web shells and off-the-shelf tools (Mimikatz, Meterpreter, LOLBins) with few new Explosive detections [6].
- 2020: Explosive v4 and Caterpillar v2 on about 250 Oracle and Atlassian servers [5].
- **Of concern:** compromise of hosting and telecom servers, which exposes their customers' sites, and the possible shift to fileless techniques.

### Indicators of Compromise (IOCs)

| # | Type | Value | Context | Source |
|---|---|---|---|---|
| 1 | IP | `69[.]64[.]90[.]94` | C&C server of the Explosive RAT | [2] |
| 2 | IP | `50[.]60[.]129[.]74` | C&C server of the Explosive RAT | [2] |
| 3 | Domain | `getadobeflashplayer[.]net` | C&C from a new Explosive v3.0 sample (DGA seed "flashplayergetadobe"), Saudi victims | [3] |
| 4 | Domain | `dotnetexplorer[.]info` | Static/dynamic C&C updater server | [3] |
| 5 | SHA-256 | `a00cd6d4d40cd0634c2d301f023b49c477bf9324640c8346a8596f4fceddd5aa` | Explosive RAT | [3] |
| 6 | SHA-256 | `af5490785da0a859c504DcJHrrHSgvFpsYxqb6g97uaQTd2kE31rPUeDZTeDsjVq` | Explosive RAT | [3] |
| 7 | SHA-256 | `5953c9bf800c67b67f1aDcJHrrHSgvFpsYxqb6g97uaQTd2kE31rPUeDZTeDsjVq` | Web shell | [3] |
| 8 | MD5 | `33AF1CD4585DA9ED804068B2A45FC8B4` | Caterpillar 2 web shell (`404.aspx`) | [5] |
| 9 | MD5 | `39887492C5C70977C0C0CF0AA0E7154B` | Modified JSP file browser (`test.jsp`) | [5] |
| 10 | MD5 | `a97fdcb6493c2012aeebdeef0e09625a` | Explosive RAT DLL (`Communicate.DLL`) | [5] |
| 11 | MD5 | `2D804386DE4073BAD642DFC816876D08` | Caterpillar web shell (`Pavos.aspx`), seen by two vendors | [5], [6] |
| 12 | IP | `200[.]159[.]87[.]196` | Server used in post-exploitation commands (port 3306) | [6] |
| 13 | File names | `test.jsp`, `yup.jsp`, `Caterpillar.aspx` | Web shell names found on compromised servers | [5] |

> note: values are defanged (`[.]`). The indicators were copied from the vendor reports; I did not test whether they are still active. They date from 2015–2022. Row 11 is confirmed by two independent reports; ClearSky's table lists the same MD5 for another file, probably a typo.

**IOCs to integrate immediately:** (1) the hashes in rows 5–11 for retro-hunting on web servers; (2) web shell file names such as `test.jsp`, `yup.jsp`, `Caterpillar.aspx` (generic names, so check the context); (3) behavior rules: `regsvr32 /i:http...scrobj.dll`, `vssadmin` shadow-copy creation, LSASS dumps. Use IPs and domains to search old logs, not for blocking.

### Vulnerabilities and Exploits

| CVE | Product | How it was used | Source |
|---|---|---|---|
| CVE-2012-3152 | Oracle Fusion Middleware (Oracle Reports) | Assessed by ClearSky as used to install the JSP file browser on Oracle servers | [5], [8] |
| CVE-2019-3396 | Atlassian Confluence Server / Data Center | Template injection leading to remote code execution; assessed by ClearSky as exploited | [5], [8] |
| CVE-2019-11581 | Atlassian Jira Server / Data Center | Template injection leading to remote code execution; assessed by ClearSky as exploited | [5], [8] |

- **Patch priority:** all three (public-facing Oracle and Atlassian servers). All are in CISA's KEV catalog [8].
- **Zero-days:** none observed. Check Point (2015) saw none and ClearSky judges them very unlikely; the group uses known flaws ("1-days").
- **Caveat:** ClearSky infers these CVEs from the vulnerable versions found on compromised servers; it did not capture the exploits. Kaspersky found no CVE for its 2019–2021 intrusions and suspects file-upload or command-injection flaws in websites, IIS PHP plugins or stolen credentials [6].

### Recent Campaigns and Operations
- **Late 2019 – mid 2021: DeftTorero intrusions (Kaspersky, October 2022).** Web servers in Egypt, Jordan, Kuwait, Lebanon, Saudi Arabia, Turkey and the UAE hosting corporate, education, government, military, media and telecom sites. Source: [6].
- **2020 – January 2021: ClearSky's report.** About 250 servers running Oracle and Atlassian software, mostly telecom/IT and hosting companies in the Middle East, with victims also in the US and UK. Source: [5].
- **Late 2012 – 2015: Check Point's first exposure.** Hundreds of targets in at least 10 countries (defense contractors, telecom, media, education); the group reacted to the report with a self-destruct command. Sources: [2], [3], [4].
- **Ongoing or upcoming?** No newer campaign found after 2022, and no source predicts one. The long gaps in reporting do not prove inactivity.
- **Geopolitical alignment:** victims are concentrated in Lebanon, Israel, the Palestinian Authority and neighbouring states. SentinelOne lists the group among Hezbollah-aligned clusters in a report on the Israel–Hamas war [7]; I found no source on sanctions affecting its targeting.

## Additional Context and Questions

### Attack Surface
Assumption: the RFI does not describe our infrastructure, so this assumes public web servers (including Oracle, Atlassian or IIS), Windows servers and a network connection.

| TTP | Attack surface | Mitigation |
|---|---|---|
| Exploit public-facing app (T1190) | Oracle, Confluence, Jira, IIS/PHP sites | Patch known flaws quickly (the group uses 1-days) [5]; assess web vulnerabilities and know your exposed web applications and FTP servers [6]; retire unsupported Oracle versions* |
| Web shells (T1505.003) | Web server folders and backups | File-integrity monitoring on web servers; scan web server backups, because tools were found in backups and restoring them can give the attacker access again [6]; check for the file names above [5] |
| Scanning and brute force (T1595) | Web directories, DNS | Watch web logs for DirBuster/GoBuster patterns* and rate-limit requests* |
| Credential theft and LOLBins (T1003, T1218) | Windows servers | Protect LSASS and limit privileged logons*; application control; alert on `vssadmin` shadow copies and `regsvr32` with a URL* |
| Lateral movement and C2 (T1021.001, T1568.002) | RDP, network egress | Restrict RDP and require MFA*; egress filtering and DNS monitoring for DGA-like domains* |

> note: mitigations marked * are my own suggestions; the others come from the cited reports. ClearSky notes that attackers connected to the web shell through NordVPN or ExpressVPN, so blocking by country is not reliable.

### Recommendations
1. Patch or retire public-facing Oracle, Confluence and Jira servers.
2. Monitor web server folders and backups for web shells.
3. Protect credentials on servers and restrict RDP.
4. Retro-hunt the hashes and file names above; monitor DNS for generated domains.

### Any known TTPs: executable programs, IP addresses, etc.
- **Commands and executables:** `regsvr32.exe`, `msiexec.exe`, `powershell.exe`, `vssadmin.exe`, `mstsc.exe`, `whoami`, `systeminfo`, `ipconfig -all`, `net user`, `net view`, `nltest /domain_trusts`.
- **Tools and malware:** Explosive RAT, Caterpillar, ASPXSpy, a modified JSP file browser, Mimikatz, LaZagne, Meterpreter, DirBuster, GoBuster.
- **Files:** `test.jsp`, `yup.jsp`, `Caterpillar.aspx`, `Pavos.aspx`, `404.aspx`, `Communicate.DLL`.
- **IPs:** `69[.]64[.]90[.]94`, `50[.]60[.]129[.]74`, `200[.]159[.]87[.]196`.

## References
1. MITRE ATT&CK, Volatile Cedar (G0123) (accessed 19 October 2026). https://attack.mitre.org/groups/G0123/
2. Check Point, "Volatile Cedar – Analysis of a Global Cyber Espionage Campaign", 31 March 2015. https://blog.checkpoint.com/security/volatilecedar/
3. Check Point, "New Data: Volatile Cedar Malware Campaign", June 2015 (appendix with indicators). https://blog.checkpoint.com/research/new-data-volatile-cedar/
4. PCWorld (IDG News Service), "Lebanese cyberespionage campaign hits defense, telecom, media firms worldwide", 31 March 2015. https://www.pcworld.com/article/426696/lebanese-cyberespionage-campaign-hits-defense-telecom-media-firms-worldwide.html
5. ClearSky, "'Lebanese Cedar' APT – Global Lebanese Espionage Campaign Leveraging Web Servers", January 2021. https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf
6. Kaspersky GReAT, "DeftTorero: tactics, techniques and procedures of intrusions revealed", 3 October 2022. https://securelist.com/defttorero-tactics-techniques-and-procedures/107610/
7. SentinelLABS, "The Israel-Hamas War | Cyber Domain State-Sponsored Activity of Interest" (Lebanese Cedar profile), 2023. https://www.sentinelone.com/labs/the-israel-hamas-war-cyber-domain-state-sponsored-activity-of-interest/
8. NVD (accessed 19 October 2026): https://nvd.nist.gov/vuln/detail/CVE-2012-3152, https://nvd.nist.gov/vuln/detail/CVE-2019-3396, https://nvd.nist.gov/vuln/detail/CVE-2019-11581. CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Best regards,**
Agent Federico Dongiovanni, CTI Analyst