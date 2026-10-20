# Request for Information (RFI): Overview of APT19, Ke3chang and Volatile Cedar

**To:** CStechnologies, requesting team
**From:** Agent Federico Dongiovanni
**Date:** 19 October 2026
**Subject:** Comparative analysis and self-evaluation
**Classification:** TLP:RED (inherited from the RFI)

Details, indicators and sources are in `APT19.md`, `Ke3chang.md` and `Volatile Cedar.md`. Confidence levels (high / medium / low) are my own assessment based on how many independent sources agree.

## Overview of Relevant APT Groups

### Which groups have been active recently and target our sector?
The RFI does not state our sector, so relevance is given by the targets each group has hit.

| | APT19 | Ke3chang | Volatile Cedar |
|---|---|---|---|
| MITRE ID | G0073 | G0004 | G0123 |
| Last documented activity | Late 2017 | 2022–2023 (Graphican); 2024–2025 ORB overlap, low confidence | Intrusions up to mid-2021 (reported October 2022) |
| Main targets | Law and investment firms; defense, finance, energy, pharma, telecom, high tech, education, manufacturing | Foreign ministries, embassies, governments, NGOs, military, oil | Telecom, ISPs, hosting providers; defense contractors, media, education |
| Relevant if we are... | A law, finance or industrial company | A government or diplomatic body | A telecom, ISP or hosting provider |

Ke3chang is the most recently active; APT19 and Volatile Cedar have no recent public reporting.

### Motivations
- **APT19:** espionage and theft of data for economic advantage.
- **Ke3chang:** espionage and intelligence collection.
- **Volatile Cedar:** political and ideological interests; espionage.
None shows financial gain as the main goal.

### Attribution

| Group | Origin | Confidence | Government or political link |
|---|---|---|---|
| APT19 | China | Medium | Low (FireEye: freelancers with some sponsorship) |
| Ke3chang | China | High | Medium (no verified public government attribution found) |
| Volatile Cedar | Lebanon | Medium | Low to medium (Hezbollah or a political group, assessed by ClearSky and SentinelOne) |

### Common TTPs

| TTP | Groups |
|---|---|
| Exploitation of known (n-day) vulnerabilities: phishing and browsers (APT19), Office and servers (Ke3chang), public web servers (Volatile Cedar) | All three |
| Command interpreters (T1059: PowerShell, cmd) | All three |
| Public off-the-shelf tools (T1588.002): Empire and Cobalt Strike, Mimikatz, LaZagne, Meterpreter | All three |
| System, network and user discovery (T1082, T1016, T1033) | All three |
| C2 over HTTP/HTTPS (T1071.001) | All three |
| Credential dumping (T1003) | Ke3chang, Volatile Cedar |
| Abuse of Windows tools (Regsvr32, T1218) | APT19, Volatile Cedar |
| Persistence through Run keys, services or web shells | All three |

## Tactics, Techniques, and Procedures (TTPs)
- **Currently used:** Ke3chang uses phishing, exposed servers, VPN and cloud accounts, credential theft and cloud-service C2. Volatile Cedar uses exposed web servers, web shells and off-the-shelf tools. APT19's last documented TTPs are phishing with Office files and Regsvr32 abuse (2017).
- **Evolution:** APT19 changed lures within weeks in 2017; Ke3chang moved from phishing to exposed servers and cloud accounts and now hides its C2 address in OneDrive; Volatile Cedar went from a custom RAT to web shells and Windows tools.
- **To watch:** C2 through legitimate cloud services, ORB relay networks, abuse of cloud accounts, compromise of hosting/telecom servers and fileless techniques.

## Indicators of Compromise (IOCs)
No indicator is confirmed to be active today. All date from 2012–2023, and only one IP was checked on VirusTotal (APT19, appears inactive). The most useful for immediate detection:

| Group | Indicator | Type |
|---|---|---|
| APT19 | `30f149479c02b741e897cdb9ecd22da7` | MD5, malicious XLSM |
| APT19 | `3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa` | SHA-256, Port 22 variant DLL |
| APT19 | `regsvr32.exe /i:<URL> scrobj.dll`, PowerShell `-W Hidden` | Behavior |
| Ke3chang | `6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785` | SHA-256, RoyalCli |
| Ke3chang | `bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d` | SHA-256, RoyalDNS |
| Ke3chang | Service `Nwsapagent` | Host-based |
| Volatile Cedar | `2D804386DE4073BAD642DFC816876D08` | MD5, Caterpillar (seen by two vendors) |
| Volatile Cedar | `33AF1CD4585DA9ED804068B2A45FC8B4` | MD5, Caterpillar 2 |
| Volatile Cedar | `test.jsp`, `yup.jsp`, `Caterpillar.aspx` | Web shell names |

Use hashes and behavior rules for detection; use domains and IPs only to search old logs.

## Specific Hacker Groups
Out of scope: the assignment covers only these three groups, so I did not assess other cybercriminal or hacker groups. None of the three shows financial motivation. A separate analysis would be needed for criminal groups.

## Vulnerabilities and Exploits

| Priority | CVE | Product | Group |
|---|---|---|---|
| High | CVE-2020-1472 | Windows Netlogon (Zerologon) | Ke3chang |
| High | CVE-2019-3396, CVE-2019-11581 | Atlassian Confluence, Jira | Volatile Cedar |
| High | CVE-2012-3152 | Oracle Reports | Volatile Cedar |
| High | CVE-2017-0199, CVE-2015-2545, CVE-2010-3333 | Microsoft Office / WordPad | APT19, Ke3chang |
| Medium | CVE-2010-2883 | Adobe Reader / Acrobat | Ke3chang |
| Legacy | CVE-2014-9163, CVE-2015-0071, CVE-2012-4681 | Flash, Internet Explorer, Java 7 | APT19, Ke3chang |

All 11 CVEs are in CISA's KEV catalog. The priority is my judgment: still-supported products first, legacy components should be removed.

**Zero-days:** three were tied to these groups (Flash and IE in 2014 for APT19, Java in 2012 for Ke3chang). All are patched, and none is known to be currently exploited. Volatile Cedar used none.

## Geopolitical and Strategic Impacts
- **APT19:** its lures followed political news (the Macron leak, the Roy Moore scandal), but its targets (law and investment firms) point to economic information.
- **Ke3chang:** targeting follows diplomatic interests (Syria-themed lure in 2013, Indian embassies, Latin American and European ministries).
- **Volatile Cedar:** victims are concentrated in Lebanon, Israel and neighbouring states; SentinelOne lists it among Hezbollah-aligned clusters in a report on the Israel–Hamas war.
- **Outlook:** the sources suggest regional tensions can shape targets but none predicts specific campaigns, and I found no source on the effect of sanctions.

## Additional Context and Questions

### Attack Surface
Assumption: our infrastructure is not described, so this assumes email, Windows endpoints, Microsoft 365, internet-facing servers and VPN. Most relevant: (1) public-facing servers (Ke3chang, Volatile Cedar); (2) email and Office users (APT19, Ke3chang); (3) Microsoft 365 and VPN accounts (Ke3chang); (4) Windows servers and domain credentials (Ke3chang, Volatile Cedar).

### Recommendations
1. Patch exposed Exchange, SharePoint, Oracle, Atlassian and VPN systems, plus Zerologon and the Office flaws.
2. Harden email and Microsoft 365: attachment scanning, macro blocking, MFA, no legacy authentication.
3. Protect credentials (LSASS, Active Directory) and restrict RDP.
4. Monitor for web shells, Run keys, new services and abused Windows tools (Regsvr32, PowerShell, vssadmin).
5. Monitor outbound traffic and DNS (cloud-service C2, DGA, port 22) and retro-hunt the hashes above.

## Self-evaluation
- **Coverage:** all RFI sections are answered for each group, using public sources only (vendor reports, MITRE, NVD, CISA).
- **Strengths:** claims are tied to numbered sources; confidence levels are stated; vendor-only TTPs are marked.
- **AI usage:** I used an AI assistant (Claude) to support this analysis: to search and summarise public sources, to structure the documents according to the RFI
- **Limits:** the IOCs are old, and only one was checked live. Our organization's infrastructure and sector are unknown, so the attack-surface sections are generic. The 2024–2025 Ke3chang link and Volatile Cedar's CVEs are low-confidence
- **Possible improvements:** live IOC checks (VirusTotal, OTX) and a review of recent news per group.

**Best regards,**
Agent Federico Dongiovanni, CTI Analyst