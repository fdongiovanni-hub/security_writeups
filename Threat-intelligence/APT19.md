# APT19 threat intelligence analysis
> APT: organized group, often linked to a state, and attacks in a targeted and sustained manner.

## Overview
ID: G0073, Associated Groups: Codoso, C0d0so0, Codoso Team, Sunshop Group
Origin: China-based. FireEye assesses it as freelancers with some degree of government sponsorship. Some analysts consider it the same group as Deep Panda (G0009), but this is unconfirmed.
Targeted sectors: defense, finance, energy, pharmaceutical, telecommunications, high tech, education, manufacturing, legal services.
Likely motivation: cyber espionage and data theft for economic advantage (inferred by FireEye).
Tools: custom malware (HTTP and Port 22 variants) plus public tools such as Empire (S0363) and Cobalt Strike (S0154).

TTPs (Tactics, Techniques, Procedures)
> (why, how, how this specific group did it)
Resource Development        T1588.002Obtain Capabilities (Tool)     Obtained and used public tools such as Empire
Initial Access		        T1566.001 Spearphishing Attachment	    Email with attachments RTF/XLSM containing exploit
Initial Access		        T1189 Drive-by Compromise		        Watering hole su forbes.com (2014)
Execution		            T1059.001 PowerShell		        	payload execution
Execution		            T1204.002 User Execution		        Needs to open attachment
Persistence		            T1547.001 Registry Run Keys		        HKCU\...\Run key
Persistence		            T1543.003 Windows Service		        "Port 22" variant registered as service
Defense Evasion		        T1218.010 / .011 Regsvr32 / Rundll32	Regsvr32 used to bypass application control; payload injected into rundll32.exe
Defense Evasion		        T1574.001 DLL Hijacking			        legitimate executable that loads a malicious DLL
Defense Evasion		        T1027 / T1140 / T1564.003		        Base64, XOR obfuscation, hidden PowerShell windows
Discovery		            T1082 / T1016 / T1033			        Collection of host, network and user information
Command & control           T1071.001 + T1132.001		        	HTTP with Base64-encoded data

## IOCs (Indicators of Compromise) (> 10)
qui serve ricerca fuori da MITRE. Le fonti da aprire sono quelle nelle References: il blog FireEye del 2017 e il report Unit 42 del 2016. Contengono hash, domini e IP di C2. Puoi aggiungere anche AlienVault OTX o VirusTotal, ma controlla sempre da quale report arriva ogni indicatore e riportalo. Tieni presente che gli IOC di un gruppo del 2014-2017 sono quasi tutti scaduti, quindi indicalo come limite.

## Vulnerabilities and Exploits
cerca i CVE citati nei report delle stesse fonti (documenti Office RTF, Flash/IE per il watering hole). Per ognuno scrivi CVE, prodotto colpito e come è stato usato. Non scrivere CVE a memoria senza averli verificati su una fonte

## Recent Campaigns
2017: spearphishing against law and investment firms. Seven firms were targeted with RTF and XLSM attachments delivering exploits. The attackers used PowerShell to run payloads and Regsvr32 to bypass application control. Source: FireEye, "Phished at the Request of Counsel" (June 2017).

Earlier activity: 2014, watering hole osn forbes.com. Source: Palo Alto Unit 42 (2016).

Note: these are the most recent campaigns documented in the MITRE ATT&CK entry. No newer activity is attributed to APT19 there.

## Attack Surface and Recommendations
deducila dalle TTP e abbinala alle mitigazioni, ogni tecnica ha una pagina "mitigazioni" su mitre att&ck