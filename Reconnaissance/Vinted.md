# Passive recon: Vinted

## Scope and rules

Target: vinted.com. The domains vinted.lt, vinted.it and vinted.fr are used only to compare WHOIS and email/DNS configuration.

All observations were made between 2026-11-13 and 2026-11-15, from ubuntu WSL, using only third-party sources: crt.sh, public DNS resolvers (1.1.1.1 and 8.8.8.8), bgp.he.net, Shodan, the Wayback Machine, Vinted's public careers page, GitHub and news sites. Public web pages were opened normally in a browser.

## Target and tools

Target: Vinted is a European online marketplace for second-hand goods, founded in 2008 in Lithuania, with headquarters in Vilnius. It's a large international company. I chose it because it has a visible technical footprint (certificates, DNS, public repositories) that one person can analyse, and because I know the local context.

Tools (passive): crt.sh, whois, dig (public resolvers 1.1.1.1 and 8.8.8.8, a normal DNS query that is considered passive), bgp.he.net, Shodan, the Wayback Machine, GitHub and news sites.

## 1. Subdomains from Certificate Transparency

I searched crt.sh for `%.vinted.com`, expired certificates excluded.

```
curl -s "https://crt.sh/?q=%25.vinted.com&exclude=expired&output=json" -o crt_all.json
jq -r '.[].name_value' crt_all.json | tr 'A-Z' 'a-z' | sort -u
```

**Data**
- 127 unique names: 57 wildcards (ex `*.int.vinted.com`), 69 explicit hostnames (Appendix A) and one entry from a third-party domain (sslip.io) that I removed.

Screenshots: 01_crtsh_results, 02_terminal_crt_counts

**What the names suggest** (guesses from the names only, not confirmed)
- Internal tools: `vault.int`, `grafana.int`, `netbox.int`, `chef-dal1.int`. Looks like a secrets manager, monitoring, network inventory and configuration management. `int` may mean internal.
- Kubernetes: `k8s.vinted.com` and wildcards like `*.ingress.ams1coreprod1.k8s.vinted.com`. Clusters split by location (`ams1`, `bru1`, `dal1`, `dus1`, maybe data centres) and by prod/sandbox.
- Test environments: `application-playground.svc`, `stage-aim-marketplace`, `cs-tool-web-assets-sandbox`.
- Identity: `atlantis-okta.svc`, suggests Okta.
- AI projects: `app.bloom-ai-poc.svc`, `v-assist-mcp.svc`, `mcp-gateway-connectors.svc`.

## 2. WHOIS

`whois` on each domain. The output format differs between registries, so I collected the fields by hand.

**Data**
- Registrar: INWX GmbH for all four domains.
- Created: vinted.com 1999-06-25, vinted.it and vinted.fr 2013-01-16, vinted.lt not shown.
- Name servers: four awsdns hosts for each domain.
- DNSSEC: unsigned on vinted.com, signed on vinted.it, not shown for .lt and .fr.

**What it suggests:** DNS seems hosted on Amazon Route 53 (inferred from the names). Registrar and DNS provider are different companies. The setup is consistent except for DNSSEC.

## 3. Email and DNS

`dig` through 1.1.1.1 for NS, MX, TXT and `_dmarc` records.

```
for d in vinted.com vinted.lt vinted.it vinted.fr; do
  echo "== $d"
  dig @1.1.1.1 +short NS $d
  dig @1.1.1.1 +short MX $d
  dig @1.1.1.1 +short TXT $d
  dig @1.1.1.1 +short TXT _dmarc.$d
done
```

**Data (same on all four domains)**
- MX: Google.
- SPF: strict (`-all`), includes Amazon SES, Google and the same four IP ranges. vinted.com also includes Atlassian, MailerLite and ServiceNow, vinted.lt includes `_spf.zdsys.com`.
- DMARC: `p=quarantine`, `pct=100`, reports sent to a vinted.com mailbox.
- vinted.com has about 20 domain-verification TXT records, ex. for Atlassian, Jamf, Jumio, HubSpot, OneTrust, ServiceNow, OpenAI and Anthropic. The other domains have a few (Google, Apple, Zoom, Microsoft).

Screenshot: 03_terminal_dns_email

**What it suggests**
- Mail seems to run on Google Workspace
- The configuration is strict, so direct spoofing of these domains should be hard. DMARC is not `reject`, the strictest setting.
- DKIM was not checked: finding its selectors would need guessing.

## 4. IP and hosting

`dig +short A` on vinted.com and api.edge.vinted.com through two resolvers, then an ASN lookup on bgp.he.net for one IP per network and for the four IP ranges in the SPF record.

**Data**
- vinted.com and api.edge.vinted.com: IPs of Cloudflare (AS13335). vinted.com also returned IPs of Fastly (AS54113) in two queries from 1.1.1.1.
- The four SPF ranges (185.68.36.0/24, 185.68.37.0/24, 185.68.38.0/24, 185.175.192.0/22) belong to Vinted, UAB (AS59874).

Screenshots: 04_bgp_cloudflare, 05_bgp_fastly, 06_bgp_vinted_uab

**What it suggests:** the website and API are served through CDNs, so DNS does not show the origin servers. The answers changed between queries, so Vinted may use more than one CDN (not verified). Vinted also runs its own network, and at least one range hosts a web service (see section 5).

## 5. Shodan

Search `hostname:vinted.com`, then filter `org:"Vinted, UAB"`. I did not open any IP.

**Data**
- 35 results. Top countries: Singapore 13, United States 10, Netherlands 7. Top port: 443 (28 results). Most results are Cloudflare (17).
- Only 4 results belong to Vinted, UAB. All four show the names `artefact-storage.svc.vinted.com` and `nexus.vinted.net` and use nginx:
  - 185.68.39.86 (Frankfurt): `301` redirect to `https://artefact-storage.svc.vinted.com/` (2026-11-14)
  - 185.68.39.22 (Lelystad): `403 Forbidden` (2026-11-13)
  - 185.68.39.150 (Frankfurt): `301`, same redirect (2026-11-08)
  - 185.175.192.1 (Vilnius): `301`, same redirect (2026-11-01)
- `it.vinted.com` (Microsoft cloud, Amsterdam) answers `403 Forbidden`.
- `artefact-storage.svc.vinted.com`: Wayback captured it with a `403 Forbidden` on December 23, 2024 and with a `301` redirect on January 27, 2023. This matches Shodan, which shows `301` on three IPs and `403` on one.

Screenshots: 07_shodan_36_results, 08_shodan_vinted_uab

**What it suggests**
- Only 4 of 36 results are on Vinted's own network, so the visible surface is small. Most answers come from CDN or cloud providers.
- A `403 Forbidden` means the server answered but refused the request.
- `artefact-storage.svc.vinted.com` is reachable from the Internet on four IPs in three countries.

## 6. Public information

**Job ads.** I read 5 public ads (Backend Software Engineer, Ad Operations Manager, two AML roles, Authentication Specialist). The Backend Engineer ad lists the stack: Go, Ruby, MySQL with Vitess, Redis, Prometheus, Grafana, ELK, Kafka, Kubernetes, ArgoCD, Jenkins, Okta and Open Policy Agent. The other ads mention ad platforms (AppLovin MAX, AdMob), consent topics (GDPR) and identity checks for Vinted Pay. Kubernetes, Grafana and Okta match the hostnames from section 1. No individuals are named. (screenshot 09_job_ad_backend)

**GitHub.** The organisation `github.com/vinted` has 165 public repositories. The most popular are tools for Elasticsearch (Rust), Ruby (`sidekiq-pool`, `packwerk-intellij`), a REST DHCP server (Go) and `certificator` (Go), which requests certificates from an ACME CA and stores them in Vault. This matches the languages in the job ad. I did not clone anything or read code. These repositories are public on purpose. (screenshot 10_github_org)

**Wayback Machine.**
- 2013-06-21: first capture that looks like Vinted, a very simple page. (11_wayback_vinted_2013)
- 2015-12-02: the page is directly a login page.
- 2018-06-28: similar to the current site.
- I found no old subdomains, internal tools or removed pages on the pages I opened.

**Public incidents** (news and regulators)
- 2024-07-02: the Lithuanian data protection authority fined Vinted UAB €2,385,276 under the GDPR, after complaints about erasure and access requests. It is a compliance case, not a security breach. Vinted said it would appeal.
- March 2023: hundreds of accounts were taken over and wallet funds stolen. Vinted said the credentials came from data obtained elsewhere, outside its platform.
- January 2025: a breach at the data broker Gravy Analytics potentially exposed location data of users of several apps, including Vinted. Vinted was not the breached party.

None of these incidents concerns the infrastructure seen in this reconnaissance.

## Top three findings

### Finding 1: internal hostnames and tech stack visible in CT logs

**What the attacker learns:** names of internal tools, a Kubernetes setup split by location and environment, test environments, the identity provider and AI projects.

**Why it matters:** it is a map of the company's technology, useful for convincing phishing (e.g. pretending to be IT) and for choosing what to research for vulnerabilities.

**Prerequisite:** names give no access. The attacker still needs a reachable system with a vulnerability, credentials, or a user who falls for a message.

**Impact:** mainly confidentiality (information disclosure).

**Mitigation:** use wildcard certificates or a private CA for internal hosts so their names are not logged publicly; keep internal and test systems off the Internet; monitor CT logs for unexpected certificates. Using a public CA with automatic renewal is convenient, so this is a trade-off, not necessarily a mistake.

**Evidence:** section 1, screenshots 01-02, Appendix A

### Finding 2: third-party services listed in DNS TXT records

**What the attacker learns:** the TXT records of vinted.com list external services the company has verified a domain with (e.g. Jumio, Jamf, HubSpot, ServiceNow). inferred from its name.

**Why it matters:** it gives an attacker a list of vendors to impersonate in phishing and of third parties whose compromise could affect Vinted.

**Prerequisite:** a phishing pretext and a user who falls for it, or a vulnerability or stolen account at a vendor. The records alone give no access.

**Impact:** mainly confidentiality.

**Mitigation:** remove verification records once they are no longer needed; keep an inventory of third-party services; move DMARC to `reject` once reports show no legitimate mail failing. Publishing these records is standard practice, so this is a hardening point, not a mistake.

**Evidence:** section 3, screenshot 03

### Finding 3: an internal-looking service reachable from the Internet

**What the attacker learns:** `artefact-storage.svc.vinted.com` (also named `nexus.vinted.net`) answers on four Vinted IPs in Germany, the Netherlands and Lithuania. It appears in both CT logs and Shodan, so the two sources agree. The word "nexus" is often a software package repository, but this is a guess from the name.

**Why it matters:** a place that stores software builds or packages could be attractive, and the attacker now knows exactly where it is. If it were weakly protected, it could leak internal software or allow tampering with what the build systems use.

**Prerequisite:** Shodan shows only a redirect and a `403 Forbidden`, so I do not know what the host serves or whether it needs a login. The attacker would need a weakness, such as missing authentication, an unpatched bug or stolen credentials. I did not test any of this, because it would be active reconnaissance.

**Impact:** low if it is properly protected. If not, confidentiality of internal software and integrity of the software supply chain.

**Mitigation:** put it behind a VPN or single sign-on, or limit access to known IP addresses; check that the redirect and the `403` really protect it; keep the software patched; avoid internal-looking names in public records. It may be public on purpose (for example for partners), which I cannot tell.

**Evidence:** section 5 (Shodan, screenshots 07-08) and section 1 (CT).

## Defender perspective

- Do not publish internal names: use wildcard certificates or a private CA for internal hosts.
- Keep internal tools and storage services behind a VPN or single sign-on, and check regularly what the Internet can see (for example with Shodan on your own address ranges).
- Clean up old DNS verification records and keep an inventory of third-party services.
- Move DMARC from `quarantine` to `reject` when reports show it is safe.
- Train staff on phishing that imitates IT teams and known vendors.

## Conclusions

Without touching Vinted, an attacker can learn a lot about how the company is built. Certificates and DNS reveal the names of internal tools, test environments and AI projects, and the DNS records list many third-party services. Job ads and GitHub confirm the technology stack, and Shodan shows that one internal-looking service is reachable from the Internet. The email setup is strict and consistent, and the main website and API sit behind CDNs, so the directly visible surface is small (4 of 36 Shodan results are on Vinted's own network). Nothing found gives access by itself, but it makes phishing and later attacks easier to prepare. The most important point to check, by the company itself, is the reachable artefact service.

## Limits of this work

- Everything comes from public third-party sources observed between 2026-11-13 and 2026-11-15 (Shodan entries are from 2026-10-24 to 2026-11-14), so results may be incomplete or outdated.
- Wildcard certificates hide real hostnames, crt.sh was searched only for vinted.com, and a name in CT logs does not show that a host is reachable.
- Interpretations of names, DNS records and ASNs are inferences, not verified facts.

## Evidence

Screenshots are uploaded separately as image files:
- 01-02: crt.sh results and terminal counts (section 1)
- 03: terminal output of the DNS queries (section 3)
- 04-06: bgp.he.net lookups for Cloudflare, Fastly and Vinted, UAB (section 4)
- 07-08: Shodan results, all 36 and the 4 of Vinted, UAB (section 5)
- 09-10: job ad and GitHub organisation (section 6)
- 11: Wayback Machine captures of vinted.com (section 6)

## Sources

Public incidents:
- EDPB, "Lithuanian SA: fine of € 2 385 276 on Vinted, UAB": https://www.edpb.europa.eu/news/lithuanian-sa-fine-of-eu-2-385-276-on-vinted-uab-company_en
- LRT, "Lithuania's Vinted fined €2.4m for consumer data rules breaches", 2024-07-03: https://www.lrt.lt/en/news-in-english/19/2310451/lithuania-s-vinted-fined-eur2-4m-for-consumer-data-rules-breaches
- Euronews, "Fashion app Vinted to appeal hefty privacy fine", 2024-07-04: https://www.euronews.com/next/2024/07/04/fashion-app-vinted-to-appeal-hefty-privacy-fine
- Bitdefender Hot for Security, "Cybercrooks target hundreds of Vinted second-hand fashion store shoppers", 2023-03-30: https://www.bitdefender.com/en-us/blog/hotforsecurity/cybercrooks-target-hundreds-of-vinted-second-hand-fashion-store-shoppers-how-can-you-limit-the-damage
- L'Avenir, "Comptes siphonnés et vague d'arnaques : Vinted ... affirme avoir « maîtrisé » le problème", 2023-03-27: https://www.lavenir.net/actu/monde/2023/03/27/comptes-siphonnes-et-vague-darnaques-vinted-la-plateforme-de-seconde-main-affirme-avoir-maitrise-le-probleme-JI5ERKOITRGE3BAYHVTHYKPQ2Q/
- CertPro, "Spotify, Vinted, and Other Popular Apps Caught in Major Data Leak" (summary of a Computing article), 2025-01-13: https://certpro.com/spotify-data-leak/

Other:
- Job ads: Vinted careers page, read on 14/11/2026.
- Code: https://github.com/vinted

## Appendix A: explicit hostnames (crt.sh, `%.vinted.com`, expired excluded)

```
admin-sandbox-static-assets.vinted.com
admin-static-assets.vinted.com
agent-gateway-connectors-sandbox.svc.vinted.com
agent-gateway-connectors.svc.vinted.com
agent-gateway-xaa-sandbox.svc.vinted.com
aim-marketplace.vinted.com
api.edge.vinted.com
api.edge.www.vinted.com
app.bloom-ai-poc.svc.vinted.com
application-playground.svc.vinted.com
artefact-storage.svc.vinted.com
atlantis-okta.svc.vinted.com
bloom-brain.svc.vinted.com
carrier-assets.vinted.com
challenge.vinted.com
chef-ams1.int.vinted.com
chef-bru1.int.vinted.com
chef-dal1.int.vinted.com
chef-dus1.int.vinted.com
consul.int.vinted.com
core.vinted.com
crm-static.vinted.com
cs-tool-web-assets-sandbox.vinted.com
cs-tool-web-assets.vinted.com
customers.shipping.vinted.com
ems.it.vinted.com
fraud-moderation.vinted.com
gh-events.svc.vinted.com
grafana.int.vinted.com
hackathon.it.vinted.com
help-center-sandbox-static.vinted.com
help-center-static.vinted.com
it.vinted.com
item-verification-images.vinted.com
k7v3q2.vinted.com
k8s.vinted.com
legal-assets.vinted.com
localisation-assets-sandbox.vinted.com
localisation-assets.vinted.com
marketplace-web-assets-sandbox.vinted.com
marketplace-web-assets.vinted.com
mcp-gateway-connectors.svc.vinted.com
ml.vinted.com
moderation-platform-assets-sandbox.vinted.com
moderation-platform-assets.vinted.com
netbox.int.vinted.com
offers-marketplace-web-assets.vinted.com
old.vinted.com
press-center-static.vinted.com
public.bloom-ai-poc.svc.vinted.com
reinvinted.vinted.com
shipping.int.vinted.com
sse-sandbox.vinted.com
sse.vinted.com
sse.www.vinted.com
stage-aim-marketplace.vinted.com
static-assets.vinted.com
static.vinted.com
svc-okta-insights-scim-sandbox.svc.vinted.com
team.vinted.com
thanos.int.vinted.com
v-assist-mcp.svc.vinted.com
van-creatives-sandbox.vinted.com
van-creatives.vinted.com
vault.int.vinted.com
vinted.com
vt.int.vinted.com
web-ui-assets.vinted.com
www.vinted.com
```