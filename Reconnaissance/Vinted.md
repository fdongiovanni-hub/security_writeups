# VINTED

## Scope and Rules

target: vinted.com, vinted.lt, vinted.it, vinted.fr
queries from wsl with third party sources (crt.sh, DNS resolver)

<!--
curl -s "https://crt.sh/?q=%25.vinted.com&exclude=expired&output=json" -o crt_all.json

jq -r '.[].name_value' crt_all.json | tr 'A-Z' 'a-z' | sort -u > evidence/crt_unique_names.txt
-->

## Finding 1
127 unique names, 72 explicit hosts (no wildcards like *.int.vinted.com)

### What the names suggests
**Internal Tools**
This category groups the platforms used by engineering teams to manage infrastructure, visualize data, and secure credentials. The .int suffix confirms that access is restricted to the private corporate network.
* **`vault . int . vinted . com`**: Hosts *HashiCorp Vault*, a centralized system for securely managing passwords, API keys, TLS certificates, and deep corporate secrets.
* **`grafana . int . vinted . com`**: An analytics and monitoring platform that connects to internal databases to generate graphical dashboards and visualize metrics in real time.
* **`netbox . int . vinted . com`**: Acts as the *Source of Truth* for network inventory, handling IP address allocation (IPAM) and the physical mapping of servers within data centers (DCIM).

**Kubernetes Clusters**
Domains ending in .k8s identify clusters running *Kubernetes*, the orchestration system used to deploy applications across hundreds of servers. Their prefixes reveal their importance and physical locations around the globe.
* **`ams1coreprod1 . k8s . vinted . com`**: The main **Production** (`prod`) cluster, located in the Amsterdam data center number 1 (`ams1`). This is the absolute heart of the live Vinted application.
* **`bru1sandbox1 . k8s . vinted . com`**: A **Test/Sandbox** cluster located in the Brussels data center (`bru1`), used for isolated staging experiments without the risk of breaking the live website.
* **`chef-dal1 . int . vinted . com`**: Identifies an automated infrastructure configuration server (*Chef*) located in a Dallas data center (`dal1`), proving the company's trans-atlantic server presence.

**Non-Production Testing Environments**
Development teams utilize these isolated environments to test code changes, UI layouts, or new business logic before pushing them to production, mitigating risks to the final user base.
* **`shipping-sandbox . vinted . com`**: A testing environment built specifically for logistics, postage calculations, and testing third-party courier APIs (such as DHL or UPS).
* **`application-playground . svc . vinted . com`**: A highly experimental, free-roam space for developers to test raw microservice code. The .svc extension shows this is mapped for internal cluster-only routing.
* **`cs-tool-web-assets-sandbox . vinted . com`**: The non-production repository for static web assets (images, stylesheets) tied to the internal Customer Support (CS) administration tools.

**Artificial Intelligence & Emerging Tech**
Subdomains dedicated to training, building, and deploying internal Artificial Intelligence models and virtual assistant frameworks.
* **`app . bloom-ai-poc . svc . vinted . com`**: Represents a *Proof of Concept* (POC), meaning a functional prototype tied to an internal AI model named "Bloom".
* **`v-assist-mcp . svc . vinted . com`**: A cluster service instance likely hosting an automated customer or internal assistant (`v-assist`) leveraging the *Model Context Protocol* (`mcp`) to safely plug AI into local corporate data.

**Public Gateways & Entry Points**
These entry points serve as the outer perimeter of the infrastructure where real internet users land. They filter, cache, and proxy global web requests down to internal backend systems.
* **`api . edge . vinted . com`**: The public-facing entry point (*Edge*) for Vinted APIs, managing and accelerating incoming client requests originating from mobile apps and browsers worldwide.
* **`www . vinted . com`**: The primary public web asset, representing the main user-facing homepage utilized by millions of online shoppers daily.

---

**Technical Limitations of the Data**
Data collected via *Certificate Transparency Logs* (like crt.sh) possesses specific structural boundaries that an analyst must keep in mind to prevent false assumptions:
* **Output Truncation**: Public CT log aggregators like crt.sh enforce limit caps on large query results, meaning older or lower-priority hosts may be missing due to a truncated list.
* **Expired Filter Blinds**: If an analysis strictly looks at active configurations, any domains attached to older decommissioned servers or unrenewed certificates disappear from view entirely.
* **Wildcard Blind Spots**: The utilization of generic wildcard certificates (e.g., `*.int.vinted.com`) effectively masks the names of specific endpoints (such as `netbox` or `vault`), limiting infrastructure visibility.
* **Presence vs. Reachability**: Discovering a host in a public CT log proves the host *exists*, but it does not guarantee that the server is listening to the public web or bypasses private perimeter firewalls.



### F1: Internal hostnames and technology stack exposed through Certificate Transparency logs

What the attacker learns. By searching %.vinted.com on crt.sh (a public search engine for certificate records), I found 72 explicit hostnames. Their names suggest the use of internal tools (e.g. vault.int, grafana.int, netbox.int), Kubernetes clusters split by location and environment (e.g. ams1coreprod1.k8s, bru1sandbox1.k8s), test environments (e.g. shipping-sandbox) and AI projects (e.g. bloom-ai-poc.svc). These meanings are my interpretation of the names, not confirmed facts. No Vinted system was contacted.

Why it matters. The names give an attacker a map of the organisation’s technology and structure without any interaction. This helps in preparing convincing phishing or pretexting messages (for example, pretending to be the IT team) and in choosing which systems to look for weaknesses in.

Additional prerequisite. Names alone give no access. The attacker would still need a reachable system with a vulnerability, valid credentials, or a user who falls for a phishing message. A name in the logs also does not prove that the host is reachable from the Internet, and I did not test this because it would be active reconnaissance.

Likely impact. Mainly confidentiality (information disclosure). Integrity and availability would be affected only if a later attack succeeded.

Mitigation. Use wildcard certificates or a private certificate authority for internal hosts, so their names are not published in public logs. Make sure test and internal systems are not reachable from the Internet, and monitor CT logs for unexpected certificates. Using a public CA with automated renewal is a common and convenient choice, so this is a trade-off, not necessarily a mistake.

Evidence. crt.sh query %.vinted.com (expired certificates excluded) run on [DATE]; screenshot of the terminal output (wc -l); full host list in Appendix A.

Limitations. crt.sh truncated some results, expired certificates were excluded, wildcard certificates hide the real names under them, and only vinted.com was queried