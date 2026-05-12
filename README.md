```
 ██████  ██   ██  ██████  ███████ ████████ ███████ ██    ██ ██████ 
 ██       ██   ██ ██    ██ ██         ██    ██      ██    ██ ██   ██
 ██   ███ ███████ ██    ██ ███████    ██    ███████ ██    ██ ██████ 
 ██    ██ ██   ██ ██    ██      ██    ██         ██ ██    ██ ██   ██
  ██████  ██   ██  ██████  ███████    ██    ███████  ██████  ██████ 
                     subdomain takeover scanner
```

A Python-based subdomain takeover scanner that enumerates subdomains, filters for dangling CNAME records, probes live hosts, and fingerprints takeover vulnerabilities — then generates a ready-to-submit disclosure report if anything is found.

---

## How It Works

ghostsub runs a four-stage pipeline designed to reduce noise at every step, so only real takeover candidates reach the scanner.

```
subfinder          enumerate subdomains passively
    ↓
dnsx -cname        keep only subdomains with CNAME records
    ↓
httpx              confirm hosts are live and responding
    ↓
subjack            fingerprint dangling CNAMEs against known services
nuclei             validate with takeover-specific templates
    ↓
report             generate markdown disclosure report if findings exist
```

The key insight behind the `dnsx` filter: only subdomains with CNAME records can be taken over via a dangling CNAME. Filtering early cuts hundreds of subdomains down to a handful before any scanner touches them.

---

## Requirements

ghostsub checks for all dependencies on startup and will offer to install anything missing.

| Tool | Role | Required |
|------|------|----------|
| `go` | Runtime for Go-based tools | Yes |
| `subfinder` | Passive subdomain enumeration | Yes |
| `dnsx` | DNS resolver / CNAME filter | Yes |
| `httpx` | Live host probing (ProjectDiscovery) | Yes |
| `subjack` | Takeover fingerprinting | Yes |
| `nuclei` | Template-based validation | Optional |

> **Note:** ghostsub explicitly resolves Go-installed binaries from `~/go/bin` first to avoid conflicts with same-named system packages (e.g. the Python `httpx` CLI vs ProjectDiscovery's `httpx`).

---

## Installation

```bash
git clone https://github.com/NEED-Programming/ghostsub.git
sudo chmod 7777 ghostsub/
cd ghostsub
python3 ghostsub.py
```

On first run, ghostsub will detect any missing tools and offer to install them automatically via `go install` or your system package manager.

To install dependencies manually:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/haccer/subjack@latest
nuclei -update-templates
```

---

## Usage

```bash
python3 ghostsub.py
```

ghostsub is interactive. It will:

1. Check all required tools and offer to install any that are missing
2. Prompt for a target domain
3. Ask for confirmation before scanning
4. Run the full pipeline
5. Print a findings summary and generate a report if takeovers are found

### Example session

```
[?] Enter target domain (e.g. example.com): target.com
[?] Start subdomain takeover scan against target.com? [y/n]: y

[*] [1/4] subfinder — enumerating subdomains of target.com...
[✔] Found 312 subdomains → ghostsub_target_com_20250512_143022/subdomains.txt
[*] [2/4] dnsx — filtering subdomains with CNAME records...
[✔] 24 subdomains have CNAMEs → ghostsub_target_com_20250512_143022/cname_hosts.txt
[*] [3/4] httpx — probing live hosts...
[✔] 18 live hosts → ghostsub_target_com_20250512_143022/live_hosts.txt
[*] [4/4a] subjack — checking for takeovers...
[*] [4/4b] nuclei — running takeover templates...
```

---

## Output

Each run creates a timestamped output directory: `ghostsub_<target>_<YYYYMMDD_HHMMSS>/`

```
ghostsub_target_com_20250512_143022/
├── subdomains.txt        # all discovered subdomains
├── cname_hosts.txt       # subdomains with CNAME records (dnsx -resp format)
├── live_hosts.txt        # confirmed live hosts
├── plain_hosts.txt       # live hosts with protocol stripped (subjack input)
├── subjack_results.txt   # full subjack output
├── nuclei_results.txt    # nuclei findings (if any)
└── report_<target>_<date>.md   # disclosure report (only generated if findings exist)
```

Timestamped directories mean repeat scans of the same target never overwrite previous results.

---

## Disclosure Report

If ghostsub finds a potential takeover, it automatically generates a `report_<target>_<date>.md` containing:

- Finding metadata (subdomain, CNAME chain, service, severity)
- Human-readable description written for a bug bounty or pentest report
- Proof-of-concept commands (`dig`, `curl`)
- Remediation recommendations
- Full methodology and references

---

## Manual Pipeline

If you prefer to run the steps manually:

```bash
# 1. Enumerate subdomains
subfinder -d target.com -silent -o subdomains.txt

# 2. Filter to CNAME records only
cat subdomains.txt | dnsx -cname -resp -silent -o cname_hosts.txt

# 3. Strip CNAME response, probe live hosts
awk '{print $1}' cname_hosts.txt | ~/go/bin/httpx -silent -o live_hosts.txt

# 4. Strip protocol for subjack
sed 's|https://||;s|http://||' live_hosts.txt > plain_hosts.txt

# 5. Scan for takeovers
subjack -w plain_hosts.txt -t 100 -timeout 30 -o results.txt -ssl -v

# 6. Validate with nuclei
cat live_hosts.txt | nuclei -t ~/.local/nuclei-templates/http/takeovers/
```

---

## Legal

**Only run ghostsub against domains you own or have explicit written authorization to test.**

Unauthorized scanning may violate computer fraud laws in your jurisdiction. If you find a genuine takeover vulnerability on a third-party domain, follow responsible disclosure — report it to the organization's security contact or through their bug bounty program. Do not claim the resource for malicious purposes.

---

## References

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — community fingerprint database
- [ProjectDiscovery](https://projectdiscovery.io) — subfinder, dnsx, httpx, nuclei
- [subjack](https://github.com/haccer/subjack) — takeover fingerprinting
- [OWASP — Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
