#!/usr/bin/env python3
"""
ghostsub — Subdomain Takeover Scanner
Enumerates, fingerprints, and reports dangling CNAME takeover vulnerabilities.
"""

import shutil
import subprocess
import sys
import os
import platform
import datetime
import socket

# ─────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}
 ██████  ██   ██  ██████  ███████ ████████ ███████ ██    ██ ██████ 
 ██       ██   ██ ██    ██ ██         ██    ██      ██    ██ ██   ██
 ██   ███ ███████ ██    ██ ███████    ██    ███████ ██    ██ ██████ 
 ██    ██ ██   ██ ██    ██      ██    ██         ██ ██    ██ ██   ██
  ██████  ██   ██  ██████  ███████    ██    ███████  ██████  ██████ 
                     subdomain takeover scanner
{RESET}""")

def info(msg):    print(f"{CYAN}[*]{RESET} {msg}")
def success(msg): print(f"{GREEN}[✔]{RESET} {msg}")
def warn(msg):    print(f"{YELLOW}[!]{RESET} {msg}")
def error(msg):   print(f"{RED}[✘]{RESET} {msg}")

# ─────────────────────────────────────────────
# Tool Definitions
# ─────────────────────────────────────────────
TOOLS = {
    "go": {
        "description": "Go language runtime (required for most tools)",
        "check_cmd":   "go version",
        "install": {
            "linux":  "sudo apt-get install -y golang-go",
            "darwin": "brew install go",
            "note":   "Or download from https://go.dev/dl/",
        },
        "required": True,
    },
    "subfinder": {
        "description": "Passive subdomain enumeration",
        "check_cmd":   "subfinder -version",
        "install": {
            "go_install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "linux":  "sudo apt-get install -y subfinder",
        },
        "required": True,
    },
    "dnsx": {
        "description": "DNS resolver / CNAME filter",
        "check_cmd":   "dnsx -version",
        "install": {
            "go_install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        },
        "required": True,
    },
    "httpx": {
        "description": "HTTP probing / live host detection (ProjectDiscovery)",
        "check_cmd":   "httpx -version",
        "install": {
            "go_install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        },
        "required": True,
    },

    "nuclei": {
        "description": "Template-based vulnerability scanner (takeover templates)",
        "check_cmd":   "nuclei -version",
        "install": {
            "go_install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        "required": False,  # Optional but recommended
    },
    "subjack": {
        "description": "Subdomain takeover scanner",
        "check_cmd":   "subjack --help",
        "install": {
            "go_install": "go install github.com/haccer/subjack@latest",
        },
        "required": True,
    },
}

# Tools installed via `go install` — always prefer ~/go/bin over system PATH
# to avoid shadowing by same-named packages (e.g. Python httpx CLI vs PD httpx)
GO_TOOLS = {"subfinder", "dnsx", "httpx", "nuclei", "subjack"}

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def go_bin_path() -> str:
    """Return the Go bin directory."""
    gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
    return os.path.join(gopath, "bin")


def resolve_bin(tool_name: str) -> str:
    """
    Return the best absolute path for a binary.
    For Go tools, prefer ~/go/bin/<tool> to avoid shadowing by
    same-named system packages (e.g. Python httpx CLI vs PD httpx).
    Falls back to whatever shutil.which finds.
    """
    if tool_name in GO_TOOLS:
        gobin_candidate = os.path.join(go_bin_path(), tool_name)
        if os.path.isfile(gobin_candidate) and os.access(gobin_candidate, os.X_OK):
            return gobin_candidate
    found = shutil.which(tool_name)
    return found or tool_name


def is_installed(tool_name: str) -> bool:
    """Check if a tool is available (gobin-aware for Go tools)."""
    if tool_name in GO_TOOLS:
        gobin_candidate = os.path.join(go_bin_path(), tool_name)
        if os.path.isfile(gobin_candidate) and os.access(gobin_candidate, os.X_OK):
            return True
    return shutil.which(tool_name) is not None


def ensure_gobin_in_path():
    """Add ~/go/bin to PATH for this process if not already there."""
    gobin = go_bin_path()
    if gobin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = gobin + os.pathsep + os.environ.get("PATH", "")
        info(f"Added {gobin} to PATH for this session.")


def run_command(cmd: str, shell: bool = True) -> tuple[bool, str]:
    """Run a shell command silently. Returns (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            text=True,
            capture_output=True,
            env=os.environ,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def run_command_live(cmd: str) -> bool:
    """Run a command with output streamed directly to the terminal (preserves colors)."""
    try:
        result = subprocess.run(cmd, shell=True, env=os.environ)
        return result.returncode == 0
    except Exception as e:
        error(str(e))
        return False


def prompt_yes_no(question: str) -> bool:
    """Prompt user for y/n."""
    while True:
        ans = input(f"{YELLOW}[?]{RESET} {question} [y/n]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("    Please enter y or n.")


def install_tool(name: str, config: dict) -> bool:
    """Attempt to install a tool. Returns True on success."""
    os_type = platform.system().lower()  # 'linux', 'darwin', 'windows'

    # Prefer go install if Go is available
    # go_install can be a string or list of fallback paths (e.g. after repo renames)
    if "go_install" in config["install"] and is_installed("go"):
        go_cmds = config["install"]["go_install"]
        if isinstance(go_cmds, str):
            go_cmds = [go_cmds]

        for cmd in go_cmds:
            info(f"Installing {name} via: {cmd}")
            ok, out = run_command(cmd)
            if ok:
                ensure_gobin_in_path()
                success(f"{name} installed successfully.")
                return True
            else:
                warn(f"go install attempt failed:\n{out.strip()}")

        error(f"All go install attempts failed for {name}.")

    # Fallback to OS package manager
    pkg_cmd = config["install"].get(os_type)
    if pkg_cmd:
        info(f"Trying package manager: {pkg_cmd}")
        ok, out = run_command(pkg_cmd)
        if ok:
            success(f"{name} installed successfully.")
            return True
        else:
            error(f"Package install failed:\n{out}")

    # Manual fallback note
    if "note" in config["install"]:
        warn(f"Manual install required: {config['install']['note']}")

    return False


# ─────────────────────────────────────────────
# Core Logic
# ─────────────────────────────────────────────
def check_tools() -> dict[str, bool]:
    """Check all tools and return a status dict."""
    ensure_gobin_in_path()
    print(f"\n{BOLD}── Tool Check ──────────────────────────────────{RESET}")
    statuses = {}
    for name, config in TOOLS.items():
        installed = is_installed(name)
        bin_path  = resolve_bin(name) if installed else ""
        tag       = f"{GREEN}✔ {bin_path}{RESET}" if installed else f"{RED}✘ missing{RESET}"
        req       = "" if config["required"] else f"  {YELLOW}(optional){RESET}"
        print(f"  {BOLD}{name:<12}{RESET} {config['description']:<48} {tag}{req}")
        statuses[name] = installed
    print()
    return statuses


def handle_missing(statuses: dict[str, bool]) -> bool:
    """
    For each missing tool, ask the user if they want to install it.
    Returns True if all *required* tools end up installed.
    """
    missing = [n for n, ok in statuses.items() if not ok]
    if not missing:
        success("All tools are already installed!")
        return True

    warn(f"{len(missing)} tool(s) missing: {', '.join(missing)}")
    print()

    for name in missing:
        config = TOOLS[name]
        label = f"{BOLD}{name}{RESET} — {config['description']}"
        req_label = "(required)" if config["required"] else "(optional)"

        if prompt_yes_no(f"Install {label} {req_label}?"):
            ok = install_tool(name, config)
            statuses[name] = ok
            if not ok:
                error(f"Could not install {name}. You may need to install it manually.")
        else:
            statuses[name] = False
            skip_msg = "Skipping (required — scan may fail)." if config["required"] else "Skipping."
            warn(skip_msg)

    # Final check: are all required tools present?
    required_missing = [
        n for n, ok in statuses.items()
        if not ok and TOOLS[n]["required"]
    ]
    if required_missing:
        error(f"Required tools still missing: {', '.join(required_missing)}")
        return False

    return True


def sanitize_domain(raw: str) -> str:
    """Strip protocol, www, trailing slashes and paths from a domain input."""
    raw = raw.strip()
    # Remove protocol
    for prefix in ("https://", "http://"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
    # Remove path/query after the domain
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    return raw.strip()


def get_target() -> str:
    """Prompt for a target domain."""
    print(f"\n{BOLD}── Target ──────────────────────────────────────{RESET}")
    while True:
        raw = input(f"{YELLOW}[?]{RESET} Enter target domain (e.g. example.com): ").strip()
        if not raw:
            print("    Domain cannot be empty.")
            continue
        target = sanitize_domain(raw)
        if raw != target:
            info(f"Sanitized target: {CYAN}{raw}{RESET} → {CYAN}{target}{RESET}")
        return target



def lookup_cname(subdomain: str) -> str:
    """Return the CNAME record for a subdomain using dig."""
    ok, out = run_command(f"dig +short CNAME {subdomain}")
    return out.strip() or "N/A"


def generate_report(target: str, output_dir: str, findings: list[dict]):
    """
    Generate a Markdown disclosure report for all confirmed findings.
    findings: list of dicts with keys: subdomain, cname, service, source, severity
    """
    if not findings:
        return None

    timestamp   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_slug   = datetime.datetime.now().strftime("%Y%m%d")
    report_path = os.path.join(output_dir, f"report_{target.replace('.','_')}_{date_slug}.md")

    try:
        scanner_host = socket.gethostname()
    except Exception:
        scanner_host = "unknown"

    lines = []
    lines.append(f"# Subdomain Takeover Report — {target}")
    lines.append(f"")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| **Target** | `{target}` |")
    lines.append(f"| **Date** | {timestamp} |")
    lines.append(f"| **Findings** | {len(findings)} |")
    lines.append(f"| **Scanner** | {scanner_host} |")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(
        f"During subdomain enumeration of `{target}`, **{len(findings)} subdomain(s)** "
        f"were identified as potentially vulnerable to takeover. "
        f"Each affected subdomain contains a dangling CNAME record pointing to an "
        f"unclaimed or deprovisioned third-party service."
    )
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## Findings")
    lines.append(f"")

    for i, f in enumerate(findings, 1):
        severity = f.get("severity", "Medium")
        lines.append(f"### Finding {i} — `{f['subdomain']}`")
        lines.append(f"")
        lines.append(f"| Field | Detail |")
        lines.append(f"|-------|--------|")
        lines.append(f"| **Subdomain** | `{f['subdomain']}` |")
        lines.append(f"| **CNAME Target** | `{f['cname']}` |")
        lines.append(f"| **Service** | {f.get('service', 'Unknown')} |")
        lines.append(f"| **Detected By** | {f['source']} |")
        lines.append(f"| **Severity** | {severity} |")
        lines.append(f"")
        lines.append(f"**Description**")
        lines.append(f"")
        lines.append(
            f"The subdomain `{f['subdomain']}` has a CNAME record pointing to "
            f"`{f['cname']}`, which appears to be unclaimed on the "
            f"{f.get('service', 'third-party')} platform. An attacker could register "
            f"this resource and serve arbitrary content under the `{target}` domain, "
            f"enabling phishing, cookie theft, or content injection."
        )
        lines.append(f"")
        lines.append(f"**Proof of Concept**")
        lines.append(f"")
        lines.append(f"```bash")
        lines.append(f"# Verify the dangling CNAME")
        lines.append(f"dig CNAME {f['subdomain']}")
        lines.append(f"# Confirm unclaimed resource")
        lines.append(f"curl -si https://{f['subdomain']} | head -20")
        lines.append(f"```")
        lines.append(f"")
        lines.append(f"**Remediation**")
        lines.append(f"")
        lines.append(f"- Remove the CNAME record for `{f['subdomain']}` if the service is no longer in use.")
        lines.append(f"- Or re-claim the resource on {f.get('service', 'the third-party platform')} and point it to an owned asset.")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

    lines.append(f"## Methodology")
    lines.append(f"")
    lines.append(f"```")
    lines.append(f"subfinder -d {target} -silent")
    lines.append(f"  → dnsx -cname -resp -silent          # filter CNAME records only")
    lines.append(f"  → httpx -silent                      # confirm live hosts")
    lines.append(f"  → subjack -ssl -v                    # takeover fingerprinting")
    lines.append(f"  → nuclei -t http/takeovers/           # template-based validation")
    lines.append(f"```")
    lines.append(f"")
    lines.append(f"## References")
    lines.append(f"")
    lines.append(f"- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)")
    lines.append(f"- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)")
    lines.append(f"- [OWASP — Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)")
    lines.append(f"")

    with open(report_path, "w") as rf:
        rf.write("\n".join(lines))

    return report_path

def find_nuclei_templates() -> str | None:
    """Locate the nuclei takeovers template directory."""
    candidates = [
        os.environ.get("NUCLEI_TEMPLATES_DIR", ""),
        os.path.expanduser("~/.local/nuclei-templates"),   # Kali default
        os.path.expanduser("~/nuclei-templates"),
        os.path.expanduser("~/.nuclei-templates"),
    ]
    for candidate in candidates:
        if candidate and os.path.isdir(os.path.join(candidate, "http", "takeovers")):
            return os.path.join(candidate, "http", "takeovers")
    return None


def run_scan(target: str, statuses: dict[str, bool]):
    """Run the scan pipeline."""
    print(f"\n{BOLD}── Running Scan on {CYAN}{target}{RESET}{BOLD} ──────────────────{RESET}\n")

    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"ghostsub_{target.replace('.', '_')}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    info(f"Output directory: {output_dir}")

    subs_file    = os.path.join(output_dir, "subdomains.txt")
    cname_file   = os.path.join(output_dir, "cname_hosts.txt")
    live_file    = os.path.join(output_dir, "live_hosts.txt")
    subjack_out    = os.path.join(output_dir, "subjack_results.txt")
    nuclei_out   = os.path.join(output_dir, "nuclei_results.txt")

    # Resolve absolute paths for all Go tools to avoid shadowing
    subfinder_bin = resolve_bin("subfinder")
    dnsx_bin      = resolve_bin("dnsx")
    httpx_bin     = resolve_bin("httpx")
    nuclei_bin    = resolve_bin("nuclei")

    # ── Step 1: Enumerate subdomains ──────────────────
    if statuses.get("subfinder"):
        info(f"[1/4] subfinder — enumerating subdomains of {target}...")
        ok, out = run_command(f"{subfinder_bin} -d {target} -silent -o {subs_file}")
        if ok and os.path.exists(subs_file):
            count = sum(1 for _ in open(subs_file))
            success(f"Found {count} subdomains → {subs_file}")
        else:
            warn(f"subfinder returned no results or failed.\n{out}")
    else:
        warn("[1/4] subfinder not available, skipping.")

    # ── Step 2: CNAME filter via dnsx ─────────────────
    # Only subdomains with CNAME records can be taken over via dangling CNAMEs
    if statuses.get("dnsx") and os.path.exists(subs_file):
        info("[2/4] dnsx — filtering subdomains with CNAME records...")
        ok, out = run_command(
            f"cat {subs_file} | {dnsx_bin} -cname -resp -silent -o {cname_file}"
        )
        if ok and os.path.exists(cname_file):
            count = sum(1 for _ in open(cname_file))
            success(f"{count} subdomains have CNAMEs → {cname_file}")
        else:
            warn(f"dnsx returned no results.\n{out}")
            # Fall back to full list if dnsx finds nothing
            cname_file = subs_file
    else:
        warn("[2/4] dnsx not available — using full subdomain list (more noise).")
        cname_file = subs_file

    # ── Step 3: Probe live hosts via httpx ─────────────
    # dnsx -resp output format: "sub.domain.com [cname.target.com]"
    # httpx needs bare hostnames — strip the bracketed CNAME with awk first
    if statuses.get("httpx") and os.path.exists(cname_file):
        info("[3/4] httpx — probing live hosts...")
        ok, out = run_command(
            f"awk '{{print $1}}' {cname_file} | {httpx_bin} -silent -o {live_file}"
        )
        if ok and os.path.exists(live_file) and os.path.getsize(live_file) > 0:
            count = sum(1 for _ in open(live_file))
            success(f"{count} live hosts → {live_file}")
        else:
            warn(f"httpx returned no live hosts — using CNAME list as fallback.\n{out}")
    else:
        warn("[3/4] httpx not available or no CNAME file, skipping.")

    # ── Step 4: Takeover scan — subzy + nuclei ─────────
    scan_input = live_file if os.path.exists(live_file) else cname_file

    subjack_bin = resolve_bin("subjack")

    if statuses.get("subjack") and os.path.exists(scan_input):
        info("[4/4a] subjack — checking for takeovers...")
        plain_input = os.path.join(output_dir, "plain_hosts.txt")
        run_command(f"sed 's|https://||;s|http://||' {scan_input} > {plain_input}")
        ok = run_command_live(
            f"{subjack_bin} -w {plain_input} -t 100 -timeout 30 -o {subjack_out} -ssl -v"
        )
        if ok or os.path.exists(subjack_out):
            hits = sum(1 for line in open(subjack_out) if "[Vulnerable]" in line or "[VULNERABLE]" in line) if os.path.exists(subjack_out) else 0
            if hits:
                success(f"subjack found {hits} potential takeover(s) → {subjack_out}")
            else:
                info("subjack completed — no takeovers found.")
        else:
            warn(f"subjack issue:\n{out.strip()}")
    else:
        warn("[4/4a] subjack not available, skipping.")

    if statuses.get("nuclei") and os.path.exists(scan_input):
        info("[4/4b] nuclei — running takeover templates...")

        takeover_templates = find_nuclei_templates()

        # Auto-update if not found
        if not takeover_templates:
            info("Templates not found — running nuclei -update-templates...")
            ok, out = run_command(f"{nuclei_bin} -update-templates")
            if ok:
                success("Templates updated.")
                takeover_templates = find_nuclei_templates()
            else:
                warn(f"Template update failed:\n{out.strip()}")

        if takeover_templates:
            info(f"      Templates: {takeover_templates}")
            # Exact pipeline: cat hosts | nuclei -t .../http/takeovers/
            cmd = f"cat {scan_input} | {nuclei_bin} -t {takeover_templates} -o {nuclei_out}"
        else:
            warn("Templates not found — falling back to -tags takeover")
            cmd = f"cat {scan_input} | {nuclei_bin} -tags takeover -o {nuclei_out}"

        ok, out = run_command(cmd)
        if ok:
            hits = sum(1 for _ in open(nuclei_out)) if os.path.exists(nuclei_out) else 0
            if hits:
                success(f"nuclei found {hits} potential takeover(s) → {nuclei_out}")
            else:
                info("nuclei completed — no takeovers found.")
        else:
            warn(f"nuclei issue:\n{out.strip()}")

    # ── Collect findings & generate report ───────────
    findings = []

    # Parse subjack results
    if os.path.exists(subjack_out):
        with open(subjack_out) as sf:
            for line in sf:
                if "[Vulnerable]" in line or "[VULNERABLE]" in line:
                    subdomain = line.split("]")[-1].strip()
                    # Extract service from subjack output e.g. "[Vulnerable: GitHub]"
                    service = "Unknown"
                    if ":" in line.split("]")[0]:
                        service = line.split(":")[1].split("]")[0].strip()
                    findings.append({
                        "subdomain": subdomain,
                        "cname":     lookup_cname(subdomain),
                        "service":   service,
                        "source":    "subjack",
                        "severity":  "High",
                    })

    # Parse nuclei results
    if os.path.exists(nuclei_out):
        with open(nuclei_out) as nf:
            for line in nf:
                line = line.strip()
                if not line:
                    continue
                # nuclei output: [template-id] [http] [severity] url
                parts = line.split()
                subdomain = parts[-1] if parts else line
                service   = parts[0].strip("[]") if parts else "Unknown"
                findings.append({
                    "subdomain": subdomain,
                    "cname":     lookup_cname(subdomain),
                    "service":   service,
                    "source":    "nuclei",
                    "severity":  "High",
                })

    # ── Summary ────────────────────────────────────────
    print(f"\n{BOLD}── Scan Complete ───────────────────────────────{RESET}")
    success(f"Results saved to: {CYAN}{output_dir}/{RESET}")
    print()
    for fname in sorted(os.listdir(output_dir)):
        fpath = os.path.join(output_dir, fname)
        size  = os.path.getsize(fpath)
        print(f"  📄 {fname:<35} ({size} bytes)")
    print()

    if findings:
        print(f"\n{RED}{BOLD}── Potential Takeovers Found ───────────────────{RESET}")
        for f in findings:
            print(f"  {RED}⚠{RESET}  {BOLD}{f['subdomain']}{RESET}")
            print(f"       CNAME  : {f['cname']}")
            print(f"       Service: {f['service']}")
            print(f"       Tool   : {f['source']}")
            print()
        report_path = generate_report(target, output_dir, findings)
        if report_path:
            success(f"Disclosure report → {CYAN}{report_path}{RESET}")
    else:
        success("No takeovers found — target appears clean.")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
def main():
    banner()

    # 1. Check tools
    statuses = check_tools()

    # 2. Install missing (with user permission)
    all_ready = handle_missing(statuses)
    if not all_ready:
        error("Cannot proceed — required tools are missing.")
        sys.exit(1)

    # 3. Re-check after installs
    print(f"\n{BOLD}── Post-install Verification ───────────────────{RESET}")
    for name in TOOLS:
        was_missing = not statuses.get(name, True)
        if was_missing:
            statuses[name] = is_installed(name)
            if statuses[name]:
                success(f"{name} found at: {resolve_bin(name)}")
            else:
                warn(f"{name} still not found. Check {go_bin_path()} or open a new terminal.")

    # 4. Get target and run
    target = get_target()

    confirm = prompt_yes_no(
        f"Start subdomain takeover scan against {BOLD}{target}{RESET}? "
        f"(Only run on domains you own or have written permission to test)"
    )
    if not confirm:
        warn("Scan cancelled.")
        sys.exit(0)

    run_scan(target, statuses)


if __name__ == "__main__":
    main()
