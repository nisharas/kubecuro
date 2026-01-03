"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:      Main Entry Point for KubeCuro: Logic Diagnostics & Auto-Healing.
--------------------------------------------------------------------------------
"""
import argcomplete
import sys
import os
import logging
import argparse
import platform
import difflib
from typing import List

# UI and Logging Imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
from rich.markdown import Markdown

# Internal Package Imports
from kubecuro.healer import linter_engine
from kubecuro.synapse import Synapse
from kubecuro.shield import Shield
from kubecuro.models import AuditIssue

# Setup Rich Logging
logging.basicConfig(
    level="INFO", 
    format="%(message)s", 
    datefmt="[%X]", 
    handlers=[RichHandler(rich_tracebacks=True)]
)
log = logging.getLogger("rich")
console = Console()

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        # We append 'kubecuro' to match the --add-data destination in build.sh
        base_path = os.path.join(sys._MEIPASS, "kubecuro")
    except Exception:
        # Now that assets are inside the package, it's just the current directory
        base_path = os.path.dirname(__file__)
        

    return os.path.join(base_path, relative_path)

# --- Extensive Resource Explanations Catalog ---
EXPLAIN_CATALOG = {
    "service": """
# 🔗 Service Logic Audit
KubeCuro verifies the **Connectivity Chain**:
1. **Selector Match**: Validates that `spec.selector` labels match at least one `Deployment` or `Pod`.
2. **Port Alignment**: Ensures `targetPort` in the Service matches a `containerPort` in the Pod spec.
3. **Orphan Check**: Warns if a Service exists without any backing workload.
    """,
    "deployment": """
# 🚀 Deployment Logic Audit
KubeCuro audits the **Rollout Safety**:
1. **Tag Validation**: Flags images using `:latest` or no tag (non-deterministic).
2. **Strategy Alignment**: Checks if `rollingUpdate` parameters are logically compatible with replica counts.
3. **Immutability**: Ensures `spec.selector.matchLabels` is identical to `spec.template.metadata.labels`.
    """,
    "ingress": """
# 🌐 Ingress Logic Audit
KubeCuro validates the **Traffic Path**:
1. **Backend Mapping**: Ensures the referenced `serviceName` exists in the scanned manifests.
2. **Port Consistency**: Validates that the `servicePort` matches a port defined in the target Service.
3. **TLS Safety**: Checks for Secret definitions if HTTPS is configured.
    """,
    "rbac": """
# 🔑 RBAC & Security Audit
KubeCuro audits **Access Control Logic**:
1. **Binding Integrity**: Ensures `RoleBinding` refers to a `Role` or `ClusterRole` that exists in the bundle.
2. **Subject Validation**: Checks if `ServiceAccount` references are valid within the namespace.
3. **Privilege Escalation**: Flags use of wildcards (`*`) in resources or verbs.
    """,
    "storage": """
# 📂 Storage & Persistent Volume Audit
KubeCuro audits **Persistence Logic**:
1. **PVC Match**: Ensures `PersistentVolumeClaims` requested by Pods are defined.
2. **StorageClass Alignment**: Validates that the `storageClassName` in the PVC exists or is supported.
3. **Access Modes**: Warns if multiple Pods use `ReadWriteOnce` on different nodes.
    """,
    "hpa": """
# 📈 HPA Audit
KubeCuro audits **Scaling Logic**:
1. **Target Ref**: Validates that the target Deployment/StatefulSet exists.
2. **Resources**: Warns if scaling on CPU/Mem but containers lack `resources.requests`.
    """,
    "networkpolicy": """
# 🛡️ NetworkPolicy Logic Audit
KubeCuro audits **Isolation Rules**:
1. **Targeting**: Warns if an empty `podSelector` is targeting all pods unintentionally.
2. **Namespace Check**: Validates `namespaceSelector` labels against known namespaces.
    """,
    "probes": """
# 🩺 Health Probe Logic Audit
KubeCuro audits the **Self-Healing** parameters:
1. **Port Mapping**: Ensures `httpGet.port` or `tcpSocket.port` is defined in the container.
2. **Timing Logic**: Flags probes where `timeoutSeconds` is greater than `periodSeconds`.
    """,
    "scheduling": """
# 🏗️ Scheduling & Affinity Audit
KubeCuro checks for **Placement Contradictions**:
1. **NodeSelector**: Verifies that selectors are not using mutually exclusive labels.
2. **Tolerations**: Ensures tolerations follow the correct `Operator` logic (Exists vs Equal).
    """
}

def show_help():
    help_console = Console()
    
    # Block ASCII Art Header
    logo_ascii = r"""
 ██╗  ██╗██╗   ██╗██████╗ ███████╗ ██████╗██╗   ██╗██████╗  ██████╗ 
 ██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗
 █████╔╝ ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██████╔╝██║   ██║
 ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║
 ██║  ██╗╚██████╔╝██████╔╝███████╗╚██████╗╚██████╔╝██║  ██║╚██████╔╝
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
    """
    
    # 1. Print the ASCII Art directly to terminal
    help_console.print(f"[bold cyan]{logo_ascii}[/bold cyan]")
    
    
    # Branding Panel
    help_console.print(Panel(
        "[bold magenta]❤️ KubeCuro[/bold magenta] | Kubernetes Logic Diagnostics & YAML Healer",
        subtitle="[italic white]v1.0.0[/italic white]",
        border_style="bright_black",
        expand=False
    ))
    
    help_console.print("\n[bold yellow]Usage:[/bold yellow]")
    help_console.print("  kubecuro [command] [file_or_dir] [options]")
    
    help_console.print("\n[bold yellow]Main Commands:[/bold yellow]")
    cmd_table = Table(show_header=False, box=None, padding=(0, 2))
    cmd_table.add_row("  [bold cyan]scan[/bold cyan]", "Analyze manifests for logic errors (Read-only)")
    cmd_table.add_row("  [bold cyan]fix[/bold cyan]", "Automatically repair syntax and API deprecations")
    cmd_table.add_row("  [bold cyan]explain[/bold cyan]", "Describe logic used for a resource (e.g., explain hpa)")
    cmd_table.add_row("  [bold cyan]checklist[/bold cyan]", "Show all active logic rules")
    help_console.print(cmd_table)

    help_console.print("\n[bold yellow]Options:[/bold yellow]")
    opt_table = Table(show_header=False, box=None, padding=(0, 2))
    opt_table.add_row("  -h, --help", "Show this help message and exit")
    opt_table.add_row("  -v, --version", "Print version and architecture information")
    opt_table.add_row("  --dry-run", "Show fixes without modifying files (use with 'fix')")
    help_console.print(opt_table)

    help_console.print("\n[bold yellow]Extensive Examples:[/bold yellow]")
    help_console.print("  [dim]1. Scan a specific file for logic gaps:[/dim]")
    help_console.print("      kubecuro scan deployment.yaml")
    help_console.print("\n  [dim]2. Smart-Route (Automatic Scan if command is omitted):[/dim]")
    help_console.print("      kubecuro ./manifests/")
    help_console.print("\n  [dim]3. Automatically fix API deprecations and syntax:[/dim]")
    help_console.print("      kubecuro fix ./prod-cluster/")
    help_console.print("\n  [dim]4. Preview fixes without touching the YAML files:[/dim]")
    help_console.print("      kubecuro fix service.yaml --dry-run")
    help_console.print("\n  [dim]5. Understand why KubeCuro audits RBAC:[/dim]")
    help_console.print("      kubecuro explain rbac")
    
    help_console.print("\n[italic white]Architecture: x86_64 Linux (Static Binary)[/italic white]\n")

def show_checklist():
    table = Table(title="📋 KubeCuro Logic Checklist", header_style="bold magenta")
    table.add_column("Resource", style="cyan")
    table.add_column("Audit Logic")
    table.add_row("Service", "Selector/Workload Linkage, Port Mapping")
    table.add_row("HPA", "Resource Request Presence, Target Validity")
    table.add_row("RBAC", "RoleBinding Integrity, Privilege Escalation")
    table.add_row("Shield", "API Version Deprecation, Security Gaps")
    table.add_row("Synapse", "Cross-resource Ingress, ConfigMap, and STS checks")
    console.print(table)

def run():
    # --- ASSET INTEGRITY CHECK ---
    # Verify critical assets are readable before starting the logic engine
    logo_path = resource_path("assets/Kubecuro Logo.png")
    if not os.path.exists(logo_path):
        # We don't crash, but we log a warning for debugging the binary
        log.debug(f"⚠️ UI Asset missing at {logo_path}")

    
    parser = argparse.ArgumentParser(prog="kubecuro", add_help=False)
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("scan").add_argument("target", nargs="?")
    subparsers.add_parser("fix").add_argument("target", nargs="?")
    subparsers.add_parser("checklist")
    subparsers.add_parser("version")
    
    explain_p = subparsers.add_parser("explain")
    explain_p.add_argument("resource", nargs="?")

    argcomplete.autocomplete(parser)

    args, unknown = parser.parse_known_args()

    # Add a handler for the completion command if you choose to add a subparser for it
    if args.command == "completion":
        # This logic is usually handled by the 'register-python-argcomplete' tool
        # but you can print instructions here
        console.print(Panel(
            "To enable autocomplete, add the following to your .bashrc or .zshrc:\n\n"
            "[bold cyan]eval \"$(register-python-argcomplete kubecuro)\"[/bold cyan]",
            title="Autocomplete Setup"
        ))
        return

    # 1. Flag-based Actions (Help/Version)
    if args.help or (not args.command and not args.version and not unknown):
        show_help(); return
    
    if args.version or args.command == "version":
        arch = platform.machine()
        os_sys = platform.system()
        console.print(f"[bold magenta]KubeCuro Version:[/bold magenta] 1.0.0")
        console.print(f"[bold cyan]Architecture:[/bold cyan] {arch} {os_sys} (Static Binary)")
        return

    if args.command == "checklist":
        show_checklist(); return
    
    # Fuzzy Matching logic for 'explain'
    if args.command == "explain":
        res = args.resource.lower() if args.resource else ""
        if res in EXPLAIN_CATALOG:
            console.print(Panel(Markdown(EXPLAIN_CATALOG[res]), title=f"Logic: {res}", border_style="green"))
        else:
            suggestions = difflib.get_close_matches(res, EXPLAIN_CATALOG.keys(), n=1, cutoff=0.6)
            error_msg = f"Resource [bold red]'{res}'[/bold red] not found."
            if suggestions:
                error_msg += f"\n\nDid you mean: [bold cyan]{suggestions[0]}[/bold cyan]?"
            
            valid_keys = ", ".join([f"[bold cyan]{k}[/bold cyan]" for k in EXPLAIN_CATALOG.keys()])
            console.print(Panel(f"{error_msg}\n\n[bold white]Available:[/bold white] {valid_keys}", title="Logic Catalog"))
        return

    # 2. Smart Command Routing Logic
    # Handles: 'kubecuro scan path', 'kubecuro fix path', or just 'kubecuro path' (Defaults to scan)
    command = args.command
    target = getattr(args, 'target', None)
    
    if not command and unknown:
        # Check if the unknown arg is a valid file/dir
        if os.path.exists(unknown[0]):
            command = "scan"
            target = unknown[0]
        else:
            console.print(f"[bold red]Error:[/bold red] Unrecognized command or invalid path: '{unknown[0]}'")
            show_help(); sys.exit(1)
    
    if not target:
        console.print("[bold red]Error:[/bold red] A valid file or directory target is required.")
        show_help(); sys.exit(1)

    # 3. Execution Pipeline
    console.print(Panel(f"❤️ [bold white]KubeCuro {command.upper()}[/bold white]", style="bold magenta"))
    
    syn = Synapse()
    shield = Shield()
    all_issues = []
    
    files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))] if os.path.isdir(target) else [target]
    # --- NEW: Check for empty file list ---
    if not files:
        console.print(f"\n[bold yellow]⚠ No YAML files found in:[/bold yellow] {target}")
        return
   
    with console.status(f"[bold green]Processing {len(files)} files...") as status:
        for f in files:
            fname = os.path.basename(f)
    
            # --- PHASE A: HEALER ---
            if command == "fix":
                # Capture the boolean result (True if changes were made/detected)
                was_fixed = linter_engine(f, dry_run=args.dry_run)
                
                if was_fixed:
                    status_text = "🟢 FIXED" if not args.dry_run else "🟡 WOULD FIX"
                    all_issues.append(AuditIssue(
                        code="FIXED", 
                        severity=status_text, 
                        file=fname, 
                        message="Repaired YAML Syntax and migrated API versions.", 
                        fix="None" if not args.dry_run else "Run without --dry-run to apply", 
                        source="Healer"
                    ))
            
            # --- PHASE B: SYNAPSE (Build Relationship Map) ---
            syn.scan_file(f)

    # --- PHASE C: SHIELD (API Audit) ---
    for doc in syn.all_docs:
        warn = shield.check_version(doc)
        if warn:
            origin = doc.get('_origin_file', 'unknown')
            # Order: code, severity, file, message, fix, source
            # OPTIONAL: Skip adding the warning if we already logged a fix for this file 
            # and we are in 'fix' mode.
            if command == "fix" and any(i.file == origin and i.code == "FIXED" for i in all_issues):
                continue
            all_issues.append(AuditIssue(
                code="API_DEPRECATED", 
                severity="🟠 MED", 
                file=origin, 
                message=warn, 
                fix="Update API version", 
                source="Shield"
            ))

    # --- PHASE D: SYNAPSE (Cross-Resource Logic Audit) ---
    all_issues.extend(syn.audit())

    # 4. Professional Reporting Table
    if not all_issues:
        console.print("\n[bold green]✔ No issues found. Your manifests are logically sound![/bold green]")
    else:
        res_table = Table(title="\n📊 Diagnostic Report", header_style="bold cyan", box=None)
        res_table.add_column("Severity", justify="left")
        res_table.add_column("File", style="dim")
        res_table.add_column("Message", soft_wrap=True)
        
        for i in all_issues:
            color = "red" if "🔴" in i.severity else "orange3" if "🟠" in i.severity else "green"
            res_table.add_row(f"[{color}]{i.severity}[/{color}]", i.file, i.message)
        console.print(res_table)

        # Audit Summary Logic
        ghost_count = sum(1 for i in all_issues if i.code == "GHOST")
        hpa_count = sum(1 for i in all_issues if i.code == "HPA_LOGIC")
        fix_count = sum(1 for i in all_issues if i.code == "FIXED")
        api_count = sum(1 for i in all_issues if i.code == "API_DEPRECATED")
        
        summary_md = f"""
### 📈 Audit Summary
* **Ghost Services:** {ghost_count} (Services with no pods)
* **HPA Logic Gaps:** {hpa_count} (Missing requests)
* **API Warnings:** {api_count} (Outdated versions)
* **Auto-Repairs:** {fix_count} (Files syntax-healed)
        """
        
        # Color summary based on health
        status_color = "red" if (ghost_count + hpa_count) > 0 else "green"
        console.print(Panel(Markdown(summary_md), title="Summary & Impact", border_style=status_color))

        # --- FINAL ACTION BANNERS ---
        # 1. Success Banner (for 'fix' command)
        if command == "fix" and fix_count > 0 and not args.dry_run:
            console.print("\n")
            console.print(Panel(
                f"[bold green]✔ HEAL COMPLETE:[/bold green] [white]{fix_count} files successfully updated.[/white]",
                border_style="bold green",
                expand=False
            ))

        # 2. Helpful Tip (for 'scan' command if issues were found)
        if command == "scan" and not args.dry_run:
            console.print(f"\n[bold yellow]TIP:[/bold yellow] Run [bold cyan]kubecuro fix {target}[/bold cyan] to auto-repair issues.")

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user. Exiting...[/yellow]")
        sys.exit(0)
    except Exception as e:
        log.exception(f"FATAL ERROR: {e}")
        sys.exit(1)
 
