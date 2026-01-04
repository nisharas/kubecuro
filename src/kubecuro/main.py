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
from rich.syntax import Syntax

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
        base_path = os.path.join(sys._MEIPASS, "kubecuro")
    except Exception:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, relative_path)

# --- Extensive Resource Explanations Catalog ---
EXPLAIN_CATALOG = {
    "rbac": """
# 🔑 RBAC & Security Audit
KubeCuro audits **Access Control Logic**:
1. **RBAC_WILD**: Flags use of global wildcards (*) in resources and verbs.
2. **RBAC_SECRET**: Flags roles that allow reading Secrets.
3. **Privilege Escalation**: Detects if a role allows a user to grant themselves more power.
""",
    "hpa": """
# 📈 HPA Scaling Audit
KubeCuro validates the **Scaling Foundation**:
1. **HPA_MISSING_REQ**: Scaling on CPU/Memory requires resources.requests to be defined.
2. **Target Ref**: Ensures the HPA is pointing to a Deployment that actually exists.
""",
    "service": """
# 🔗 Service Logic Audit
KubeCuro verifies the **Connectivity Chain**:
1. **Selector Match**: Validates that spec.selector labels match a Deployment.
2. **Port Alignment**: Ensures targetPort matches a containerPort.
""",
    "deployment": """
# 🚀 Deployment Logic Audit
KubeCuro audits the **Rollout Safety**:
1. **Tag Validation**: Flags images using :latest or no tag.
2. **Strategy Alignment**: Checks if rollingUpdate parameters are logical.
""",
    "ingress": """
# 🌐 Ingress Logic Audit
KubeCuro validates the **Traffic Path**:
1. **Backend Mapping**: Ensures the referenced serviceName exists.
2. **Port Consistency**: Validates that the servicePort matches the target Service.
""",
    "storage": """
# 📂 Storage & Persistent Volume Audit
KubeCuro audits **Persistence Logic**:
1. **PVC Match**: Ensures PersistentVolumeClaims requested by Pods are defined.
2. **StorageClass Alignment**: Validates that the storageClassName exists.
""",
    "networkpolicy": """
# 🛡️ NetworkPolicy Logic Audit
KubeCuro audits **Isolation Rules**:
1. **Targeting**: Warns if an empty podSelector is targeting all pods.
2. **Namespace Check**: Validates namespaceSelector labels.
""",
    "probes": """
# 🩺 Health Probe Logic Audit
KubeCuro audits the **Self-Healing** parameters:
1. **Port Mapping**: Ensures httpGet.port or tcpSocket.port is defined.
2. **Timing Logic**: Flags probes where timeoutSeconds > periodSeconds.
""",
    "scheduling": """
# 🏗️ Scheduling & Affinity Audit
KubeCuro checks for **Placement Contradictions**:
1. **NodeSelector**: Verifies that selectors are not mutually exclusive.
2. **Tolerations**: Ensures tolerations follow the correct Operator logic.
"""
}

def show_help():
    help_console = Console()
    # logo_ascii must be absolutely clean of hidden Unicode spaces
    logo_ascii = r"""
 ██╗  ██╗██╗   ██╗██████╗ ███████╗ ██████╗██╗   ██╗██████╗  ██████╗ 
 ██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗
 █████╔╝ ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██████╔╝██║   ██║
 ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║
 ██║  ██╗╚██████╔╝██████╔╝███████╗╚██████╗╚██████╔╝██║  ██╗╚██████╔╝
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
    """
    help_console.print(f"[bold cyan]{logo_ascii}[/bold cyan]")
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
    cmd_table.add_row("  [bold cyan]completion[/bold cyan]", "Generate shell completion scripts (bash/zsh)")
    help_console.print(cmd_table)

    help_console.print("\n[bold yellow]Options:[/bold yellow]")
    opt_table = Table(show_header=False, box=None, padding=(0, 2))
    opt_table.add_row("  -h, --help", "Show this help message and exit")
    opt_table.add_row("  -v, --version", "Print version and architecture information")
    opt_table.add_row("  --dry-run", "Show fixes without modifying files (use with 'fix')")
    help_console.print(opt_table)

    help_console.print("\n[bold yellow]Extensive Examples:[/bold yellow]")
    help_console.print("  [dim]1. Scan a specific file for logic gaps:[/dim]\n      kubecuro scan deployment.yaml")
    help_console.print("\n  [dim]2. Automatically fix API deprecations and syntax:[/dim]\n      kubecuro fix ./prod-cluster/")
    help_console.print("\n  [dim]3. Enable Autocomplete:[/dim]")
    help_console.print("      [bold cyan]source <(kubecuro completion bash)[/bold cyan]")
    
    help_console.print("\n[italic white]Architecture: Static Binary / x86_64[/italic white]\n")

def show_checklist():
    table = Table(title="📋 KubeCuro Logic Checklist", header_style="bold magenta")
    table.add_column("Resource", style="cyan"); table.add_column("Audit Logic")
    table.add_row("Service", "Selector/Workload Linkage, Port Mapping")
    table.add_row("HPA", "Resource Request Presence, Target Validity")
    table.add_row("RBAC", "Wildcard Access, Secret Reading, Binding Integrity")
    table.add_row("Shield", "API Version Deprecation, Security Gaps")
    table.add_row("Synapse", "Cross-resource Ingress, ConfigMap, and STS checks")
    console.print(table)

def interactive_explain(target_file, issues):
    with open(target_file, 'r') as f:
        original_code = f.read()

    # 1. Show the Current Code
    syntax = Syntax(original_code, "yaml", theme="monokai", line_numbers=True)
    console.print(Panel(f"🔍 [bold]Deep Dive:[/bold] {target_file}", style="blue"))
    console.print(syntax)

    # 2. Generate a "Proposed Fix" using the Healer Engine
    # We run the linter in memory (dry_run=True) to see the result
    from kubecuro.healer import linter_engine
    
    # We read the file again to simulate what the fix would look like
    # Note: This is a simplified founder-friendly approach
    fixed_code = linter_engine(target_file, dry_run=True, return_content=True)

    if fixed_code and fixed_code != original_code:
        diff = difflib.unified_diff(
            original_code.splitlines(),
            fixed_code.splitlines(),
            fromfile="Current",
            tofile="Fixed",
            lineterm=""
        )
        diff_text = "\n".join(list(diff))
        if diff_text:
            console.print(Panel(
                Syntax(diff_text, "diff", theme="monokai"),
                title="✨ Proposed Auto-Fix",
                border_style="green"
            ))

    # 3. Show the Logic Reasons
    for issue in issues:
        explanation = EXPLAIN_CATALOG.get(issue.code.lower(), issue.message)
        
        # Grab line number if available
        line_info = getattr(issue, 'line', None)
        title_str = f"📍 Line {line_info}" if line_info else "Logic Violation"

        console.print(Panel(
            f"[bold red]ISSUE:[/bold red] {issue.code}\n[yellow]REASON:[/yellow] {explanation}",
            title=title_str,
            title_align="left",
            border_style="red"
        ))


def run():
    # Asset Integrity
    logo_path = resource_path("assets/Kubecuro Logo.png")
    if not os.path.exists(logo_path):
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
    
    subparsers.add_parser("completion").add_argument("shell", choices=["bash", "zsh"])

    argcomplete.autocomplete(parser)
    args, unknown = parser.parse_known_args()

    # --- 1. PRIORITY ROUTING ---
    if args.command == "completion":
        if args.shell == "bash":
            print('complete -o default -o nospace -C "kubecuro" "kubecuro"')
        else:
            print('#compdef kubecuro\ntype compdef >/dev/null 2>&1 || alias compdef=: \ncomplete -o default -o nospace -C "kubecuro" "kubecuro"')
        return

    if args.help or (not args.command and not args.version and not unknown):
        show_help(); return
    
    if args.version or args.command == "version":
        console.print(f"[bold magenta]KubeCuro Version:[/bold magenta] 1.0.0 ({platform.machine()})")
        return

    if args.command == "checklist":
        show_checklist(); return
    
    # --- EXPLAIN COMMAND LOGIC ---
    if args.command == "explain":
        res = args.resource.lower() if args.resource else ""
        
        # Scenario A: User points to a real file (e.g., kubecuro explain deployment.yaml)
        if os.path.exists(res):
            # 1. Quickly scan the file to find the errors
            syn, shield = Synapse(), Shield()
            syn.scan_file(res)
            file_issues = []
            for doc in syn.all_docs:
                findings = shield.scan(doc, all_docs=syn.all_docs)
                for f in findings:
                    file_issues.append(AuditIssue(
                        code=f['code'], severity=f['severity'], 
                        file=res, message=f['msg'], line=f.get('line')
                    ))
            
            # 2. Show the "Deep Dive" interactive view
            with open(res, 'r') as f:
                code = f.read()
            syntax = Syntax(code, "yaml", theme="monokai", line_numbers=True)
            console.print(Panel(f"🔍 [bold]Interactive Diagnosis:[/bold] {res}", style="blue"))
            console.print(syntax)
            
            for issue in file_issues:
                explanation = EXPLAIN_CATALOG.get(issue.code.lower(), issue.message)
                console.print(Panel(f"[bold red]ISSUE:[/bold red] {issue.code}\n[yellow]WHY:[/yellow] {explanation}", border_style="red"))
            return

        # Scenario B: User asks for a general concept (e.g., kubecuro explain hpa)
        if res in EXPLAIN_CATALOG:
            console.print(Panel(Markdown(EXPLAIN_CATALOG[res]), title=f"Logic: {res}", border_style="green"))
        else:
            console.print("[red]Please provide a valid keyword (hpa, rbac) or a filename.[/red]")
        return

    # --- 2. SMART COMMAND ROUTING ---
    command, target = args.command, getattr(args, 'target', None)
    if not command and unknown:
        if os.path.exists(unknown[0]):
            command, target = "scan", unknown[0]
        else:
            console.print(f"[bold red]Error:[/bold red] Unrecognized input: '{unknown[0]}'"); sys.exit(1)
    
    if not target or not command:
        console.print("[bold red]Error:[/bold red] Target path required."); show_help(); sys.exit(1)

    # --- 3. CORE PIPELINE ---
    console.print(Panel(f"❤️ [bold white]KubeCuro {command.upper()}[/bold white]", style="bold magenta"))
    
    syn, shield, all_issues = Synapse(), Shield(), []
    files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))] if os.path.isdir(target) else [target]
    
    if not files:
        console.print(f"\n[bold yellow]⚠ No YAML files found in:[/bold yellow] {target}"); return
   
    with console.status(f"[bold green]Processing {len(files)} files...") as status:
        for f in files:
            fname = os.path.basename(f)
            
            # 1. Load and Scan with Synapse
            syn.scan_file(f) 
            
            # 2. Healer Check
            effective_dry = True if command == "scan" else args.dry_run
            if linter_engine(f, dry_run=effective_dry):
                all_issues.append(AuditIssue(
                    code="FIXED", severity="🟡 WOULD FIX" if effective_dry else "🟢 FIXED",
                    file=fname, message="Repaired YAML syntax/API versioning.", source="Healer"
                ))

            # 3. Shield Check (Run immediately while we have the context)
            # We look at the docs just added to synapse for this specific file
            current_docs = [d for d in syn.all_docs if d.get('_origin_file') == f or len(files) == 1]
            for doc in current_docs:
                for finding in shield.scan(doc, all_docs=syn.all_docs):
                    # Filter out already-fixed deprecations in 'fix' mode
                    if command == "fix" and finding['code'] == "API_DEPRECATED":
                        if any(i.file == fname and i.code == "FIXED" for i in all_issues):
                            continue
                    
                    all_issues.append(AuditIssue(
                        code=str(finding['code']),
                        severity=str(finding['severity']),
                        file=fname,
                        message=str(finding['msg']),
                        source="Shield",
                        line=finding.get('line')
                    ))
            
    # 4. SYNAPSE AUDIT
    synapse_issues = syn.audit()
    for issue in synapse_issues:
        # Ensure every field is a string to prevent Rich rendering errors
        issue.code = str(issue.code)
        issue.severity = str(issue.severity)
        issue.message = str(issue.message)
        all_issues.append(issue)

    # --- 4. REPORTING ---
    if not all_issues:
        console.print("\n[bold green]✔ No issues found![/bold green]")
    else:
        # 1. Create the beautiful Rich table
        res_table = Table(title="\n📊 Diagnostic Report", header_style="bold cyan", box=None)
        res_table.add_column("Severity") 
        res_table.add_column("File", style="dim") 
        res_table.add_column("Message")
        
        for i in all_issues:
            # Add to Rich Table
            c = "red" if "🔴" in i.severity else "orange3" if "🟠" in i.severity else "green"
            # Create a nice "file:line" string
            loc = f"{i.file}:{i.line}" if getattr(i, 'line', None) else i.file
            res_table.add_row(f"[{c}]{i.severity}[/{c}]", loc, i.message)
            
            # 2. TEST SAFETY: Print raw text if we are in a test environment
            # This ensures pytest 'sees' the strings even if Rich formatting hides them
            if "PYTEST_CURRENT_TEST" in os.environ:
                print(f"AUDIT_LOG: {i.code} | {i.severity} | {i.message}")

        console.print(res_table)

        # Advanced Counters
        ghosts   = sum(1 for i in all_issues if i.code == 'GHOST')
        hpa_gaps = sum(1 for i in all_issues if i.code in ['HPA_LOGIC', 'HPA_MISSING_REQ'])
        security = sum(1 for i in all_issues if i.code in ['RBAC_WILD', 'SEC_PRIVILEGED', 'RBAC_SECRET'])
        api_rot  = sum(1 for i in all_issues if i.code == 'API_DEPRECATED')
        repairs  = sum(1 for i in all_issues if i.code == 'FIXED')
        remaining = len([i for i in all_issues if "FIXED" not in i.severity])
        
        sum_md = f"### 📈 Audit Summary\n"
        sum_md += f"* **Security Risks:** {security}\n"
        sum_md += f"* **Ghost Services:** {ghosts}\n"
        sum_md += f"* **HPA Logic Gaps:** {hpa_gaps}\n"
        sum_md += f"* **API Deprecations:** {api_rot}\n"
        
        if command == "fix":
            status_text = "REPAIRED" if not args.dry_run else "FIXABLE"
            sum_md += f"\n---\n**🛠️ {status_text}: {repairs}** | **⚠️ REMAINING: {remaining}**"
        else:
            sum_md += f"* **Auto-Fixable:** {repairs}"

        all_sev = str([i.severity for i in all_issues])
        if "🔴" in all_sev or security > 0 or ghosts > 0:
            border_col = "red"
        elif "🟠" in all_sev or "🟡" in all_sev:
            border_col = "yellow"
        else:
            border_col = "green"

        console.print(Panel(Markdown(sum_md), title="Final Audit Results", border_style=border_col))

        if command == "fix" and not args.dry_run and repairs > 0:
            console.print(Panel("[bold green]✔ HEAL COMPLETE: Manifests are now stable.[/bold green]", border_style="bold green", expand=False))
        elif command == "scan" and (repairs > 0 or api_rot > 0):
            console.print(f"\n[bold yellow]TIP:[/bold yellow] Run [bold cyan]kubecuro fix {target}[/bold cyan] to auto-repair deprecations.")

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        log.exception(f"FATAL ERROR: {e}"); sys.exit(1)
