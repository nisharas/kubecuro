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
import time

from typing import List
from argcomplete.completers import FilesCompleter

# UI and Logging Imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.progress_bar import ProgressBar

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
    "ingress_port_mismatch": """
# 🌐 Ingress Port Mismatch
The **Traffic Path** is broken.
An Ingress acts as a router, but it is trying to send traffic to a port that the Service is not listening on.
**Result:** Users will see a `503 Service Unavailable` or `502 Bad Gateway`.
**Fix:** Update the `service.port.number` in your Ingress to match one of the `ports.port` values in your Service manifest.
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
    opt_table.add_row("  -y, --yes", "Skip confirmation prompts (Auto-fix)")
    help_console.print(opt_table)

    help_console.print("\n[bold yellow]Examples:[/bold yellow]")
    help_console.print("  [dim]1. Scan a specific file for logic gaps:[/dim]")
    help_console.print("     kubecuro scan deployment.yaml")
    help_console.print("\n  [dim]2. Smart-Route (Automatic Scan if command is omitted):[/dim]")
    help_console.print("     kubecuro ./manifests/")
    help_console.print("\n  [dim]3. Automatically fix API deprecations and syntax:[/dim]")
    help_console.print("     kubecuro fix ./test-cluster/")
    help_console.print("\n  [dim]4. Preview fixes without touching the YAML files:[/dim]")
    help_console.print("     kubecuro fix service.yaml --dry-run")
    help_console.print("\n  [dim]5. Understand why KubeCuro audits RBAC:[/dim]")
    help_console.print("     kubecuro explain rbac")
    help_console.print("\n  [dim]6. Enable Autocomplete:[/dim]")
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
    """Provides a high-fidelity, colorful breakdown of a file's logic errors and proposed fixes."""
    with open(target_file, 'r') as f:
        original_code = f.read()

    # --- Header ---
    console.print(Panel(
        f"🔍 [bold white]Deep Dive Analysis:[/bold white] [cyan]{target_file}[/cyan]", 
        style="bold blue", 
        expand=True
    ))

    # --- 1. Proposed Fix (The Diff) ---
    fixed_code = linter_engine(target_file, dry_run=True, return_content=True)

    if fixed_code and fixed_code != original_code:
        diff = difflib.unified_diff(
            original_code.splitlines(),
            fixed_code.splitlines(),
            fromfile="Current",
            tofile="Healed",
            lineterm=""
        )
        diff_text = "\n".join(list(diff))
        
        if diff_text:
            diff_syntax = Syntax(diff_text, "diff", theme="monokai", background_color="default")
            console.print(Panel(
                diff_syntax,
                title="✨ [bold green]PROPOSED AUTO-REPAIR[/bold green]",
                subtitle="[dim]Green (+) = Fixed | Red (-) = Deprecated/Broken[/dim]",
                border_style="green",
                padding=(1, 2)
            ))
    else:
        console.print("[dim italic]No syntax or API repairs suggested for this file.[/dim italic]\n")

    # --- 2. The Logic Violation Breakdown ---
    if issues:
        logic_table = Table(title="🧠 Logic Violation Breakdown", box=None, header_style="bold magenta")
        logic_table.add_column("Location", style="cyan", justify="center")
        logic_table.add_column("Rule ID", style="bold red")
        logic_table.add_column("Deep Explanation", style="white")

        for issue in issues:
            raw_explanation = EXPLAIN_CATALOG.get(issue.code.lower(), issue.message)
            line_str = f"Line {issue.line}" if hasattr(issue, 'line') and issue.line else "Global"
            explanation = Markdown(raw_explanation) if "#" in str(raw_explanation) else raw_explanation
            logic_table.add_row(line_str, issue.code, explanation)
        
        console.print(logic_table)
    
    # --- 3. Optional Source Preview ---
    if console.confirm("\nView full source with line numbers?", default=False):
        syntax = Syntax(original_code, "yaml", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title="📄 Source Code Preview", border_style="dim"))

def show_resolution_guide(issues):
    """Prints a manual resolution guide for issues that couldn't be auto-fixed."""
    guide_table = Table(title="\n📘 Manual Resolution Guide", header_style="bold magenta", box=None)
    guide_table.add_column("Issue Type", style="cyan", width=20)
    guide_table.add_column("Action Required", style="white")

    codes = set(str(i.code).upper() for i in issues)

    if "GHOST" in codes:
        guide_table.add_row(
            "👻 Ghost Service", 
            "The Service selector doesn't match any Pod labels. [bold yellow]Fix:[/bold yellow] Align `spec.selector` in your Service with `spec.template.metadata.labels` in your Deployment."
        )
    if "HPA_MISSING_REQ" in codes or "HPA_LOGIC" in codes:
        guide_table.add_row(
            "📈 HPA Gap", 
            "HPA cannot scale without resource requests. [bold yellow]Fix:[/bold yellow] Add `resources.requests.cpu` or `memory` to your container spec."
        )
    if any("RBAC" in c for c in codes):
        guide_table.add_row(
            "🔑 RBAC Risk", 
            "Over-privileged service account detected. [bold yellow]Fix:[/bold yellow] Remove wildcards ('*') from your Role/ClusterRole and use specific resources."
        )

    if guide_table.row_count > 0:
        console.print(guide_table)

def run():
    start_time = time.time() 
    logo_path = resource_path("assets/Kubecuro Logo.png")
    if not os.path.exists(logo_path):
        log.debug(f"⚠️ UI Asset missing at {logo_path}")

    parser = argparse.ArgumentParser(prog="kubecuro", add_help=False)
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-y", "--yes", action="store_true", help="Auto-accept all fixes without prompting")
    
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("scan").add_argument("target", nargs="?")
    subparsers.add_parser("fix").add_argument("target", nargs="?")
    subparsers.add_parser("checklist")
    subparsers.add_parser("version")
    
    explain_p = subparsers.add_parser("explain")
    explain_p.add_argument(
        "resource", 
        nargs="?", 
        choices=list(EXPLAIN_CATALOG.keys()),
        help="Resource keyword (hpa, rbac, etc.) or path to a YAML file"
    )

    subparsers.add_parser("completion").add_argument("shell", choices=["bash", "zsh"])

    argcomplete.autocomplete(parser, validator=lambda sig, val: True)

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
        
        if os.path.exists(res):
            syn, shield = Synapse(), Shield()
            syn.scan_file(res)
            file_issues = []
            
            # 1. Collect Shield Findings
            for doc in syn.all_docs:
                findings = shield.scan(doc, all_docs=syn.all_docs)
                for f in findings:
                    file_issues.append(AuditIssue(
                        code=f['code'], 
                        severity=f['severity'], 
                        file=res, 
                        message=f['msg'], 
                        line=f.get('line'),
                        source="Shield"
                    ))
            
            # 2. Collect Synapse Findings
            synapse_findings = syn.audit()
            for sf in synapse_findings:
                # Only include if it belongs to this specific file
                if sf.file == os.path.basename(res):
                    file_issues.append(sf)
            
            interactive_explain(res, file_issues)
            return

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
        if command in ["checklist", "version", "completion"]:
            pass 
        else:
            console.print("[bold red]Error:[/bold red] Target path (file or directory) required.")
            show_help()
            sys.exit(1)

    # --- 3. CORE PIPELINE ---
    console.print(Panel(f"❤️ [bold white]KubeCuro {command.upper()}[/bold white]", style="bold magenta"))
    
    syn, shield, all_issues = Synapse(), Shield(), []
    files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))] if os.path.isdir(target) else [target]
    
    if not files:
        console.print(f"\n[bold yellow]⚠ No YAML files found in:[/bold yellow] {target}"); return
   
    with console.status(f"[bold green]Processing {len(files)} files...") as status:
        for f in files:
            fname = os.path.basename(f)
            syn.scan_file(f) 
            
            effective_dry = True if command == "scan" else args.dry_run
            
            if command == "fix" and not args.dry_run:
                fixed_content = linter_engine(f, dry_run=True, return_content=True)
                with open(f, 'r') as original:
                    original_content = original.read()
                      
                if fixed_content and fixed_content != original_content:
                    console.print(f"\n[bold yellow]🛠️ Proposed fix for {fname}:[/bold yellow]")
                    diff = difflib.unified_diff(
                        original_content.splitlines(),
                        fixed_content.splitlines(),
                        fromfile="current", tofile="proposed", lineterm=""
                    )
                    console.print(Syntax("\n".join(list(diff)), "diff", theme="monokai"))
                                    
                    if getattr(args, 'yes', False):
                        linter_engine(f, dry_run=False)
                        msg = "[bold green]FIXED:[/bold green] Applied repairs (Auto-approved)."
                    elif sys.stdin.isatty():
                        # Only prompt if we are in an interactive terminal
                        confirm = console.input(f"[bold cyan]Apply this fix to {fname}? (y/N): [/bold cyan]")
                        if confirm.lower() == 'y':
                            linter_engine(f, dry_run=False)
                            msg = "[bold green]FIXED:[/bold green] Applied API and syntax repairs."
                        else:
                            msg = "[bold yellow]SKIPPED:[/bold yellow] User declined the fix."
                    else:
                        # Non-interactive (CI/CD) and no -y flag provided
                        msg = "[bold red]SKIPPED:[/bold red] Non-interactive environment. Use -y to auto-apply."
                else:
                    msg = "No repairs needed."
            else:
                has_changes = linter_engine(f, dry_run=True)
                msg = "[bold green]API UPGRADE:[/bold green] networking.k8s.io/v1beta1 → v1" if has_changes else None
            
            if msg:
                all_issues.append(AuditIssue(
                    code="FIXED", 
                    severity="🟢 FIXED" if command == "fix" and not effective_dry else "🟡 WOULD FIX",
                    file=fname, 
                    message=msg,
                    source="Healer"
                ))

            current_docs = [d for d in syn.all_docs if d.get('_origin_file') == f or len(files) == 1]
            for doc in current_docs:
                for finding in shield.scan(doc, all_docs=syn.all_docs):
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
            
    synapse_issues = syn.audit()
    for issue in synapse_issues:
        issue.code = str(issue.code)
        issue.severity = str(issue.severity)
        issue.message = str(issue.message)
        all_issues.append(issue)

    # --- 4. REPORTING ---
    if not all_issues:
        console.print("\n[bold green]✔ No issues found![/bold green]")
    else:
        res_table = Table(title="\n📊 Diagnostic Report", header_style="bold cyan", box=None)
        res_table.add_column("Severity", width=12) 
        res_table.add_column("Location", style="dim") 
        res_table.add_column("Message")
        
        for i in all_issues:
            c = "red" if "🔴" in i.severity else "orange3" if "🟠" in i.severity else "green"
            line_info = f":{i.line}" if hasattr(i, 'line') and i.line else ""
            loc = f"{i.file}{line_info}"
            res_table.add_row(f"[{c}]{i.severity}[/{c}]", loc, i.message)
            
            if "PYTEST_CURRENT_TEST" in os.environ:
                print(f"AUDIT_LOG: {i.code} | {i.severity} | {i.message}")

        console.print(res_table)

        ghosts    = sum(1 for i in all_issues if str(i.code).upper() == 'GHOST')
        hpa_gaps  = sum(1 for i in all_issues if str(i.code).upper() in ['HPA_LOGIC', 'HPA_MISSING_REQ'])
        security  = sum(1 for i in all_issues if any(x in str(i.code).upper() for x in ['RBAC', 'PRIVILEGED', 'SECRET']))
        api_rot   = sum(1 for i in all_issues if str(i.code).upper() == 'API_DEPRECATED')
        repairs   = sum(1 for i in all_issues if str(i.code).upper() == 'FIXED')

        all_sev = str([i.severity for i in all_issues])
        if security > 0 or ghosts > 0 or "🔴" in all_sev:
            border_col = "red"
        elif hpa_gaps > 0 or "🟠" in all_sev:
            border_col = "yellow"
        else:
            border_col = "green"

        elapsed_time = time.time() - start_time
        unhealthy_files = set()
        for i in all_issues:
            if "🔴" in i.severity:
                was_fixed = any(fix.file == i.file and fix.code == "FIXED" for fix in all_issues)
                if not was_fixed: unhealthy_files.add(i.file)
            if i.code in ["GHOST", "HPA_LOGIC", "HPA_MISSING_REQ"]:
                unhealthy_files.add(i.file)

        success_rate = ((len(files) - len(unhealthy_files)) / len(files)) * 100
        if len(unhealthy_files) > 0 and success_rate > 99.9: success_rate = 99.9

        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_row("📁 [bold white]Files Scanned[/bold white]", str(len(files)))
        summary_table.add_row("⏱️  [bold cyan]Time Elapsed[/bold cyan]", f"{elapsed_time:.2f}s")
        summary_table.add_section()
        summary_table.add_row("🛡️  [bold red]Security Risks[/bold red]", str(security))
        summary_table.add_row("👻  [bold yellow]Ghost Services[/bold yellow]", str(ghosts))
        summary_table.add_row("📈  [bold blue]HPA Logic Gaps[/bold blue]", str(hpa_gaps))
        summary_table.add_section()
        summary_table.add_row("🛠️  [bold green]Auto-Fixable[/bold green]", f"[bold green]{repairs}[/bold green]")
        
        rate_color = "green" if success_rate > 80 else "yellow" if success_rate > 50 else "red"
        status_emoji = "🎯" if success_rate == 100 else "⚠️"
        summary_table.add_row(f"{status_emoji} [bold white]Final Health Score[/bold white]", f"[{rate_color}]{success_rate:.1f}%[/{rate_color}]")
        
        if all_issues:
            sec_pct = (security / len(all_issues)) * 100
            console.print(f"\n[bold white]Security Density:[/bold white] {sec_pct:.1f}%")

        footer = None
        if command == "fix":
            status_text = "REPAIRED" if not args.dry_run else "FIXABLE"
            footer = f"[bold white]{status_text}[/bold white]: {repairs} changes applied"

        console.print(Panel(summary_table, title="[bold white]Final Audit Results[/bold white]", border_style=border_col, subtitle=footer, expand=False))

        unfixed_issues = [i for i in all_issues if i.code != "FIXED"]
        if unfixed_issues:
            show_resolution_guide(unfixed_issues)
        
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
