#!/usr/bin/env python3
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
import json
import tempfile

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
from rich.rule import Rule

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

BASELINE_FILE = ".kubecuro-baseline.json"

def load_baseline() -> set:
    """Reads the JSON baseline and returns a set of unique fingerprints."""
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r") as f:
                data = json.load(f)
                return set(data.get("issues", []))
        except Exception:
            return set()
    return set()

def save_baseline(issues):
    """Saves every issue found in the current scan to the baseline file."""
    fingerprints = list(set([f"{i.file}:{i.code}" for i in issues if i.code != "FIXED"]))
    data = {
        "project_name": os.path.basename(os.getcwd()),
        "created_at": time.strftime("%Y-%m-%d"),
        "issues": fingerprints
    }
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)



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
""",
    "oom_risk": """
# 📉 OOM Risk Audit
KubeCuro detects potential **Out-of-Memory** failures:
1. **Missing Limits**: Containers without memory limits can destabilize nodes.
2. **Request/Limit Gap**: Large gaps between requests and limits can lead to unpredictable eviction.
""",
    "repair": """
# ✨ KubeCuro Auto-Healing Logic
When you run `kubecuro fix`, the engine performs **Atomic Manifest Repair**:

1. **API Migration**: Automatically bumps `extensions/v1beta1` to `networking.k8s.io/v1`.
2. **Schema Correction**: Fixes indentation errors and missing mandatory fields.
3. **Safety First**: KubeCuro creates a temporary "shadow" file to test the fix before overwriting your original YAML.

**How to use:**
* Preview fixes: `kubecuro fix ./manifests --dry-run`
* Apply all: `kubecuro fix ./manifests -y`
"""
}

def show_help():
    help_console = Console()
    logo_ascii = r"""
 ██╗  ██╗██║   ██║██████╗ ███████╗ ██████╗██║   ██║██████╗  ██████╗ 
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
    help_console.print(f"  [bold cyan]kubecuro[/bold cyan] [green]<command>[/green] [white]<target>[/white] [dim][options][/dim]")
   
    help_console.print("\n[bold yellow]Main Commands:[/bold yellow]")
    cmd_table = Table(show_header=False, box=None, padding=(0, 2))
    cmd_table.add_row("  [bold cyan]scan[/bold cyan]", "Analyze manifests for logic errors (Read-only)")
    cmd_table.add_row("  [bold cyan]fix[/bold cyan]", "Automatically repair syntax and API deprecations")
    cmd_table.add_row("  [bold cyan]explain[/bold cyan]", "Learn the reasoning behind specific rules or resources. (e.g., explain hpa)")
    cmd_table.add_row("  [bold cyan]baseline[/bold cyan]",   "Suppress current issues to focus on new technical debt.")
    cmd_table.add_row("  [bold cyan]checklist[/bold cyan]", "Show all active logic rules")
    cmd_table.add_row("  [bold cyan]completion[/bold cyan]", "Setup tab-autocompletion for your shell (bash/zsh)")
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
    help_console.print("      kubecuro scan deployment.yaml")
    help_console.print("\n  [dim]2. Smart-Route (Automatic Scan if command is omitted):[/dim]")
    help_console.print("      kubecuro ./manifests-folder/")
    help_console.print("\n  [dim]3. Automatically fix API deprecations and syntax:[/dim]")
    help_console.print("      kubecuro fix ./test-cluster/")
    help_console.print("\n  [dim]4. Preview fixes without touching the YAML files:[/dim]")
    help_console.print("      kubecuro fix service.yaml --dry-run")
    help_console.print("\n  [dim]5. Get detailed logic for any resource or rule:[/dim]")
    help_console.print("      kubecuro explain rbac")
    help_console.print("\n  [dim]6. Record current issues as a baseline (Technical Debt):[/dim]")
    help_console.print("      kubecuro baseline ./manifests-folder/")
    help_console.print("\n  [dim]7. View all issues, including suppressed ones:[/dim]")
    help_console.print("      kubecuro scan ./manifests-folder/ --all")
    help_console.print("\n[dim]💡 Tip: Run 'kubecuro completion zsh' (or bash) to enable tab-autocompletion![/dim]")
    help_console.print("\n[italic white]Architecture: Static Binary / x86_64[/italic white]\n")

def show_checklist():
    table = Table(title="📋 KubeCuro Logic Checklist", header_style="bold magenta")
    table.add_column("Resource", style="cyan"); table.add_column("Audit Logic")
    table.add_row("Service", "Selector/Workload Linkage, Port Mapping")
    table.add_row("HPA", "Resource Request Presence, Target Validity")
    table.add_row("RBAC", "Wildcard Access, Secret Reading, Binding Integrity")
    table.add_row("Shield", "API Version Deprecation, Security Gaps, OOM Risks")
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
    fixed_code, _ = linter_engine(target_file, dry_run=True, return_content=True)

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
    if "OOM_RISK" in codes:
        guide_table.add_row(
            "📉 OOM Risk",
            "Workload is missing memory limits or has unsafe request ratios. [bold yellow]Fix:[/bold yellow] Define `resources.limits.memory` to prevent node instability."
        )

    if guide_table.row_count > 0:
        console.print(guide_table)

def run():
    # 1. SETUP THE PARSER
    parser = argparse.ArgumentParser(prog="kubecuro", add_help=True)
    
    # SILENCE ARGPARSE ERRORS only when probing
    if "COMP_LINE" in os.environ:
        def silent_error(message):
            # If the shell is just probing, we don't want to see "invalid choice"
            sys.exit(0)
        parser.error = silent_error

    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-y", "--yes", action="store_true")
    parser.add_argument("--all", action="store_true")

    # FIX: This tells argcomplete "Look here for commands"
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
  
    # FIX: Added help strings. Some shell completion engines use these to show hints
    subparsers.add_parser("scan", help="Scan resources")
    subparsers.add_parser("fix", help="Apply fixes")
    subparsers.add_parser("baseline", help="Manage baseline")
    subparsers.add_parser("checklist", help="Show checklist")
    subparsers.add_parser("version", help="Print version")
    
    explain_p = subparsers.add_parser("explain", help="Explain resource")
    explain_p.add_argument("resource", nargs="?")

    subparsers.add_parser("completion").add_argument("shell", choices=["bash", "zsh"])

    # 2. THE GATEKEEPER (Must run before any logic)
    argcomplete.autocomplete(parser)
    if "_ARGCOMPLETE" in os.environ:
        sys.exit(0)

    # 3. SAFE PARSING
    try:
        args, unknown = parser.parse_known_args()
    except Exception:
        sys.exit(0)

    # 4. SMART ROUTING FIX
    # If no command, check if the first unknown arg is a valid command/file
    # This prevents 'kubecuro' from being treated as a file during completion
    command = args.command
    target = getattr(args, 'target', None)

    if not command and unknown:
        if unknown[0] in ["scan", "fix", "baseline", "explain", "checklist"]:
            command = unknown[0]
            target = unknown[1] if len(unknown) > 1 else None
        elif os.path.exists(unknown[0]):
            command = "scan"
            target = unknown[0]

    # --- 5. EXECUTION ---
    start_time = time.time()
    logo_path = resource_path("assets/KubeCuro-Logo.png")
    if not os.path.exists(logo_path):
        log.debug(f"⚠️ UI Asset missing at {logo_path}")


    # Check for baseline presence early
    HAS_BASELINE = os.path.exists(BASELINE_FILE)
    
    if HAS_BASELINE and not args.all and args.command in ["scan", "fix"]:
        console.print(f"[dim]ℹ️  Baseline active ([cyan]{BASELINE_FILE}[/cyan]). Legacy issues are hidden. Use [bold]--all[/bold] to see everything.[/dim]")
    
    # --- 1. PRIORITY ROUTING ---
    if args.command == "completion":
        if args.shell in ["bash", "zsh"]:
            if sys.stdout.isatty():
                shell_rc = "~/.bashrc" if args.shell == "bash" else "~/.zshrc"
                console.print(Panel(
                    f"[bold yellow]{args.shell.capitalize()} Completion Detected[/bold yellow]\n\n"
                    f"To enable autocompletion, run:\n"
                    f"[bold cyan]source <(kubecuro completion {args.shell})[/bold cyan]\n\n"
                    f"To make it permanent, add it to your {shell_rc}",
                    title="Setup Guide"
                ))
            else:
                # argcomplete provides a universal register-python-argcomplete tool, 
                # but for a standalone binary, we output the specific shell eval.
                if args.shell == "bash":
                    print('complete -o default -o nospace -C "kubecuro" "kubecuro"')
                else:
                    # Simpler Zsh approach that works with most modern Oh-My-Zsh setups
                    print('autoload -U compinit && compinit')
                    print('complete -o default -o nospace -C "kubecuro" "kubecuro"')
                    
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
            
            # --- CONTEXT-AWARE SCANNING ---
            context_dir = os.path.dirname(os.path.abspath(res))
            for f_item in os.listdir(context_dir):
                if f_item.endswith(('.yaml', '.yml')):
                    syn.scan_file(os.path.join(context_dir, f_item))

            file_issues = []
            
            for doc in syn.all_docs:
                if doc.get('_origin_file') == os.path.basename(res):
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
            
            synapse_findings = syn.audit()
            for sf in synapse_findings:
                if sf.file == os.path.basename(res):
                    file_issues.append(sf)
            
            interactive_explain(res, file_issues)
            return

        # Check the catalog first
        explanation_text = EXPLAIN_CATALOG.get(res)
        
        if explanation_text:
            console.print(Panel(Markdown(explanation_text), title=f"KubeCuro Knowledge Base: {res.upper()}", border_style="cyan"))
        else:
            console.print("[red]Please provide a valid keyword (hpa, rbac) or a filename.[/red]")
        return

    # --- 2. SMART COMMAND ROUTING ---
    command, target = args.command, getattr(args, 'target', None)
    
    # 🛑 THIS LINE: If we are in the middle of autocompleting, STOP here.
    if "_ARGCOMPLETE" in os.environ:
        return
    
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
    console.print(Panel(f"❤️ [bold white]KubeCuro {command.upper()}[/bold white]", style="bold magenta", expand=True, title_align="center"))
    
    syn, shield, all_issues = Synapse(), Shield(), []
    seen_identifiers = set()  # UNIQUE TRACKER: fname:line:code

    if os.path.isdir(target):
        files = sorted([os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))])
    else:
        files = [target]
    
    if not files:
        console.print(f"\n[bold yellow]⚠ No YAML files found in:[/bold yellow] {target}"); return
   
    with console.status(f"[bold green]Processing {len(files)} files...") as status:
        for f in files:
            fname = os.path.basename(f)
            with open(f, 'r') as file_read:
                original_content = file_read.read()
            syn.scan_file(f) 
            
            # --- 3.1. RUN SHIELD FIRST (High-precision diagnostics) ---
            current_docs = [d for d in syn.all_docs if d.get('_origin_file') == fname]
            for doc in current_docs:
                findings = shield.scan(doc, all_docs=syn.all_docs)
                for finding in findings:
                    f_code = str(finding['code']).upper()
                    f_line = finding.get('line')

                    if f"{fname}:{f_line}:{f_code}" in seen_identifiers:
                        continue

                    is_fix_registered = any(i.file == fname and i.code == "FIXED" and "FIXED" in i.severity for i in all_issues)
                    
                    if command == "scan" or (command == "fix" and not is_fix_registered):
                        all_issues.append(AuditIssue(
                            code=f_code, 
                            severity=str(finding['severity']),
                            file=fname,
                            message=str(finding['msg']),
                            source="Shield",
                            line=f_line
                        ))
                        seen_identifiers.add(f"{fname}:{f_line}:{f_code}")

            # --- 3.2. RUN HEALER (Generic repairs & Logic gaps) ---
            fixed_content, triggered_codes = linter_engine(f, dry_run=True, return_content=True)
            
            for t_code in triggered_codes:
                # Handle both "CODE" and "CODE:LINE" formats
                parts = str(t_code).split(":")
                code_str = parts[0].upper()
                line_val = int(parts[1]) if len(parts) > 1 else 1

                # 🎯 Better Anchoring: If it says Line 1 and it's OOM_RISK, find the real line
                if line_val == 1 and code_str == "OOM_RISK":
                    for idx, line_text in enumerate(original_content.splitlines()):
                        if "image:" in line_text or "containerPort:" in line_text:
                            line_val = idx + 1
                            break
            
                # PRIORITY GATE: 
                # Skip Healer if Shield already flagged this Rule ID on this specific line
                if f"{fname}:{line_val}:{code_str}" in seen_identifiers:
                    continue
                    
                # Skip Healer's generic 'Line 1' warning if Shield found the same code 
                # anywhere else in the file (prevents double-counting file-wide issues)
                if line_val == 1 and any(id.startswith(f"{fname}:") and id.endswith(f":{code_str}") for id in seen_identifiers):
                    continue
            
                # Assign appropriate messaging
                msg = f"Logic gap detected by Healer engine: {code_str}"
                if "DEPRECATED" in code_str:
                    msg = f"API Version '{code_str}' is deprecated and will be removed in future K8s releases."
            
                # Standardized Severity Mapping
                if "DEPRECATED" in code_str:
                    sev, msg = "🔵 INFO", f"API Version '{code_str}' is deprecated. Auto-fix available."
                elif "OOM_RISK" in code_str:
                    sev, msg = "🟠 HIGH", "Memory limits missing. Risk of Node instability."
                else:
                    sev, msg = "🟡 MEDIUM", f"Logic gap detected: {code_str}"

                all_issues.append(AuditIssue(
                    code=code_str,
                    severity=sev,
                    file=fname,
                    line=line_val,
                    message=msg,
                    source="Healer"
                ))
                
                seen_identifiers.add(f"{fname}:{line_val}:{code_str}")

            # --- 3.3. AUTO-FIX PIPELINE ---
            if fixed_content and fixed_content.strip() != original_content.strip():
                if command == "fix":
                    status.stop()
                    diff = list(difflib.unified_diff(
                        original_content.splitlines(),
                        fixed_content.splitlines(),
                        fromfile="current", tofile="proposed", lineterm=""
                    ))

                    if args.dry_run:
                        console.print(f"\n[bold cyan]🔍 DRY RUN: Proposed changes for {fname}:[/bold cyan]")
                        console.print(Syntax("\n".join(diff), "diff", theme="monokai"))

                        all_issues.append(AuditIssue(
                            code="REPAIR", severity="✨ AUTO", file=fname, 
                            message="Automated repairs are available for this file. Run 'fix' to apply.", source="Healer"
                        ))
                        
                        status.start()
                        continue 

                    console.print(f"\n[bold yellow]🛠️ Proposed fix for {fname}:[/bold yellow]")
                    console.print(Syntax("\n".join(diff), "diff", theme="monokai"))
                    
                    do_fix = False
                    if args.yes:
                        do_fix = True
                    elif sys.stdin.isatty():
                        try:
                            confirm = console.input(f"[bold cyan]👉 Apply this fix to {fname}? (y/N): [/bold cyan]").strip().lower()
                            if confirm == 'y':
                                do_fix = True
                        except (EOFError, KeyboardInterrupt):
                            console.print("\n[bold red]Skipping fix due to interruption.[/bold red]")
                            do_fix = False
                    
                    if do_fix:
                        target_path = os.path.abspath(f)
                        target_dir = os.path.dirname(target_path)
                        
                        fd, temp_path = tempfile.mkstemp(dir=target_dir, text=True, suffix='.yaml')
                        try:
                            with os.fdopen(fd, 'w') as tmp:
                                tmp.write(fixed_content)
                            
                            os.replace(temp_path, target_path)
                            
                            all_issues.append(AuditIssue(
                                code="HEALED", severity="🟢 FIXED", file=fname, 
                                message="[bold green]FIXED:[/bold green] Applied repairs atomically.", 
                                source="Healer"
                            ))
                        except Exception as e:
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                            log.error(f"Failed to save changes to {fname}: {e}")
                    else:
                        all_issues.append(AuditIssue(
                            code="FIXED", severity="🟡 SKIPPED", file=fname, 
                            message="[bold yellow]SKIPPED:[/bold yellow] Fix declined.", source="Healer"
                        ))
                    
                    status.start()
                    continue 
                else:
                    # This triggers during a 'scan' if a fix is possible but not yet applied
                    all_issues.append(AuditIssue(
                        code="REPAIR", 
                        severity="🔵 INFO", 
                        file=fname, 
                        message="[bold cyan]Healer:[/bold cyan] Automated repairs available. Run [italic]kubecuro fix[/italic] to apply.", 
                        source="Healer"
                    ))
            
    # --- 3.4. CROSS-RESOURCE AUDIT (Synapse) ---
    synapse_findings = syn.audit()
    for issue in synapse_findings:
        issue.code = str(issue.code).upper()
        if f"{issue.file}:{issue.line}:{issue.code}" not in seen_identifiers:
            all_issues.append(issue)
            seen_identifiers.add(f"{issue.file}:{issue.line}:{issue.code}")

    # === BASELINE & SUPPRESSION LOGIC ===
    baseline_fingerprints = load_baseline()
    
    if command == "baseline":
        save_baseline(all_issues)
        console.print(Panel(f"✅ BASELINE CREATED: {len(all_issues)} issues recorded and suppressed.", border_style="green"))
        return

    reporting_issues = []
    legacy_summary = {}

    for issue in all_issues:
        fingerprint = f"{issue.file}:{issue.code}"
        if fingerprint in baseline_fingerprints and not args.all:
            legacy_summary[issue.code] = legacy_summary.get(issue.code, 0) + 1
        else:
            reporting_issues.append(issue)

    # --- 4. REPORTING ---
        if not reporting_issues:
            console.print("\n[bold green]✔ No new issues found![/bold green]")
        else:
            issues_by_file = {}
            for i in reporting_issues:
                issues_by_file.setdefault(i.file, []).append(i)

            for filename, file_issues in issues_by_file.items():
                console.print(f"\n📂 [bold white]LOCATION: {filename}[/bold white]")
                res_table = Table(header_style="bold cyan", box=None, show_header=True)
                res_table.add_column("Severity", width=12) 
                res_table.add_column("Line", style="grey70", justify="right", width=6)
                res_table.add_column("Rule ID", style="bold red", width=15) 
                res_table.add_column("Message")
                
                for i in sorted(file_issues, key=lambda x: (x.line if x.line else 0)):
                    if "CRITICAL" in i.severity or "HIGH" in i.severity: c = "red"
                    elif "MEDIUM" in i.severity: c = "yellow"
                    elif "INFO" in i.severity: c = "blue"
                    elif "AUTO" in i.severity or "FIXED" in i.severity: c = "green"
                    else: c = "white"

                    line_display = str(i.line) if i.line else "-"
                    res_table.add_row(f"[{c}]{i.severity}[/{c}]", line_display, i.code, i.message)
                console.print(res_table)

        # --- 5. FINAL SUMMARY LOGIC ---
        active_issues = len([i for i in reporting_issues if "FIXED" not in i.severity and "HEALED" not in i.code])
        suppressed_count = sum(legacy_summary.values())
        total_found = active_issues + suppressed_count
        
        # 📊 Calculate Health Score & Risk Level
        if total_found == 0:
            success_rate = 100
            risk_level = "[bold green]LOW[/bold green] ✅"
            panel_color = "green"
        elif active_issues == 0:
            success_rate = 100
            risk_level = "[bold cyan]STABLE (Baseline Active)[/bold cyan] 🛡️"
            panel_color = "cyan"
        else:
            success_rate = max(0, int(((total_found - active_issues) / total_found) * 100))
            if success_rate > 80:
                risk_level = "[bold yellow]MEDIUM[/bold yellow] ⚠️"
                panel_color = "yellow"
            else:
                risk_level = "[bold red]HIGH[/bold red] 🚨"
                panel_color = "red"

        # Count specific categories for the table
        api_rot = sum(1 for i in reporting_issues if "REPAIR" in str(i.code).upper())
        repairs_applied = sum(1 for i in reporting_issues if "HEALED" in str(i.code).upper())
        
        console.print("\n", Rule(title="[bold white]FINAL AUDIT SUMMARY[/bold white]", style="dim"), "\n")
        
        # Display the Risk Gauge first
        console.print(Panel(
            f"  [bold]Health Score:[/bold] {success_rate}%  |  [bold]Risk Level:[/bold] {risk_level}",
            border_style=panel_color,
            expand=False
        ))

        summary_table = Table(show_header=True, box=None, padding=(0, 2), header_style="bold magenta")
        summary_table.add_column("Category")
        summary_table.add_column("Active", justify="right")
        summary_table.add_column("Suppressed", justify="right")

        summary_table.add_row("🛡️  Active Risks", str(active_issues), str(suppressed_count))
        summary_table.add_row("✨  Auto-Repairs Avail.", str(api_rot), "0")
        summary_table.add_row("🟢  Repairs Applied", str(repairs_applied), "0")

        console.print(summary_table)

        # 🏆 Celebration for Perfect Health
        if success_rate == 100 and active_issues == 0:
            console.print(Panel(
                "[bold green]🎉 CONGRATULATIONS! Your infrastructure is optimized.[/bold green]\n"
                "[white]No active logic gaps or security threats were detected.[/white]",
                title="✨ [bold gold1]ELITE STATUS[/bold gold1]",
                border_style="green",
                expand=False,
                padding=(1, 4)
            ))
        
        if api_rot > 0 and command == "scan":
            console.print(Panel(f"✨ [bold green]Healer Tip:[/bold green] {api_rot} automated repairs are available. Run [bold cyan]kubecuro fix[/bold cyan] to heal these manifests.", border_style="green"))

        duration = round(time.time() - start_time, 2)
        console.print(f"\n[dim]Audit completed in {duration}s | Files: {len(files)}[/dim]\n")

if __name__ == "__main__":
    run()
