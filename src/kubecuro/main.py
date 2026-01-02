"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:     Main Entry Point for KubeCuro with kubectl-style sub-commands.
--------------------------------------------------------------------------------
"""
import sys
import os
import logging
import argparse
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

def show_help():
    """Displays high-level usage similar to 'kubectl --help'."""
    help_console = Console()
    help_console.print(Panel("[bold green]❤️ KubeCuro[/bold green] | Kubernetes Logic Diagnostics", expand=False))
    
    help_console.print("\n[bold yellow]Usage:[/bold yellow]")
    help_console.print("  kubecuro [command] [target] [flags]")
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("\n[bold cyan]Available Commands:[/bold cyan]", "")
    table.add_row("  scan", "Analyze manifests for logical errors (default)")
    table.add_row("  fix", "Scan and automatically repair manifests")
    table.add_row("  explain", "Describe the logic KubeCuro uses for specific resources")
    table.add_row("  version", "Print version and architecture info")
    
    table.add_row("\n[bold cyan]Global Flags:[/bold cyan]", "")
    table.add_row("  -h, --help", "Show this help message")
    table.add_row("  -v, --version", "Alias for version command")
    
    help_console.print(table)
    help_console.print("\nUse \"kubecuro [command] --help\" for more information about a command.")

def show_explain(resource: str):
    """Implementation of 'kubecuro explain' similar to 'kubectl explain'."""
    catalog = {
        "service": """
# Service Logic Audit
KubeCuro verifies that the **spec.selector** labels in your Service perfectly match the labels defined in your Pods/Deployments. 
It also checks if the **targetPort** exists in the container definition.
        """,
        "deployment": """
# Deployment Logic Audit
KubeCuro checks for 'latest' tags in images, validates replica logic, and ensures that the **matchLabels** strategy aligns with the template metadata.
        """,
        "ingress": """
# Ingress Logic Audit
KubeCuro validates that the **serviceName** and **servicePort** referenced in the Ingress rules actually exist in your scanned Service manifests.
        """
    }
    
    content = catalog.get(resource.lower())
    if content:
        console.print(Panel(Markdown(content), title=f"Explain: {resource}", border_style="cyan"))
    else:
        console.print(f"[bold red]Error:[/bold red] Resource '{resource}' is not yet supported by KubeCuro logic audits.")

def run():
    """Main execution loop for KubeCuro with Sub-command support."""
    # Main Parser
    parser = argparse.ArgumentParser(prog="kubecuro", add_help=False)
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    
    subparsers = parser.add_subparsers(dest="command")

    # Sub-command: scan
    scan_parser = subparsers.add_parser("scan", add_help=False)
    scan_parser.add_argument("target", nargs="?", help="File or directory to scan")
    scan_parser.add_argument("-h", "--help", action="store_true")

    # Sub-command: fix
    fix_parser = subparsers.add_parser("fix", add_help=False)
    fix_parser.add_argument("target", nargs="?", help="File or directory to fix")
    fix_parser.add_argument("--dry-run", action="store_true")
    fix_parser.add_argument("-h", "--help", action="store_true")

    # Sub-command: explain
    explain_parser = subparsers.add_parser("explain", add_help=False)
    explain_parser.add_argument("resource", nargs="?", help="Resource to explain (e.g., service)")
    explain_parser.add_argument("-h", "--help", action="store_true")

    args, unknown = parser.parse_known_args()

    # 1. Handle Global Help or Missing Command
    if args.help or (not args.command and not args.version):
        show_help()
        return

    # 2. Handle Version
    if args.version or args.command == "version":
        console.print("[bold magenta]KubeCuro Version:[/bold magenta] 1.0.0")
        console.print("[dim]Architecture: x86_64 Linux (Static Binary)[/dim]")
        return

    # 3. Handle Explain Command
    if args.command == "explain":
        if not args.resource or args.help:
            console.print("[bold yellow]Usage:[/bold yellow] kubecuro explain <resource_name>")
            console.print("Example: kubecuro explain service")
        else:
            show_explain(args.resource)
        return

    # 4. Handle Scan/Fix Logic
    target = args.target
    if not target:
        show_help()
        return
        
    if not os.path.exists(target):
        log.error(f"Path '{target}' not found.")
        sys.exit(1)

    # Header Panel for Execution
    console.print(Panel(f"❤️ [bold white]KubeCuro {args.command.upper()}: Kubernetes Logic Diagnostics[/bold white]", style="bold magenta"))
    
    syn = Synapse()
    shield = Shield()
    all_issues: List[AuditIssue] = []
    
    if os.path.isdir(target):
        files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))]
    else:
        files = [target]

    with console.status(f"[bold green]Running {args.command}...") as status:
        for f in files:
            fname = os.path.basename(f)
            # Healer (Syntax)
            try:
                if linter_engine(f):
                    all_issues.append(AuditIssue(
                        engine="Healer", code="SYNTAX", severity="🟡 LOW", 
                        file=fname, message="Auto-healed YAML formatting", 
                        remediation="No action needed."
                    ))
            except Exception as e: log.error(f"Healer error: {e}")

            syn.scan_file(f)

            # Shield (API)
            try:
                from ruamel.yaml import YAML
                y = YAML(typ='safe', pure=True)
                with open(f, 'r') as content:
                    docs = list(y.load_all(content))
                    for d in docs:
                        if not d: continue
                        warn = shield.check_version(d)
                        if warn:
                            all_issues.append(AuditIssue(
                                engine="Shield", code="API", severity="🟠 MED", 
                                file=fname, message=warn, 
                                remediation="Update apiVersion."
                            ))
            except: pass

    all_issues.extend(syn.audit())

    # --- Output ---
    if not all_issues:
        console.print("\n[bold green]✔ All manifests healthy.[/bold green]")
    else:
        res_table = Table(title="\n📊 Diagnostic Summary", show_header=True, header_style="bold cyan")
        res_table.add_column("File")
        res_table.add_column("Engine")
        res_table.add_column("Issue")
        for issue in all_issues:
            res_table.add_row(issue.file, issue.engine, issue.message)
        console.print(res_table)

    console.print("\n[bold magenta]✔ Process Complete. Powered by FixMyK8s.[/bold magenta]")

if __name__ == "__main__":
    run()
