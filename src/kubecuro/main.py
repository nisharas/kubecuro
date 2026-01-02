"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
PURPOSE:        Main Entry Point for KubeCuro with Rich UI.
--------------------------------------------------------------------------------
"""
import sys
import os
import logging
import argparse
from typing import List

# UI and Logging Imports
from rich.console import Console
# Table and Panel are imported but handled within the main logic
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler

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

def run():
    """Main execution loop for KubeCuro."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-v", "--version", action="store_true")
    
    args = parser.parse_args()

    # Handle Help Menu
    if args.help or (not args.target and not args.version):
        console.print(Panel.fit(
            "💓 [bold magenta]KubeCuro[/bold magenta] | Kubernetes Logic Diagnostics\n\n"
            "[bold cyan]Usage:[/bold cyan] kubecuro <file_or_directory>\n\n"
            "[bold yellow]Options:[/bold yellow]\n"
            "  -h, --help      Show this menu\n"
            "  -v, --version   Show version info",
            title="Help", border_style="blue"
        ))
        return

    # Handle Version
    if args.version:
        console.print("[bold magenta]KubeCuro Version:[/bold magenta] 1.0.0")
        return

    # Validate Path
    target = args.target
    if not os.path.exists(target):
        log.error(f"Path '{target}' not found.")
        sys.exit(1)

    # Header Panel
    console.print(Panel("💓 [bold white]KubeCuro: Kubernetes Logic Diagnostics[/bold white]", style="bold magenta"))
    
    syn = Synapse()
    shield = Shield()
    all_issues: List[AuditIssue] = []
    
    # Identify files to scan
    if os.path.isdir(target):
        files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))]
    else:
        files = [target]

    if not files:
        log.warning(f"No YAML files found in {target}")
        return

    # --- PHASE 1: Scanning & Healing ---
    with console.status("[bold green]Analyzing manifests...") as status:
        for f in files:
            fname = os.path.basename(f)
            
            # 1. Healer (Syntax Audit)
            try:
                # linter_engine should also use pure=True internally in healer.py
                if linter_engine(f):
                    all_issues.append(AuditIssue(
                        engine="Healer", code="SYNTAX", severity="🟡 LOW", 
                        file=fname, message="Auto-healed YAML formatting", 
                        remediation="No action needed."
                    ))
            except Exception as e:
                log.error(f"Healer failed on {fname}: {e}")

            # 2. Synapse (Resource Mapping)
            syn.scan_file(f)

            # 3. Shield (API Deprecation Scan)
            try:
                from ruamel.yaml import YAML
                # FORCED PURE=TRUE TO BYPASS STATICX RPATH ERRORS
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
                                remediation="Update apiVersion to a stable version."
                            ))
            except Exception:
                pass

    # --- PHASE 2: Cross-Resource Logic Audit ---
    all_issues.extend(syn.audit())

    # --- PHASE 3: Output Table ---
    if not all_issues:
        console.print("\n[bold green]✔ All manifests healthy. No logic gaps detected.[/bold green]")
    else:
        table = Table(title="\n📊 Diagnostic Summary", show_header=True, header_style="bold cyan")
        table.add_column("File", style="dim")
        table.add_column("Engine")
        table.add_column("Severity")
        table.add_column("Issue Description")
        
        for issue in all_issues:
            table.add_row(issue.file, issue.engine, issue.severity, issue.message)
        console.print(table)

    # --- PHASE 4: Remediation Guide ---
    # Only show remediation for MED/HIGH issues to keep output clean
    critical_issues = [i for i in all_issues if i.severity != "🟡 LOW"]
    if critical_issues:
        console.print("\n[bold green]💡 FIXMYK8S REMEDIATION GUIDE:[/bold green]")
        for issue in critical_issues:
            console.print(Panel(
                f"[bold]{issue.code}:[/bold] {issue.remediation}", 
                title=f"Fix for {issue.file}", 
                border_style="yellow"
            ))

    console.print("\n[bold magenta]✔ Diagnosis Complete. Powered by FixMyK8s.[/bold magenta]")

if __name__ == "__main__":
    run()
