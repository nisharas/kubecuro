"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
PURPOSE:        Main Entry Point for KubeCuro with Rich UI.
--------------------------------------------------------------------------------
"""
import sys
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
import logging

from .healer import linter_engine
from .synapse import Synapse
from .shield import Shield
from .models import AuditIssue  
from .utils.logger import get_logger Shield

# Setup Rich Logging
logging.basicConfig(level="INFO", format="%(message)s", datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True)])
log = logging.getLogger("rich")
console = Console()

def run():
    if len(sys.argv) < 2:
        console.print("[bold cyan]Usage: kubecuro <file_or_directory>[/bold cyan]")
        return

    target = sys.argv[1]
    if not os.path.exists(target):
        log.error(f"Path '{target}' not found.")
        return

    console.print(Panel.heading("💓 KubeCuro: Kubernetes Logic Diagnostics", style="bold magenta"))
    
    syn = Synapse()
    shield = Shield()
    all_issues: List[AuditIssue] = []
    
    files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))] if os.path.isdir(target) else [target]

    # --- PHASE 1: Scanning & Healing ---
    with console.status("[bold green]Healing and Scanning manifests...") as status:
        for f in files:
            fname = os.path.basename(f)
            
            # 1. Healer
            if linter_engine(f):
                all_issues.append(AuditIssue("Healer", "SYNTAX", "🟡 LOW", fname, "Auto-healed YAML formatting", "No action needed."))

            # 2. Synapse Scan
            syn.scan_file(f)

            # 3. Shield Scan
            try:
                from ruamel.yaml import YAML
                y = YAML()
                with open(f, 'r') as content:
                    docs = list(y.load_all(content))
                    for d in docs:
                        warn = shield.check_version(d)
                        if warn:
                            all_issues.append(AuditIssue("Shield", "API", "🟠 MED", fname, warn, "Update apiVersion to stable."))
            except Exception: pass

    # --- PHASE 2: Logic Audit ---
    all_issues.extend(syn.audit())

    # --- PHASE 3: Output Table ---
    table = Table(title="\n📊 Diagnostic Summary", show_header=True, header_style="bold cyan", border_style="dim")
    table.add_column("File", style="dim")
    table.add_column("Engine")
    table.add_column("Severity")
    table.add_column("Issue Description")
    
    for issue in all_issues:
        table.add_row(issue.file, issue.engine, issue.severity, issue.message)

    console.print(table)

    # --- PHASE 4: Remediation Guide ---
    if all_issues:
        console.print("\n[bold green]💡 FIXMYK8S REMEDIATION GUIDE:[/bold green]")
        for issue in all_issues:
            if issue.severity != "🟡 LOW": # Only show critical fixes
                console.print(Panel(f"[bold]{issue.code}:[/bold] {issue.remediation}", 
                                    title=f"Fix for {issue.file}", border_style="yellow"))

    console.print("\n[bold magenta]✔ Diagnosis Complete. Powered by FixMyK8s.[/bold magenta]")

if __name__ == "__main__":
    run()
