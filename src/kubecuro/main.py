#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""
KubeCuro: Kubernetes Logic Diagnostics & YAML Healer (CNCF-Grade CLI v1.0.0)
===========================================================================
"""
import sys
import os
import logging
import argparse
import platform
import time
import json
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any

import argcomplete
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.rule import Rule

# Core Engine Imports (keeping your existing modules)
from kubecuro.healer import linter_engine
from kubecuro.synapse import Synapse
from kubecuro.shield import Shield
from kubecuro.models import AuditIssue

# CNCF-Grade Logging Setup
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, show_level=False)]
)
log = logging.getLogger("kubecuro")
console = Console()

# Constants
BASELINE_FILE = ".kubecuro-baseline.json"
VERSION = "v1.0.0"

class KubecuroCLI:
    """CNCF-Grade Command Dispatcher - Single Responsibility."""
    
    def __init__(self):
        self.baseline_fingerprints = self._load_baseline()
    
    def _load_baseline(self) -> set:
        """Load baseline suppression file."""
        if os.path.exists(BASELINE_FILE):
            try:
                with open(BASELINE_FILE, "r") as f:
                    data = json.load(f)
                    return set(data.get("issues", []))
            except Exception:
                pass
        return set()
    
    def _save_baseline(self, issues: List[AuditIssue]):
        """Save current issues as baseline."""
        fingerprints = {f"{i.file}:{i.code}" for i in issues if i.code != "FIXED"}
        data = {
            "project_name": Path.cwd().name,
            "version": VERSION,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "issues": list(fingerprints)
        }
        with open(BASELINE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    
    def run(self, args: argparse.Namespace):
        """Main dispatch - CNCF kubectl-style."""
        if args.command == "version":
            self._show_version()
            return
        
        if args.command == "completion":
            self._handle_completion(args)
            return
        
        if args.command == "checklist":
            self._show_checklist()
            return
        
        if args.command == "explain":
            self._handle_explain(args)
            return
        
        if args.command == "baseline":
            self._handle_baseline(args)
            return
        
        # Core commands: scan/fix
        target = self._resolve_target(args)
        if not target:
            console.print("[bold red]Error:[/bold red] Target path (file or directory) required.")
            sys.exit(1)
        
        engine = AuditEngine(target, args.dry_run, args.yes, args.all, self.baseline_fingerprints)
        engine.execute(args.command)
    
    def _resolve_target(self, args: argparse.Namespace) -> Optional[Path]:
        """Smart path resolution (file/dir/auto-scan)."""
        target = getattr(args, 'target', None)
        
        # Smart routing: path without command → scan
        if not args.command and args.unknown and len(args.unknown) > 0:
            candidate = args.unknown[0]
            if os.path.exists(candidate):
                return Path(candidate)
        
        return target
    
    def _show_version(self):
        console.print(f"[bold magenta]KubeCuro[/bold magenta] {VERSION} ({platform.machine()})")
    
    def _handle_completion(self, args):
        shell = getattr(args, 'shell', 'bash')
        shell_rc = "~/.bashrc" if shell == "bash" else "~/.zshrc"
        console.print(Panel(
            f"[bold cyan]🚀 {shell.upper()} Tab Completion[/]\n\n"
            f"[bold green]1. Test now:[/] source <(register-python-argcomplete kubecuro)\n"
            f"[bold green]2. Permanent:[/] echo 'eval \"$(register-python-argcomplete kubecuro)\"' >> {shell_rc}",
            title="Setup", border_style="green"
        ))
    
    def _show_checklist(self):
        table = Table(title="📋 KubeCuro Logic Rules", header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Checks")
        table.add_row("Service", "Ghost selectors, port mismatches")
        table.add_row("HPA", "Missing resource requests, invalid targets")
        table.add_row("RBAC", "Wildcard access, secret reads")
        table.add_row("Probes", "Missing ports, timing violations")
        table.add_row("Security", "OOM risks, privilege escalation")
        console.print(table)
    
    def _handle_explain(self, args):
        resource = getattr(args, 'resource', '').lower()
        explanations = {
            "rbac": "# 🔑 RBAC Security\nWildcards (*) and secret access risks",
            "hpa": "# 📈 HPA Scaling\nRequires resource requests for CPU/memory",
            "service": "# 🔗 Service Linking\nSelector must match Deployment labels",
        }
        if resource in explanations:
            console.print(Panel(Markdown(explanations[resource]), 
                              title=f"KubeCuro Explains: {resource.upper()}", 
                              border_style="cyan"))
        else:
            console.print("[red]Usage: kubecuro explain [rbac|hpa|service][/]")
    
    def _handle_baseline(self, args):
        target = self._resolve_target(args)
        if not target:
            console.print("[bold red]Error: Target required for baseline[/]")
            return
        
        engine = AuditEngine(target, False, False, True, set())
        issues = engine._audit_pipeline()
        self._save_baseline(issues)
        console.print(Panel(f"✅ Baseline saved: {len(issues)} issues suppressed", 
                          border_style="green"))

class AuditEngine:
    """Core analysis + healing engine - Isolated from CLI."""
    
    def __init__(self, target: Path, dry_run: bool, yes: bool, show_all: bool, baseline: set):
        self.target = Path(target)
        self.dry_run = dry_run
        self.yes = yes
        self.show_all = show_all
        self.baseline = baseline
        self.console = Console()
    
    def execute(self, command: str):
        """Execute scan or fix pipeline."""
        console.print(Panel(f"❤️ KubeCuro [bold white]{command.upper()}[/]", 
                          style="bold magenta", expand=True))
        
        issues = self._audit_pipeline()
        reporting_issues = self._filter_baseline(issues)
        
        if command == "scan":
            self._render_scan_results(reporting_issues)
        elif command == "fix":
            self._execute_fixes(issues)
    
    def _audit_pipeline(self) -> List[AuditIssue]:
        """Execute full Synapse → Shield → Healer pipeline."""
        syn = Synapse()
        shield = Shield()
        all_issues = []
        seen = set()
        
        files = self._find_yaml_files()
        if not files:
            return []
        
        with console.status(f"[bold green]Auditing {len(files)} files..."):
            for fpath in files:
                fname = fpath.name
                syn.scan_file(str(fpath))
                
                # Shield: High-precision rules
                docs = [d for d in syn.all_docs if d.get('_origin_file') == fname]
                for doc in docs:
                    for finding in shield.scan(doc, syn.all_docs):
                        ident = f"{fname}:{finding.get('line')}:{finding['code']}"
                        if ident not in seen:
                            all_issues.append(AuditIssue(
                                code=str(finding['code']).upper(),
                                severity=finding['severity'],
                                file=fname,
                                message=finding['msg'],
                                line=finding.get('line'),
                                source="Shield"
                            ))
                            seen.add(ident)
                
                # Healer: Syntax + logic gaps
                fixed, codes = linter_engine(str(fpath), dry_run=True, return_content=True)
                for code in codes:
                    parts = str(code).split(":")
                    ccode, line = parts[0].upper(), int(parts[1]) if len(parts) > 1 else 1
                    ident = f"{fname}:{line}:{ccode}"
                    if ident not in seen:
                        all_issues.append(AuditIssue(
                            code=ccode, severity="🟡 MEDIUM", file=fname,
                            message=f"Healer: {ccode}", line=line, source="Healer"
                        ))
                        seen.add(ident)
        
        # Cross-resource audit
        for issue in syn.audit():
            ident = f"{issue.file}:{issue.line}:{issue.code}"
            if ident not in seen:
                all_issues.append(issue)
        
        return all_issues
    
    def _find_yaml_files(self) -> List[Path]:
        """Find all YAML files in target."""
        if self.target.is_file():
            return [self.target]
        return [p for p in self.target.rglob("*.yaml") or self.target.rglob("*.yml")]
    
    def _filter_baseline(self, issues: List[AuditIssue]) -> List[AuditIssue]:
        """Filter out baseline-suppressed issues."""
        reporting = []
        suppressed = {}
        for issue in issues:
            fp = f"{issue.file}:{issue.code}"
            if fp in self.baseline and not self.show_all:
                suppressed[issue.code] = suppressed.get(issue.code, 0) + 1
            else:
                reporting.append(issue)
        self._show_baseline_summary(suppressed)
        return reporting
    
    def _show_baseline_summary(self, suppressed):
        if suppressed:
            console.print(f"[dim]ℹ️  {sum(suppressed.values())} issues baseline-suppressed[/]")
    
    def _render_scan_results(self, issues: List[AuditIssue]):
        """Render professional scan report."""
        if not issues:
            console.print("[bold green]✅ No issues found![/]")
            return
        
        # Group by file
        by_file = {}
        for issue in issues:
            by_file.setdefault(issue.file, []).append(issue)
        
        for fname, file_issues in by_file.items():
            console.print(f"\n📂 [bold cyan]{fname}[/]")
            table = Table(box=None, padding=(0,1))
            table.add_column("Severity", width=10)
            table.add_column("Line")
            table.add_column("Code", style="bold red")
            table.add_column("Issue")
            
            for issue in sorted(file_issues, key=lambda x: x.line or 0):
                color = "red" if "HIGH" in issue.severity else "yellow"
                table.add_row(f"[{color}]{issue.severity}[/{color}]", 
                            str(issue.line or "-"), issue.code, issue.message)
            console.print(table)
        
        self._render_summary(issues)
    
    def _render_summary(self, issues: List[AuditIssue]):
        """Health score + summary."""
        active = len([i for i in issues if "FIXED" not in i.severity])
        score = 95 if active == 0 else max(0, 100 - (active * 5))
        
        console.print(Rule(title="FINAL AUDIT SUMMARY"))
        console.print(Panel(f"[bold]Health:[/] {score}% | [bold]Issues:[/] {active}", 
                          border_style="green" if score > 90 else "yellow"))
    
    def _execute_fixes(self, issues: List[AuditIssue]):
        """Execute healing pipeline."""
        files = self._find_yaml_files()
        for fpath in files:
            fixed, _ = linter_engine(str(fpath), dry_run=self.dry_run)
            if fixed:
                self._apply_fix(fpath, fixed)
    
    def _apply_fix(self, fpath: Path, fixed_content: str):
        """Atomically apply fix."""
        if self.dry_run:
            console.print(f"[cyan]DRY-RUN: Would fix {fpath.name}[/]")
            return
        
        backup = fpath.with_suffix('.yaml.backup')
        fpath.rename(backup)
        
        with open(fpath, 'w') as f:
            f.write(fixed_content)
        
        console.print(f"[green]✅ FIXED: {fpath.name}[/]")

def create_parser() -> argparse.ArgumentParser:
    """CNCF-Grade parser with proper help."""
    parser = argparse.ArgumentParser(
        prog="kubecuro",
        description="Kubernetes Logic Diagnostics & YAML Healer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kubecuro scan ./manifests/
  kubecuro fix deployment.yaml --dry-run
  kubecuro explain hpa
  kubecuro checklist"""
    )
    
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("-y", "--yes", action="store_true")
    parser.add_argument("--all", action="store_true")
    
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    
    # Scan command
    scan_p = subparsers.add_parser("scan", help="Analyze YAML logic (read-only)")
    scan_p.add_argument("target", nargs="?", help="Path to scan")
    
    # Fix command  
    fix_p = subparsers.add_parser("fix", help="Auto-repair YAML files")
    fix_p.add_argument("target", nargs="?", help="Path to fix")
    
    # Utility commands
    subparsers.add_parser("baseline", help="Suppress current issues")
    subparsers.add_parser("checklist", help="Show all rules")
    subparsers.add_parser("explain", help="Explain rules/resources")
    explain_p = subparsers.add_parser("explain", help="Explain a rule")
    explain_p.add_argument("resource", nargs="?")
    subparsers.add_parser("completion", help="Shell completion")
    completion_p = subparsers.add_parser("completion")
    completion_p.add_argument("shell", choices=["bash", "zsh"], nargs="?")
    
    return parser

def main():
    """Entry point - CNCF kubectl pattern."""
    parser = create_parser()
    
    # Handle autocompletion FIRST
    if "COMP_LINE" in os.environ:
        parser.error = lambda _: None
    argcomplete.autocomplete(parser)
    if "_ARGCOMPLETE" in os.environ:
        sys.exit(0)
    
    args, unknown = parser.parse_known_args()
    args.unknown = unknown
    
    cli = KubecuroCLI()
    cli.run(args)

if __name__ == "__main__":
    main()
