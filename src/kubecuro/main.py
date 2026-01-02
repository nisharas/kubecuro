"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:     Main Entry Point for KubeCuro: Logic Diagnostics & Auto-Healing.
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

# --- Resource Explanations Catalog ---
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
    "networkpolicy": """
# 🛡️ NetworkPolicy Logic Audit
KubeCuro audits **Isolation Rules**:
1. **Targeting**: Warns if an empty `podSelector` is targeting all pods unintentionally.
2. **Namespace Check**: Validates `namespaceSelector` labels against known namespaces.
    """,
    "configmap": """
# 📦 ConfigMap & Secret Logic Audit
KubeCuro audits **Injection Logic**:
1. **Volume Mounts**: Ensures referenced ConfigMaps/Secrets exist in the bundle.
2. **Key Validation**: Checks `valueFrom` references to ensure keys exist in the target resource.
    """,
    "hpa": """
# 📈 HPA Audit
KubeCuro audits **Scaling Logic**:
1. **Target Ref**: Validates that the target Deployment/StatefulSet exists.
2. **Resources**: Warns if scaling on CPU/Mem but containers lack `resources.requests`.
    """,
    "statefulset": """
# 💾 StatefulSet Persistence Audit
KubeCuro verifies the **Identity & Storage** requirements:
1. **Headless Service**: Ensures `serviceName` points to a Service with `clusterIP: None`.
2. **Volume Templates**: Validates `volumeClaimTemplates` for correct storage class naming.
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
    help_console.print(Panel("[bold green]❤️ KubeCuro[/bold green] | Kubernetes Logic Diagnostics", expand=False))
    help_console.print("\n[bold yellow]Usage:[/bold yellow] kubecuro [command] [target]")
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("  scan", "Analyze manifests for logical errors (Read-only)")
    table.add_row("  fix", "Automatically repair syntax and API deprecations")
    table.add_row("  explain", "Describe logic used for specific resources")
    table.add_row("  checklist", "Show all logic rules")
    
    help_console.print(table)

def show_checklist():
    table = Table(title="📋 KubeCuro Logic Checklist", header_style="bold magenta")
    table.add_column("Resource", style="cyan")
    table.add_column("Audit Logic")
    table.add_row("Service", "Selector/Workload Linkage, Port Mapping")
    table.add_row("HPA", "Resource Request Presence, Target Validity")
    table.add_row("Shield", "API Version Deprecation, Security Gaps")
    console.print(table)

def run():
    parser = argparse.ArgumentParser(prog="kubecuro", add_help=False)
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("scan").add_argument("target", nargs="?")
    subparsers.add_parser("fix").add_argument("target", nargs="?")
    subparsers.add_parser("checklist")
    subparsers.add_parser("version")
    
    explain_p = subparsers.add_parser("explain")
    explain_p.add_argument("resource", nargs="?")

    args, unknown = parser.parse_known_args()

    if args.help or (not args.command and not args.version):
        show_help(); return
    if args.version or args.command == "version":
        console.print("[bold magenta]KubeCuro Version:[/bold magenta] 1.0.0"); return
    if args.command == "checklist":
        show_checklist(); return
    if args.command == "explain":
        res = args.resource.lower() if args.resource else ""
        console.print(Panel(Markdown(EXPLAIN_CATALOG.get(res, "Resource not found.")), title=f"Logic: {res}")); return

    # Target Logic
    target = getattr(args, 'target', None) or (unknown[0] if unknown else None)
    if not target or not os.path.exists(target):
        log.error("Valid target path required."); sys.exit(1)

    console.print(Panel(f"❤️ [bold white]KubeCuro {args.command.upper()}[/bold white]", style="bold magenta"))
    
    syn = Synapse()
    shield = Shield()
    all_issues = []
    
    files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))] if os.path.isdir(target) else [target]

    with console.status(f"[bold green]Processing {len(files)} files...") as status:
        for f in files:
            fname = os.path.basename(f)
            
            # 1. HEALER PHASE
            # If command is 'fix', we actually write changes. If 'scan', we just check.
            if args.command == "fix":
                if linter_engine(f):
                    all_issues.append(AuditIssue("Healer", "FIXED", "🟢 FIXED", fname, "Repaired YAML Syntax/API", "None"))
            
            # 2. SYNAPSE SCAN (Metadata Collection)
            syn.scan_file(f)

    # 3. SHIELD & SYNAPSE AUDIT (Cross-resource logic)
    # Check for API Deprecations in the docs collected by Synapse
    for doc in syn.workload_docs:
        # Check for retired APIs
        warn = shield.check_version(doc)
        if warn:
            all_issues.append(AuditIssue("Shield", "API", "🟠 MED", doc.get('_origin_file', 'unknown'), warn, "Update API version"))

    # Add the deep logic analysis results
    all_issues.extend(syn.audit())

    # --- OUTPUT RESULTS ---
    if not all_issues:
        console.print("\n[bold green]✔ No issues found. Manifests are healthy![/bold green]")
    else:
        res_table = Table(title="\n📊 Diagnostic Report", header_style="bold cyan")
        res_table.add_column("Severity"); res_table.add_column("File"); res_table.add_column("Message")
        for i in all_issues:
            res_table.add_row(i.severity, i.file, i.message)
        console.print(res_table)
        
        if args.command == "scan":
            console.print(f"\n[bold yellow]TIP:[/bold yellow] Found {len(all_issues)} issues. Run [bold cyan]kubecuro fix[/bold cyan] to auto-repair.")

if __name__ == "__main__":
    run()
