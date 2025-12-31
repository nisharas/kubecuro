"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
DATE:           2025-12-31
PURPOSE:        The Main Entry Point for KubeCuro. Orchestrates the Healer, 
                Shield, and Synapse engines to generate a Health Summary.
--------------------------------------------------------------------------------
"""
import sys
import os
from tabulate import tabulate
from .healer import linter_engine
from .synapse import Synapse
from .shield import Shield
from .logger import get_logger

try:
    from ruamel.yaml import YAML
except ImportError:
    import ruamel.yaml
    YAML = ruamel.yaml.YAML

log = get_logger()
yaml = YAML()

# 🧠 Knowledge Base for the Table and Remediation Guide
ISSUE_INTEL = {
    "GHOST": {"sev": "🔴 HIGH", "fix": "👉 [GHOST]: Update Service 'selector' to match Pod 'labels'."},
    "PORT": {"sev": "🔴 HIGH", "fix": "👉 [PORT]: Align Service 'targetPort' with Pod 'containerPort'."},
    "NAMESPACE": {"sev": "🟠 MED", "fix": "👉 [NAMESPACE]: Move Service and Pod to the same namespace."},
    "API": {"sev": "🟠 MED", "fix": "👉 [API]: Update 'apiVersion' to a stable version (e.g., networking.k8s.io/v1)."},
    "SYNTAX": {"sev": "🟡 LOW", "fix": "👉 [SYNTAX]: Indentation/Formatting was auto-healed."}
}

def print_help():
    print("""
✨ KubeCuro: The Cure for your Kubernetes Manifests

Usage:
  kubecuro <file_or_directory>

Options:
  --help      Show this heartbeat menu

Examples:
  kubecuro pod.yaml          # Heals and diagnoses one file
  kubecuro ./k8s-folder      # Heals and scans an entire directory
    """)

def run():
    if len(sys.argv) < 2 or sys.argv[1] in ["--help", "-h"]:
        print_help()
        return

    target = sys.argv[1]
    if not os.path.exists(target):
        log.error(f"❌ Path '{target}' not found.")
        return

    log.info(f"✨ KubeCuro is diagnosing: {os.path.abspath(target)}")

    syn = Synapse()
    shield = Shield()
    
    # Track results for the final table
    # Format: { filename: {"sev": "", "engine": "", "issues": [], "status": ""} }
    report_card = {}

    # Identify files to process
    if os.path.isdir(target):
        files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))]
    else:
        files = [target]

    # --- PHASE 1: Syntax Healing & Individual File Scanning ---
    for f in files:
        fname = os.path.basename(f)
        report_card[fname] = {"sev": "🟢 NONE", "engine": "Healthy", "issues": [], "status": "✨ Healthy"}
        
        # 1. Healer Engine (Syntax)
        healed = linter_engine(f)
        if healed:
            report_card[fname].update({"sev": "🟡 LOW", "engine": "Healer", "status": "✅ Healed"})
            report_card[fname]["issues"].append("SYNTAX")

        # 2. Feed Synapse & Shield
        try:
            with open(f, 'r') as content:
                docs = list(yaml.load_all(content))
                # Feed Synapse the file for label/port mapping
                syn.scan_file(f) 
                
                for d in docs:
                    if not d: continue
                    # Engine: Shield (API Versions)
                    warn = shield.check_version(d)
                    if warn:
                        report_card[fname].update({"sev": "🟠 MED", "engine": "Shield", "status": "⚠️ Warning"})
                        if "API" not in report_card[fname]["issues"]:
                            report_card[fname]["issues"].append("API")
        except Exception:
            continue

    # --- PHASE 2: Logic Audit (Connections) ---
    log.info("\n🔍 Analyzing system connections...")
    logic_logs = syn.audit()
    
    # Print detailed logic logs to terminal
    if logic_logs:
        log.info(f"⚠️  Detected {len(logic_logs)} logic irregularities:")
        print("-" * 65)
        for issue in logic_logs:
            print(f"  {issue}")
        print("-" * 65)

    # Map structured logic issues back to the report card
    for fname, issue_set in syn.files_with_issues.items():
        if fname in report_card:
            # Upgrade engine status if previous issues existed
            engine_name = "Synapse" if report_card[fname]["engine"] == "Healthy" else "Multi"
            report_card[fname].update({
                "sev": "🔴 HIGH", 
                "engine": engine_name, 
                "status": "❌ Logic Gap"
            })
            for issue_code in issue_set:
                if issue_code not in report_card[fname]["issues"]:
                    report_card[fname]["issues"].append(issue_code)

    # --- PHASE 3: Generate Summary Table ---
    table_data = []
    all_detected_issues = set()
    
    for fname in sorted(report_card.keys()):
        data = report_card[fname]
        table_data.append([
            fname, 
            data["sev"], 
            data["engine"], 
            ", ".join(sorted(data["issues"])) if data["issues"] else "None", 
            data["status"]
        ])
        all_detected_issues.update(data["issues"])

    print("\n📊 FINAL HEALTH SUMMARY (KubeCuro)")
    print(tabulate(table_data, headers=["File Name", "Severity", "Engine", "Issues Found", "Status"], tablefmt="grid"))

    # --- PHASE 4: Generate Remediation Guide ---
    if all_detected_issues:
        print("\n💡 SUGGESTED REMEDIATIONS:")
        print("=" * 72)
        for issue in sorted(all_detected_issues):
            if issue in ISSUE_INTEL:
                print(ISSUE_INTEL[issue]["fix"])
        print("=" * 72)

    log.info("\n✔ Diagnosis Complete.")

if __name__ == "__main__":
    run()
