import sys
import os
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

def print_help():
    print("""
💓 KubePulse: The Heartbeat of your Kubernetes Manifests

Usage:
  kubepulse <file_or_directory>

Options:
  --help     Show this heartbeat menu

Examples:
  kubepulse pod.yaml          # Heals syntax in one file
  kubepulse ./k8s-folder      # Heals and syncs all files in a folder
    """)

def run():
    if len(sys.argv) < 2 or sys.argv[1] in ["--help", "-h"]:
        print_help()
        return

    target = sys.argv[1]
    if not os.path.exists(target):
        log.error(f"❌ Path '{target}' not found.")
        return

    log.info(f"💓 KubePulse is checking the pulse of: {target}")

    # Initialize Engines
    syn = Synapse()
    shield = Shield()
    api_warnings = []
    
    # Identify files to process
    if os.path.isdir(target):
        files = [os.path.join(target, f) for f in os.listdir(target) if f.endswith(('.yaml', '.yml'))]
    else:
        files = [target]

    # Step A: Heal Syntax and Scan for Logic/APIs
    for f in files:
        # 1. Fix formatting issues (Engine 1)
        linter_engine(f)
        
        # 2. Open file to feed the Logic and Shield engines
        try:
            with open(f, 'r') as content:
                docs = list(yaml.load_all(content))
                for d in docs:
                    if not d: continue
                    # Engine 2: Logic
                    syn.scan_file(f) 
                    # Engine 3: Shield (API Versions)
                    warn = shield.check_version(d) 
                    if warn: api_warnings.append(warn)
        except Exception:
            continue

    # Step B: Final Pulse Report
    log.info("\n🔍 Analyzing system connections...")
    logic_issues = syn.audit()
    
    # Check if anything was found
    if not logic_issues and not api_warnings:
        log.info("💚 HEARTBEAT STABLE: All connections and APIs are healthy.")
    else:
        if logic_issues:
            log.info(f"⚠️  Detected {len(logic_issues)} logic irregularities:")
            print("-" * 60)
            for issue in logic_issues:
                print(f"  {issue}")
            print("-" * 60)
        
        if api_warnings:
            log.info(f"🛡️  Detected {len(api_warnings)} API version warnings:")
            print("-" * 60)
            for w in api_warnings:
                print(f"  {w}")
            print("-" * 60)

    log.info("\n✔ Pulse Check Complete.")

if __name__ == "__main__":
    run()
