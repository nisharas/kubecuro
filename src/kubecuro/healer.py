#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
DATE:           2025-12-31
PURPOSE:        The Healer Engine: Universal K8s Linter & Auto-Remediator.
                Features Split-Stream processing for multi-doc YAML safety.
--------------------------------------------------------------------------------
"""
import sys
import re
import difflib
from io import StringIO
try:
    from ruamel.yaml import YAML
except ImportError:
    import ruamel.yaml
    YAML = ruamel.yaml.YAML

def linter_engine(file_path):
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    
    try:
        # 1. Read original manifest
        with open(file_path, 'r') as f:
            original_content = f.read()

        # ---------------------------------------------------------
        # STEP 2: SPLIT-STREAM PROCESSING
        # ---------------------------------------------------------
        # Split by '---' to handle multi-doc files individually
        raw_docs = re.split(r'^---', original_content, flags=re.MULTILINE)
        healed_parts = []

        for doc in raw_docs:
            if not doc.strip():
                continue

            # A. UNIVERSAL COLON ADDER (Comment-Safe)
            # Fixes: 'metadata' -> 'metadata:'
            d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+)(?=[ \t]*$)', r'\1:', doc, flags=re.MULTILINE)
            
            # B. SPACE INJECTOR
            # Fixes: 'image:nginx' -> 'image: nginx'
            d = re.sub(r'(^[ \t]*[\w.-]+):(?!\s| )', r'\1: ', d, flags=re.MULTILINE)

            # C. THE IMAGE/URL SHIELD
            # Fixes: image: user/repo:tag -> image: "user/repo:tag"
            d = re.sub(r'([\w.-]+:[ \t]+)([^"\s\n][^#\n]*:[^#\n]*)', r'\1"\2"', d)
            
            # D. TAB TO SPACE CONVERTER
            d = d.replace('\t', '  ')

            # Normalize via Parser
            try:
                parsed = yaml.load(d)
                if parsed:
                    buf = StringIO()
                    yaml.dump(parsed, buf)
                    healed_parts.append(buf.getvalue().strip())
            except Exception:
                # If a specific doc is too broken, keep it as is and move on
                healed_parts.append(d.strip())

        # Re-join with proper K8s separators
        healed_final = "---\n" + "\n---\n".join(healed_parts) + "\n"

        # ---------------------------------------------------------
        # STEP 3: UI REPORTING & SAVING
        # ---------------------------------------------------------
        diff = list(difflib.unified_diff(
            original_content.splitlines(),
            healed_final.splitlines(),
            fromfile='Current',
            tofile='Healed',
            lineterm=''
        ))

        print(f"\n🩺 [DIAGNOSTIC REPORT] File: {file_path}")
        print("=" * 60)
        
        if not diff:
            print("✔ Manifest is already healthy. No changes required.")
        else:
            for line in diff:
                if line.startswith('+') and not line.startswith('+++'):
                    print(f"\033[92m{line}\033[0m") # Green (Fixed)
                elif line.startswith('-') and not line.startswith('---'):
                    print(f"\033[91m{line}\033[0m") # Red (Error)
            
            with open(file_path, 'w') as f:
                f.write(healed_final)
            
            print("=" * 60)
            print(f"SUCCESS: Configuration file '{file_path}' has been healed.")

    except Exception as e:
        print(f"\n[CRITICAL ERROR] Auto-heal failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print("Usage: kubecuro <filename.yaml>")
    else:
        linter_engine(sys.argv[1])
