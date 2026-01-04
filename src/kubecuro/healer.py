#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:      The Healer Engine: Syntax Repair & API Version Migration.
--------------------------------------------------------------------------------
"""
import sys
import re
import difflib
import os
# Use StringIO to capture YAML output into a string variable
from io import StringIO
from ruamel.yaml import YAML

# Strict relative import to ensure 100% logic alignment with Shield
try:
    from .shield import Shield
except ImportError:
    from shield import Shield

def linter_engine(file_path, apply_api_fixes=True, dry_run=False, return_content=False):
    """
    1. Repairs broken YAML syntax (missing colons, tabs, etc.)
    2. Migrates deprecated API versions to stable ones using Shield's logic.
    3. Respects dry-run flag to prevent accidental writes.
    """
    # Round-trip loader ('rt') is essential to preserve comments and formatting
    yaml = YAML(typ='rt', pure=True)
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    
    shield = Shield()
    
    try:
        if not os.path.exists(file_path):
            return False

        with open(file_path, 'r') as f:
            original_content = f.read()

        # Split docs to handle multi-manifest files safely
        # We filter out empty strings to avoid creating "empty" documents
        raw_docs = re.split(r'^---', original_content, flags=re.MULTILINE)
        healed_parts = []

        for doc_str in raw_docs:
            if not doc_str.strip():
                continue

            # --- Phase 1: Regex Syntax Healing ---
            # Fix missing colons at end of lines (common typo)
            d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+)(?=[ \t]*$)', r'\1:', doc_str, flags=re.MULTILINE)
            # Fix missing space after colon
            d = re.sub(r'(^[ \t]*[\w.-]+):(?!\s| )', r'\1: ', d, flags=re.MULTILINE)
            # Replace tabs with spaces (Kubernetes YAML standard)
            d = d.replace('\t', '    ')

            try:
                # Load the regex-cleaned string into the round-trip parser
                parsed = yaml.load(d)
                
                if parsed and apply_api_fixes:
                    # --- Phase 2: Logical API Healing (Shield Integration) ---
                    kind = parsed.get('kind')
                    api = parsed.get('apiVersion')
                    
                    if api in shield.DEPRECATIONS:
                        mapping = shield.DEPRECATIONS[api]
                        # Look for specific resource replacement (e.g., Ingress) or use default
                        new_api = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
                        
                        if new_api and not str(new_api).startswith("REMOVED"):
                            parsed['apiVersion'] = new_api

                if parsed:
                    buf = StringIO()
                    yaml.dump(parsed, buf)
                    healed_parts.append(buf.getvalue().strip())
            
            except Exception:
                # If parsing fails after regex (e.g. deep indentation error), 
                # keep the regex-cleaned string as the best effort.
                healed_parts.append(d.strip())
        
        # Reconstruct the multi-doc YAML file
        healed_final = "---\n" + "\n---\n".join(p.strip() for p in healed_parts if p.strip()) + "\n"

        # Generate Diff to check if changes actually occurred
        diff = list(difflib.unified_diff(
            original_content.splitlines(),
            healed_final.splitlines(),
            fromfile='Current',
            tofile='Healed',
            lineterm=''
        ))

        if not diff:
            return False # No healing needed, file is already healthy
        
        # --- Phase 3: Commit Logic ---
        if return_content:
            return healed_final # Give the text back to the caller (main.py)
        if not dry_run:
            with open(file_path, 'w') as f:
                f.write(healed_final)
            return True
        else:
            # In dry-run, we return True if changes *would* have been made
            # This allows main.py to still report it as a "detected issue"
            return True

    except Exception:
        # Prevent the tool from crashing on a single bad file
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print("Usage: healer.py <filename.yaml>")
    else:
        # Manual test mode for single file debugging
        success = linter_engine(sys.argv[1])
        if success:
            print(f"✅ Successfully healed {sys.argv[1]}")
        else:
            print(f"ℹ️ No changes needed or error occurred in {sys.argv[1]}")
