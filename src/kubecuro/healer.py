#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:     The Healer Engine: Syntax Repair & API Version Migration.
--------------------------------------------------------------------------------
"""
import sys
import re
import difflib
from io import StringIO
from ruamel.yaml import YAML

# Strict relative import to ensure 100% logic alignment with Shield
from .shield import Shield

def linter_engine(file_path, apply_api_fixes=True):
    """
    1. Repairs broken YAML syntax (missing colons, tabs, etc.)
    2. Migrates deprecated API versions to stable ones using Shield's logic.
    """
    # Round-trip loader to preserve comments and formatting
    yaml = YAML(typ='rt', pure=True)
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    
    shield = Shield()
    
    try:
        with open(file_path, 'r') as f:
            original_content = f.read()

        # Split docs to handle multi-manifest files
        raw_docs = re.split(r'^---', original_content, flags=re.MULTILINE)
        healed_parts = []

        for doc_str in raw_docs:
            if not doc_str.strip():
                continue

            # --- Phase 1: Regex Syntax Healing ---
            # Fix missing colons at end of lines
            d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+)(?=[ \t]*$)', r'\1:', doc_str, flags=re.MULTILINE)
            # Fix missing space after colon
            d = re.sub(r'(^[ \t]*[\w.-]+):(?!\s| )', r'\1: ', d, flags=re.MULTILINE)
            # Replace tabs with spaces
            d = d.replace('\t', '    ')

            try:
                parsed = yaml.load(d)
                if parsed and apply_api_fixes:
                    # --- Phase 2: Logical API Healing ---
                    kind = parsed.get('kind')
                    api = parsed.get('apiVersion')
                    
                    # Check if Shield considers this API deprecated
                    # Accessing via the instance to ensure we get the full DEPRECATIONS map
                    if api in shield.DEPRECATIONS:
                        mapping = shield.DEPRECATIONS[api]
                        # Handle resource-specific mapping or default group migration
                        new_api = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
                        if new_api:
                            parsed['apiVersion'] = new_api

                if parsed:
                    buf = StringIO()
                    yaml.dump(parsed, buf)
                    healed_parts.append(buf.getvalue().strip())
            except Exception:
                # If parsing fails after regex, keep the regex-cleaned string
                healed_parts.append(d.strip())

        healed_final = "---\n" + "\n---\n".join(healed_parts) + "\n"

        # Generate Diff for the console output
        diff = list(difflib.unified_diff(
            original_content.splitlines(),
            healed_final.splitlines(),
            fromfile='Current',
            tofile='Healed',
            lineterm=''
        ))

        if not diff:
            return False # No changes made
        else:
            # Print report only if called as a script (for testing)
            if __name__ == "__main__":
                print(f"\n🩺 [DIAGNOSTIC REPORT] File: {file_path}")
                for line in diff:
                    if line.startswith('+') and not line.startswith('+++'):
                        print(f"\033[92m{line}\033[0m") # Green for adds
                    elif line.startswith('-') and not line.startswith('---'):
                        print(f"\033[91m{line}\033[0m") # Red for deletes

            with open(file_path, 'w') as f:
                f.write(healed_final)
            return True

    except Exception as e:
        print(f"\n[CRITICAL ERROR] Healer failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print("Usage: healer.py <filename.yaml>")
    else:
        # Note: Running as a script requires proper PYTHONPATH since we use relative imports
        linter_engine(sys.argv[1])
