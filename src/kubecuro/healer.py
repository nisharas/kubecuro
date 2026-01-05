#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:      The Healer Engine: Syntax Repair, API Migration, & Security Patching.
--------------------------------------------------------------------------------
"""
import sys
import re
import os
from io import StringIO
from ruamel.yaml import YAML

# Import Shield to ensure we use the same deprecation map
try:
    from .shield import Shield
except ImportError:
    from shield import Shield

class Healer:
    def __init__(self):
        # Round-trip loader preserves comments and block styles
        self.yaml = YAML(typ='rt')
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.yaml.preserve_quotes = True
        self.shield = Shield()
        # Track what we found during the process
        self.detected_codes = set()

    def apply_security_patches(self, doc, kind):
        """Injects security best practices into the YAML object."""
        if not isinstance(doc, dict):
            return

        if kind in ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet']:
            spec = doc.get('spec', {})
            template = spec.get('template', {}) if kind != 'Pod' else doc
            t_spec = template.get('spec')

            if t_spec is not None:
                # 1. FIX: Automount ServiceAccount Token
                if t_spec.get('automountServiceAccountToken') is None:
                    t_spec['automountServiceAccountToken'] = False
                
                # 2. FIX: Privileged Mode
                containers = t_spec.get('containers', [])
                if isinstance(containers, list):
                    for c in containers:
                        s_ctx = c.get('securityContext')
                        if s_ctx and s_ctx.get('privileged') is True:
                            s_ctx['privileged'] = False

    def heal_file(self, file_path, apply_fixes=True, dry_run=False, return_content=False):
        """Regex -> API Upgrade -> Security Injection."""
        try:
            if not os.path.exists(file_path):
                return False

            with open(file_path, 'r') as f:
                original_content = f.read()

            raw_docs = re.split(r'^---', original_content, flags=re.MULTILINE)
            healed_parts = []
            self.detected_codes = set()

            for doc_str in raw_docs:
                if not doc_str.strip():
                    continue

                # --- Phase 1: Syntax Repair ---
                d = re.sub(r'^(?![ \t]*#|---|-)([ \t]*[\w.-]+)$', r'\1:', doc_str, flags=re.MULTILINE)
                d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+):(?!\s|$)', r'\1: ', d, flags=re.MULTILINE)
                d = d.replace('\t', '    ')

                try:
                    parsed = self.yaml.load(d)
                    
                    if parsed and apply_fixes and isinstance(parsed, dict):
                        kind = parsed.get('kind')
                        api = parsed.get('apiVersion')

                        # --- Phase 2: API Version Migration ---
                        if api in self.shield.DEPRECATIONS:
                            # Flag that we found a deprecated API for main.py to report
                            self.detected_codes.add("API_DEPRECATED")
                            
                            mapping = self.shield.DEPRECATIONS[api]
                            if isinstance(mapping, dict):
                                new_api = mapping.get(kind, mapping.get("default"))
                            else:
                                new_api = mapping
                            
                            if new_api and not str(new_api).startswith("REMOVED"):
                                parsed['apiVersion'] = new_api

                        # --- Phase 3: Security Patching ---
                        self.apply_security_patches(parsed, kind)

                    if parsed:
                        buf = StringIO()
                        self.yaml.dump(parsed, buf)
                        healed_parts.append(buf.getvalue().strip())
                
                except Exception:
                    healed_parts.append(d.strip())

            prefix = "---\n" if original_content.startswith("---") else ""
            healed_final = prefix + "\n---\n".join(healed_parts) + "\n"

            if original_content.strip() == healed_final.strip():
                return False 

            if return_content:
                return healed_final
            
            if not dry_run:
                with open(file_path, 'w') as f:
                    f.write(healed_final)
            
            return True

        except Exception:
            return False

def linter_engine(file_path, apply_api_fixes=True, dry_run=False, return_content=False):
    h = Healer()
    result = h.heal_file(file_path, apply_api_fixes, dry_run, return_content)
    # If we are just returning content, we can't easily return the codes too 
    # unless we change the signature. For now, we keep the signature for main.py.
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: healer.py <file.yaml>")
    else:
        result = linter_engine(sys.argv[1])
        if result:
            print(f"✅ Healed {sys.argv[1]}")
        else:
            print(f"ℹ️ No changes required for {sys.argv[1]}")
