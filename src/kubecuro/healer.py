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

class Healer:
    def __init__(self):
        # Round-trip loader preserves comments and block styles
        self.yaml = YAML(typ='rt')
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.yaml.preserve_quotes = True
        
        # --- CIRCULAR IMPORT FIX ---
        # Import Shield locally to avoid top-level dependency loops
        try:
            from kubecuro.shield import Shield
        except ImportError:
            # Fallback for local development/testing structures
            try:
                from shield import Shield
            except ImportError:
                Shield = None
        
        self.shield = Shield() if Shield else None
        self.detected_codes = set()

    def apply_security_patches(self, doc, kind):
        """Standard Security Hardening Logic."""
        if not isinstance(doc, dict): return
        
        # Target workload types
        workloads = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'Job']
        if kind in workloads or kind == 'CronJob':
            spec = doc.get('spec', {})
            
            # Handle standard nesting vs CronJob nesting
            if kind == 'CronJob':
                template = spec.get('jobTemplate', {}).get('spec', {}).get('template', {})
            else:
                template = spec.get('template', {}) if kind != 'Pod' else doc
            
            t_spec = template.get('spec') if isinstance(template, dict) else None

            if t_spec:
                # 1. Automount ServiceAccount Token
                if t_spec.get('automountServiceAccountToken') is None:
                    t_spec['automountServiceAccountToken'] = False
                
                # 2. Privileged Escalation / Privileged Mode
                containers = t_spec.get('containers', [])
                if isinstance(containers, list):
                    for c in containers:
                        s_ctx = c.get('securityContext', {})
                        if s_ctx and s_ctx.get('privileged') is True:
                            s_ctx['privileged'] = False

    def heal_file(self, file_path, apply_fixes=True, dry_run=False, return_content=False):
        try:
            if not os.path.exists(file_path): 
                return (False, set())

            with open(file_path, 'r') as f:
                original_content = f.read()

            # Split by separator
            raw_docs = re.split(r'^---', original_content, flags=re.MULTILINE)
            healed_parts = []
            self.detected_codes = set()

            for doc_str in raw_docs:
                if not doc_str.strip(): continue

                # Syntax Repair Logic
                d = re.sub(r'^(?![ \t]*#|---|-)([ \t]*[\w.-]+)$', r'\1:', doc_str, flags=re.MULTILINE)
                d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+):(?!\s|$)', r'\1: ', d, flags=re.MULTILINE)
                d = d.replace('\t', '    ')

                try:
                    parsed = self.yaml.load(d)
                    if parsed and isinstance(parsed, dict):
                        kind = parsed.get('kind')
                        api = parsed.get('apiVersion')

                        # API Migration Logic using Shield's catalog
                        if self.shield and api in self.shield.DEPRECATIONS:
                            self.detected_codes.add("API_DEPRECATED")
                            if apply_fixes:
                                mapping = self.shield.DEPRECATIONS[api]
                                new_api = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
                                if new_api and not str(new_api).startswith("REMOVED"):
                                    parsed['apiVersion'] = new_api

                        if apply_fixes:
                            self.apply_security_patches(parsed, kind)

                        buf = StringIO()
                        self.yaml.dump(parsed, buf)
                        healed_parts.append(buf.getvalue().strip())
                    else:
                        healed_parts.append(doc_str.strip())
                except Exception:
                    healed_parts.append(doc_str.strip())

            if not healed_parts: 
                return (False, set())

            prefix = "---\n" if original_content.startswith("---") else ""
            healed_final = prefix + "\n---\n".join(healed_parts) + "\n"

            # Check if changes occurred
            if original_content.strip() == healed_final.strip():
                # Even if no text changed, we return the detected codes (like API_DEPRECATED)
                return (healed_final if return_content else True, self.detected_codes)

            if return_content:
                return (healed_final, self.detected_codes)
            
            if not dry_run:
                with open(file_path, 'w') as f:
                    f.write(healed_final)
            
            return (True, self.detected_codes)
        except Exception:
            return (False, set())

def linter_engine(file_path, apply_api_fixes=True, dry_run=False, return_content=False):
    h = Healer()
    return h.heal_file(file_path, apply_api_fixes, dry_run, return_content)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: healer.py <file.yaml>")
    else:
        res, codes = linter_engine(sys.argv[1])
        if res:
            print(f"✅ Healed {sys.argv[1]} | Triggered: {codes}")
        else:
            print(f"ℹ️ No changes required for {sys.argv[1]}")
