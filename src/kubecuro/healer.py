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
        try:
            from kubecuro.shield import Shield
        except ImportError:
            try:
                from shield import Shield
            except ImportError:
                Shield = None
        
        self.shield = Shield() if Shield else None
        self.detected_codes = set()

    def apply_security_patches(self, doc, kind, global_line_offset=0):
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
            
            if isinstance(template, dict):
                t_spec = template.get('spec')
                if t_spec and isinstance(t_spec, dict):
                    # 1. Automount ServiceAccount Token - NON-TECHNICAL FIX:
                    # We no longer force this to False because it can break app connectivity.
                    # We just flag it for the user to see.
                    if t_spec.get('automountServiceAccountToken') is None:
                        self.detected_codes.add(f"SEC_TOKEN_AUDIT:{global_line_offset}")
                    
                    # 2. Privileged Escalation / Privileged Mode
                    containers = t_spec.get('containers', [])
                    if isinstance(containers, list):
                        for c in containers:
                            if not isinstance(c, dict): continue
                            s_ctx = c.get('securityContext', {})
                            if s_ctx and s_ctx.get('privileged') is True:
                                # This is safe to auto-fix as 'privileged' is rarely required
                                s_ctx['privileged'] = False
                                self.detected_codes.add(f"SEC_PRIVILEGED:{global_line_offset}")

    def heal_file(self, file_path, apply_fixes=True, dry_run=False, return_content=False):
        try:
            if not os.path.exists(file_path): 
                return (None if return_content else False, set())

            with open(file_path, 'r') as f:
                original_content = f.read()

            # Refined split to avoid splitting on comments containing ---
            raw_docs = re.split(r'^---\s*$', original_content, flags=re.MULTILINE)
            healed_parts = []
            self.detected_codes = set()
            
            # Track cumulative line numbers for multi-doc reporting
            current_line_offset = 1 if not original_content.startswith("---") else 2

            for doc_str in raw_docs:
                if not doc_str.strip(): 
                    # Maintain line count even for empty chunks
                    current_line_offset += doc_str.count('\n') + 1
                    continue

                # Syntax Repair Logic - Conservative cleanup
                d = doc_str.replace('\t', '    ')
                # Ensure keys have spaces after colons: 'key:value' -> 'key: value'
                d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+):(?!\s|$)', r'\1: ', d, flags=re.MULTILINE)

                try:
                    # Parse the document
                    parsed = self.yaml.load(d)
                    if parsed and isinstance(parsed, dict):
                        kind = parsed.get('kind')
                        api = parsed.get('apiVersion')

                        # API Migration Logic using Shield's catalog
                        if self.shield and api in self.shield.DEPRECATIONS:
                            # FIND EXACT LINE NUMBER WITHIN THIS DOC
                            doc_lines = doc_str.splitlines()
                            relative_line = 1
                            for i, line in enumerate(doc_lines):
                                if "apiVersion:" in line and api in line:
                                    relative_line = i + 1
                                    break
                            
                            # Calculate global line number
                            global_line = current_line_offset + (relative_line - 1)
                            self.detected_codes.add(f"API_DEPRECATED:{global_line}")
                            
                            if apply_fixes:
                                mapping = self.shield.DEPRECATIONS[api]
                                # Handle dict mapping vs string mapping
                                new_api = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
                                if new_api and not str(new_api).startswith("REMOVED"):
                                    parsed['apiVersion'] = new_api

                        # Apply security audits/patches (Passing the current line offset for better reporting)
                        self.apply_security_patches(parsed, kind, global_line_offset=current_line_offset)

                        buf = StringIO()
                        self.yaml.dump(parsed, buf)
                        healed_parts.append(buf.getvalue().rstrip())
                    else:
                        healed_parts.append(doc_str.strip())
                except Exception:
                    # If parsing fails, keep the original doc fragment
                    healed_parts.append(doc_str.strip())
                
                # Update offset for next document: text lines + the --- separator
                current_line_offset += doc_str.count('\n') + 1

            if not healed_parts: 
                return (None if return_content else False, set())

            # Reconstruct the file
            prefix = "---\n" if original_content.startswith("---") else ""
            healed_final = prefix + "\n---\n".join(healed_parts) + "\n"

            # Check if text actually changed (ignoring surrounding whitespace)
            content_changed = original_content.strip() != healed_final.strip()

            if return_content:
                return (healed_final, self.detected_codes)
            
            if content_changed and not dry_run:
                with open(file_path, 'w') as f:
                    f.write(healed_final)
            
            return (content_changed, self.detected_codes)
            
        except Exception:
            return (None if return_content else False, set())

def linter_engine(file_path, apply_api_fixes=True, dry_run=False, return_content=False):
    h = Healer()
    return h.heal_file(file_path, apply_api_fixes, dry_run, return_content)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: healer.py <file.yaml>")
    else:
        res, codes = linter_engine(sys.argv[1], dry_run=True)
        if codes:
            print(f"✅ Analyzed {sys.argv[1]} | Issues: {codes}")
        else:
            print(f"ℹ️ No issues detected for {sys.argv[1]}")
