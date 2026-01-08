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
import logging
from typing import Tuple, Union, Optional, Set
from io import StringIO
from pathlib import Path
from ruamel.yaml import YAML

logger = logging.getLogger(__name__)

class Healer:
    def __init__(self):
        # Round-trip loader preserves comments and block styles
        self.yaml = YAML(typ='rt')
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.yaml.preserve_quotes = True
        
        # --- CIRCULAR IMPORT FIX + SHIELD INTEGRATION ---
        try:
            from kubecuro.shield import Shield
            self.shield = Shield()
        except ImportError:
            try:
                from shield import Shield
                self.shield = Shield()
            except ImportError:
                self.shield = None
        
        self.detected_codes: Set[str] = set()

    def get_line(self, obj: any, key: Optional[str] = None) -> int:
        """Extract line number from ruamel.yaml object (copied from Shield)."""
        try:
            if obj is None:
                return 1
            
            if key and hasattr(obj, 'lc') and hasattr(obj.lc, 'data') and key in obj.lc.data:
                return obj.lc.data[key][0] + 1
            
            if hasattr(obj, 'lc') and hasattr(obj.lc, 'line'):
                return obj.lc.line + 1
            
            return 1
        except Exception:
            return 1

    def apply_security_patches(self, doc: dict, kind: str, global_line_offset: int = 0) -> None:
        """Standard Security Hardening & Stability Patching with accurate line numbers."""
        if not isinstance(doc, dict): 
            return
        
        # Target workload types
        workloads = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob']
        if kind not in workloads:
            return
            
        spec = doc.get('spec', {})
        
        # 1. Navigation: Extract the Pod Spec (t_spec)
        if kind == 'CronJob':
            # CronJob -> jobTemplate -> spec -> template -> spec
            job_tmpl = spec.get('jobTemplate', {})
            template = job_tmpl.get('spec', {}).get('template', {})
        else:
            template = spec.get('template', {}) if kind != 'Pod' else doc
        
        if not isinstance(template, dict): 
            return
        t_spec = template.get('spec')
        if not t_spec or not isinstance(t_spec, dict): 
            return

        # 2. SEC_TOKEN_AUDIT: Flag it (Keep your current policy of not auto-fixing)
        if t_spec.get('automountServiceAccountToken') is None:
            token_line = self.get_line(t_spec, 'automountServiceAccountToken')
            self.detected_codes.add(f"SEC_TOKEN_AUDIT:{token_line}")

        # 3. Container-level fixes (OOM_RISK & PRIVILEGED) - CONTAINER-SPECIFIC LINES
        containers = t_spec.get('containers', [])
        if isinstance(containers, list):
            for c in containers:
                if not isinstance(c, dict): 
                    continue
                
                container_line = self.get_line(c)
                
                # --- FIX: OOM_RISK (Missing Resource Limits) ---
                res = c.get('resources', {})
                if 'limits' not in res:
                    # Initialize resources if totally missing
                    if 'resources' not in c:
                        c['resources'] = {}
                    
                    # Inject conservative default limits (ruamel-compatible)
                    c['resources']['limits'] = {
                        'cpu': '500m',
                        'memory': '256Mi'
                    }
                    self.detected_codes.add(f"OOM_RISK:{container_line}")

                # --- FIX: SEC_PRIVILEGED ---
                s_ctx = c.get('securityContext', {})
                if isinstance(s_ctx, dict) and s_ctx.get('privileged') is True:
                    s_ctx['privileged'] = False
                    self.detected_codes.add(f"SEC_PRIVILEGED:{container_line}")

    def heal_file(self, 
                  file_path: str, 
                  apply_fixes: bool = True, 
                  dry_run: bool = False, 
                  return_content: bool = False) -> Tuple[Optional[str], Set[str]]:
        """Heal YAML file with accurate line tracking and full type safety."""
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
                    actual_lines = len(doc_str.splitlines())
                    current_line_offset += actual_lines + 1
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
                        if self.shield and api and api in self.shield.DEPRECATIONS:
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
                except Exception as e:
                    logger.warning(f"Failed to parse YAML doc in {file_path}: {e}")
                    # If parsing fails, keep the original doc fragment
                    healed_parts.append(doc_str.strip())
                
                # Update offset for next document: actual lines + separator
                actual_lines = len(doc_str.splitlines())
                current_line_offset += actual_lines + 1

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
            
        except Exception as e:
            logger.error(f"Heal failed for {file_path}: {e}")
            return (None if return_content else False, set())

def linter_engine(file_path: str, 
                  apply_api_fixes: bool = True, 
                  dry_run: bool = False, 
                  return_content: bool = False) -> Tuple[Optional[str], Set[str]]:
    """Public entrypoint for main.py integration."""
    h = Healer()
    return h.heal_file(file_path, apply_api_fixes, dry_run, return_content)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: healer.py <file.yaml>")
        sys.exit(1)
    else:
        res, codes = linter_engine(sys.argv[1], dry_run=True)
        if codes:
            print(f"✅ Analyzed {sys.argv[1]} | Issues: {codes}")
        else:
            print(f"ℹ️ No issues detected for {sys.argv[1]}")
