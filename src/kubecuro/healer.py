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

class RegexShield:
    """Sanitizes raw text to prevent YAML Parser crashes from human 'dirty' typing."""
    
    @staticmethod
    def sanitize(text: str) -> tuple[str, list]:
        fixes = []
        original = text
        
        # 1. FIX: Multi-colon or Trailing colon on image lines
        if re.search(r'(image:\s*)"([^"]+)"\s*:', text):
            text = re.sub(r'(image:\s*)"([^"]+)"\s*:', r'\1"\2"', text)
            fixes.append("SYNTAX_REPAIRED")
        
        if re.search(r'image:\s*[:\s]{2,}', text):
            text = re.sub(r'(image:\s*)[:\s]+', r'\1', text)
            fixes.append("SYNTAX_REPAIRED")

        # 2. Fixing 'tag: latest' spaces inside quotes
        if ": latest" in text:
            text = text.replace(": latest", ":latest")
            fixes.append("SYNTAX_REPAIRED")

        # 3. ELASTIC Indentation Fixer:
        # Matches the indentation of the PREVIOUS line to maintain block integrity.
        lines = text.splitlines()
        fixed_lines = []
        
        for i in range(len(lines)):
            current_line = lines[i]
            
            # Check if this line is a drifted 'command' or 'args'
            if i > 0 and re.search(r'^\s+(command|args):', current_line):
                # Get the indentation of the previous line (e.g., 'image:' or 'name:')
                prev_line = lines[i-1]
                prev_indent_match = re.match(r'^(\s*)', prev_line)
                
                if prev_indent_match:
                    target_indent = prev_indent_match.group(1)
                    # If current line starts with a list marker '-' handle that, 
                    # otherwise just align the keys vertically.
                    content = current_line.lstrip()
                    fixed_lines.append(f"{target_indent}{content}")
                    continue
            
            fixed_lines.append(current_line)
        
        text = "\n".join(fixed_lines)
        if text.strip() != original.strip() and "SYNTAX_REPAIRED" not in fixes:
            fixes.append("SYNTAX_REPAIRED")
            
        return text, fixes

class Healer:
    def __init__(self):
        # Round-trip loader preserves comments and block styles
        self.yaml = YAML(typ='rt')
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.yaml.preserve_quotes = True
        
        # --- SHIELD INTEGRATION ---
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

    def parse_cpu(self, cpu_str: str) -> int:
        """Convert K8s CPU string to millicores."""
        if not cpu_str: return 0
        cpu_str = str(cpu_str).strip()
        if cpu_str.endswith('m'):
            return int(cpu_str[:-1])
        try:
            return int(float(cpu_str) * 1000)
        except ValueError:
            return 0

    def parse_mem(self, mem_str: str) -> int:
        """Convert K8s Memory string to MiB."""
        if not mem_str: return 0
        mem_str = str(mem_str).strip().lower()
        units = {'k': 1/1024, 'm': 1, 'g': 1024, 't': 1024*1024,
                 'ki': 1/1024, 'mi': 1, 'gi': 1024, 'ti': 1024*1024}
        match = re.match(r'(\d+)([a-z]*)', mem_str)
        if not match: return 0
        val, unit = match.groups()
        return int(int(val) * units.get(unit, 1))

    def get_line(self, obj: any, key: Optional[str] = None) -> int:
        """Extract line number from ruamel.yaml LC data."""
        try:
            if obj is None: return 1
            if key and hasattr(obj, 'lc') and hasattr(obj.lc, 'data') and key in obj.lc.data:
                return obj.lc.data[key][0] + 1
            if hasattr(obj, 'lc') and hasattr(obj.lc, 'line'):
                return obj.lc.line + 1
            return 1
        except Exception:
            return 1

    def apply_security_patches(self, doc: dict, kind: str, global_line_offset: int = 0, apply_defaults: bool = False) -> None:
        """Standard Security Hardening & Stability Patching."""
        if not isinstance(doc, dict): return

        # 1. Service Logic
        if kind == 'Service':
            spec = doc.get('spec', {})
            if not spec or not spec.get('selector'):
                actual_line = global_line_offset + (self.get_line(doc, 'spec') - 1)
                if not apply_defaults:
                    self.detected_codes.add(f"SVC_SELECTOR_MISSING:{actual_line}")
            return
        
        # 2. Workload Navigation
        workloads = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob']
        if kind not in workloads: return
            
        spec = doc.get('spec', {})
        if not isinstance(spec, dict): return

        if kind == 'CronJob':
            job_tmpl_spec = spec.get('jobTemplate', {}).get('spec', {})
            template = job_tmpl_spec.get('template', {})
            t_spec = template.get('spec', {})
        elif kind == 'Pod':
            t_spec = spec
        else:
            template = spec.get('template', {})
            t_spec = template.get('spec', {})
        
        if not t_spec or not isinstance(t_spec, dict): return

        # 3. Security: Token Audit
        if t_spec.get('automountServiceAccountToken') is None:
            token_line = global_line_offset + (self.get_line(t_spec) - 1)
            self.detected_codes.add(f"SEC_TOKEN_AUDIT:{token_line}")

        # 4. Container-level fixes
        containers = t_spec.get('containers', [])
        if not isinstance(containers, list): return

        for idx, c in enumerate(containers):
            c_image = str(c.get('image', '')).lower()
            c_cmd = " ".join(c.get('command', [])) if isinstance(c.get('command'), list) else str(c.get('command', ''))
            c_args = " ".join(c.get('args', [])) if isinstance(c.get('args'), list) else str(c.get('args', ''))
            exec_context = (c_cmd + " " + c_args).lower()

            is_dummy = any(sig in exec_context for sig in ['sleep ', 'tail -f /dev/null', 'pause', 'infinity'])
            is_sidecar = any(sig in c_image for sig in ['istio-proxy', 'envoy', 'fluentd', 'sidecar', 'otel-collector'])
            
            if is_dummy: profile = {'cpu': '10m', 'memory': '32Mi'}
            elif is_sidecar: profile = {'cpu': '100m', 'memory': '128Mi'}
            elif idx > 0: profile = {'cpu': '200m', 'memory': '192Mi'}
            else: profile = {'cpu': '500m', 'memory': '256Mi'}

            # 5. Resources
            res = c.get('resources', {})
            if 'limits' not in res:
                actual_line = global_line_offset + (self.get_line(c) - 1)
                if apply_defaults:
                    if 'resources' not in c: c['resources'] = {}
                    reqs = res.get('requests', {})
                    final_cpu, final_mem = profile['cpu'], profile['memory']
                    if 'cpu' in reqs and self.parse_cpu(reqs['cpu']) > self.parse_cpu(final_cpu):
                        final_cpu = reqs['cpu']
                    if 'memory' in reqs and self.parse_mem(reqs['memory']) > self.parse_mem(final_mem):
                        final_mem = reqs['memory']
                    c['resources']['limits'] = {'cpu': final_cpu, 'memory': final_mem}
                    self.detected_codes.add(f"OOM_FIXED:{actual_line}")
                else:
                    self.detected_codes.add(f"OOM_RISK:{actual_line}")

            # 6. Privileged
            s_ctx = c.get('securityContext', {})
            if isinstance(s_ctx, dict) and s_ctx.get('privileged') is True:
                actual_line = global_line_offset + (self.get_line(c, 'securityContext') - 1)
                if apply_defaults:
                    s_ctx['privileged'] = False
                    self.detected_codes.add(f"SEC_PRIVILEGED_FIXED:{actual_line}")
                else:
                    self.detected_codes.add(f"SEC_PRIVILEGED_RISK:{actual_line}")

    def heal_file(self, file_path: str, apply_fixes: bool = True, apply_defaults: bool = False, dry_run: bool = False, return_content: bool = False) -> Tuple[Union[bool, Optional[str]], Set[str]]:
        try:
            if not os.path.exists(file_path): return (None if return_content else False, set())
            with open(file_path, 'r') as f: original_content = f.read()
            
            # Split documents
            raw_docs = re.split(r'^---\s*$', original_content, flags=re.MULTILINE)
            healed_parts = []
            self.detected_codes = set()           

            # PASS 1: Metadata Map
            label_map = {}
            for doc_str in raw_docs:
                if not doc_str.strip(): continue
                clean_d, _ = RegexShield.sanitize(doc_str)
                try:
                    temp_parsed = self.yaml.load(clean_d)
                    if temp_parsed and isinstance(temp_parsed, dict):
                        kind, name = temp_parsed.get('kind'), temp_parsed.get('metadata', {}).get('name')
                        if kind and name:
                            labels = None
                            if kind == 'Pod':
                                labels = temp_parsed.get('metadata', {}).get('labels')
                            elif kind in ['Deployment', 'StatefulSet', 'DaemonSet']:
                                labels = temp_parsed.get('spec', {}).get('template', {}).get('metadata', {}).get('labels')
                            if labels: label_map[(kind, name)] = labels
                except Exception: continue

            # PASS 2: Healing Loop
            current_line_offset = 1 if not original_content.startswith("---") else 2
            for doc_str in raw_docs:
                if not doc_str.strip():
                    current_line_offset += len(doc_str.splitlines()) + 1
                    continue

                # --- INTEGRATED REGEX SHIELD ---
                d, shield_codes = RegexShield.sanitize(doc_str)
                for code in shield_codes:
                    self.detected_codes.add(f"{code}:{current_line_offset}")
                
                # Tab conversion and simple key-value spacing
                d = d.replace('\t', '    ')
                d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+):(?!\s|$)', r'\1: ', d, flags=re.MULTILINE)

                try:
                    parsed = self.yaml.load(d)
                    if parsed and isinstance(parsed, dict):
                        kind = parsed.get('kind')
                        api = parsed.get('apiVersion')
                        name = parsed.get('metadata', {}).get('name')

                        # API & Selector Fixes
                        if self.shield and api in self.shield.DEPRECATIONS:
                            self.detected_codes.add(f"API_DEPRECATED:{current_line_offset}")
                            if apply_fixes:
                                mapping = self.shield.DEPRECATIONS[api]
                                new_api = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
                                if new_api and not str(new_api).startswith("REMOVED"):
                                    parsed['apiVersion'] = new_api
                                    if new_api == 'apps/v1' and kind == 'Deployment' and 'selector' not in parsed.get('spec', {}):
                                        labels = parsed.get('spec', {}).get('template', {}).get('metadata', {}).get('labels')
                                        if labels: 
                                            parsed['spec']['selector'] = {'matchLabels': labels}
                                            self.detected_codes.add(f"FIX_SELECTOR_INJECTED:{current_line_offset}")

                        # Service Healing
                        if kind == 'Service' and apply_fixes and not parsed.get('spec', {}).get('selector'):
                            matching_labels = None
                            for target_kind in ['Deployment', 'StatefulSet', 'DaemonSet', 'Pod']:
                                if (target_kind, name) in label_map:
                                    matching_labels = label_map[(target_kind, name)]
                                    break
                            if matching_labels:
                                parsed['spec']['selector'] = matching_labels
                                self.detected_codes.add(f"SVC_SELECTOR_FIXED:{current_line_offset}")

                        self.apply_security_patches(parsed, kind, current_line_offset, apply_defaults)
                        buf = StringIO()
                        self.yaml.dump(parsed, buf)
                        healed_parts.append(buf.getvalue().rstrip())
                    else:
                        healed_parts.append(d.strip())

                except Exception:
                    # If YAML parsing still fails, we check if RegexShield made progress
                    self.detected_codes.add(f"SYNTAX_ERROR:{current_line_offset}")
                    healed_parts.append(d.strip())              

                current_line_offset += len(doc_str.splitlines()) + 1

            healed_final = ("---\n" if original_content.startswith("---") else "") + "\n---\n".join(healed_parts) + "\n"
            
            if return_content: return (healed_final, self.detected_codes)
            
            # CRITICAL LOGIC FIX: Check if we actually improved the file
            changed = original_content.strip() != healed_final.strip()
            
            # If we detected a SYNTAX_ERROR but changed is False, it means we FAILED to fix it.
            # We should only return True (changed) if the RegexShield actually sanitised the content.
            if changed and not dry_run:
                with open(file_path, 'w') as f: f.write(healed_final)
                
            return (changed, self.detected_codes)

        except Exception:
            return (None if return_content else False, set())

def linter_engine(file_path: str, apply_api_fixes: bool = True, apply_defaults: bool = False, dry_run: bool = False, return_content: bool = False) -> Tuple[Union[bool, Optional[str]], Set[str]]:
    return Healer().heal_file(file_path, apply_api_fixes, apply_defaults, dry_run, return_content)

if __name__ == "__main__":
    if len(sys.argv) < 2: 
        print("Usage: healer.py <file.yaml>")
        sys.exit(1)
    res, codes = linter_engine(sys.argv[1], dry_run=True)
    print(f"✅ Analyzed {sys.argv[1]} | Issues: {codes}" if codes else f"ℹ️ No issues for {sys.argv[1]}")
