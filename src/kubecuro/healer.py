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
from ruamel.yaml import YAML
from kubecuro.shield import Shield, RegexShield

logger = logging.getLogger(__name__)

class Healer:
    def __init__(self):
        # Round-trip loader preserves comments and block styles
        self.yaml = YAML(typ='rt')
        self.yaml.indent(mapping=2, sequence=2, offset=0)
        self.yaml.block_seq_indent = 2
        self.yaml.width = 4096
        self.yaml.preserve_quotes = True
        
        # --- SHIELD INTEGRATION ---
        self.shield = Shield()
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

    def validate_schema(self, doc: dict, kind: str) -> bool:
        """
        Lightweight Schema Validation: Checks if the mandatory top-level 
        fields for a given Kind are present.
        """
        # Define minimum structural requirements for common K8s objects
        schema_requirements = {
            'Pod': ['spec'],
            'Deployment': ['spec'],
            'Service': ['spec'],
            'StatefulSet': ['spec'],
            'DaemonSet': ['spec'],
            'ConfigMap': ['data', 'binaryData'],
            'Secret': ['data', 'stringData'],
            'Ingress': ['spec'],
            'Namespace': []
        }
        
        if kind in schema_requirements:
            # For things like ConfigMaps, we only need one of the data fields
            fields = schema_requirements[kind]
            if not fields: return True
            return any(field in doc for field in fields)
        return True

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

            # 5. Resources & OOM Fixes
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

            # 6. Privileged Context
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
            
            raw_docs = re.split(r'^---\s*$', original_content, flags=re.MULTILINE)
            healed_parts = []
            self.detected_codes = set()           

            # --- PASS 1: METADATA MAP (Multi-Pass Mapping) ---
            all_parsed_docs = []
            label_map = {}
            for doc_str in raw_docs:
                if not doc_str.strip(): continue
                clean_d, _ = RegexShield.sanitize(doc_str)
                try:
                    temp_parsed = self.yaml.load(clean_d)
                    if temp_parsed and isinstance(temp_parsed, dict):
                        all_parsed_docs.append(temp_parsed)
                        kind, name = temp_parsed.get('kind'), temp_parsed.get('metadata', {}).get('name')
                        if kind and name:
                            labels = None
                            if kind == 'Pod':
                                labels = temp_parsed.get('metadata', {}).get('labels')
                            elif kind in ['Deployment', 'StatefulSet', 'DaemonSet']:
                                labels = temp_parsed.get('spec', {}).get('template', {}).get('metadata', {}).get('labels')
                            if labels: label_map[(kind, name)] = labels
                except Exception: continue

            # --- PASS 2: HEALING LOOP ---
            current_line_offset = 1
            for doc_str in raw_docs:
                if not doc_str.strip():
                    current_line_offset += len(doc_str.splitlines()) + 1
                    continue

                # 1. INITIAL REGEX SANITIZATION (Regex Shield)
                d, shield_codes = RegexShield.sanitize(doc_str)
                lines_in_doc = len(doc_str.splitlines())
                for code in shield_codes:
                    self.detected_codes.add(f"{code}:{current_line_offset}")

                # 2. PRE-PARSER BLUNT FORCE REPAIR (Indentation & Colons)
                lines = d.splitlines()
                repaired_lines = []
                for idx, line in enumerate(lines):
                    # A. Indentation Snap (Fixes those huge gaps)
                    if line.startswith(" " * 12) and not line.strip().startswith("#"):
                        line = "    " + line.lstrip()
                        self.detected_codes.add(f"FIX_INDENTATION_SNAPPED:{current_line_offset + idx}")
                    
                    # B. Smart Colon Injection (Fixes 'image "nginx"')
                    k8s_keys = r"(image|name|containerPort|hostPort|protocol|imagePullPolicy|kind|apiVersion|labels)"
                    if re.search(rf'^[ \t]*{k8s_keys}[ \t]+[\'"\[\w]', line):
                        line = re.sub(rf'^([ \t]*)({k8s_keys})([ \t]+)', r'\1\2: \3', line)
                        self.detected_codes.add(f"FIX_COLON_INJECTED:{current_line_offset + idx}")
                    
                    repaired_lines.append(line)
                d = "\n".join(repaired_lines)
                
                # Tab conversion & Key-Value whitespace
                d = d.replace('\t', '    ')
                d = re.sub(r'^(?![ \t]*#)([ \t]*[\w.-]+):(?!\s|$)', r'\1: ', d, flags=re.MULTILINE)

                if not d.strip():
                    current_line_offset += lines_in_doc + 1
                    continue

                # 3. PARSING & STRUCTURAL HEALING
                try:
                    parsed = self.yaml.load(d)
                    if parsed and isinstance(parsed, dict):
                        kind = parsed.get('kind')
                        api = parsed.get('apiVersion')
                        name = parsed.get('metadata', {}).get('name')

                        # --- NEW: SCHEMA CHECK ---
                        if not self.validate_schema(parsed, kind):
                            self.detected_codes.add(f"SCHEMA_INVALID_STRUCTURE:{current_line_offset}")

                        findings = self.shield.scan(parsed, all_docs=all_parsed_docs)
                        for f in findings:
                            abs_line = (current_line_offset + f['line'] - 1) if f['line'] > 0 else current_line_offset
                            self.detected_codes.add(f"{f['code']}:{abs_line}")

                        # API & Selector Fixes
                        if api in self.shield.DEPRECATIONS:
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

                except Exception as e:
                    mark = getattr(e, 'problem_mark', None)                    
                    error_line = current_line_offset + (mark.line if mark else 0)
                    self.detected_codes.add(f"SYNTAX_ERROR:{error_line}")
                    healed_parts.append(d.strip())             

                current_line_offset += lines_in_doc + 1

            # --- 4. GHOST DOCUMENT FILTERING ---
            healed_parts = [p for p in healed_parts if p.strip()]
            healed_final = ("---\n" if original_content.startswith("---") else "") + "\n---\n".join(healed_parts) + "\n"
            
            if return_content: return (healed_final, self.detected_codes)
            
            changed = original_content.strip() != healed_final.strip()
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

    file_to_scan = sys.argv[1]
    # We run with dry_run=True to get the findings without modifying the file immediately
    res, codes = linter_engine(file_to_scan, dry_run=True)

    print(f"\n{'='*60}")
    print(f"🛡️  KUBE-SHIELD AUDIT REPORT: {file_to_scan}")
    print(f"{'='*60}")

    if not codes:
        print("✅ No stability or security issues detected.")
    else:
        # Sort codes by line number for a clean read
        sorted_findings = sorted(list(codes), key=lambda x: int(x.split(':')[-1]))
        
        for finding in sorted_findings:
            code, line = finding.split(':')            
            # Simple color logic for terminal
            pref = "ℹ️"
            if any(x in code for x in ["CRITICAL", "OOM", "PRIVILEGED"]): pref = "🔴"
            elif any(x in code for x in ["HIGH", "WILD", "REMOVED"]): pref = "🟠"
            elif "FIX" in code: pref = "🔧"            
            print(f"Line {line.ljust(4)} | {pref} {code}")
        print("-" * 60)
        if res:
            print(f"💾 STATS: Changes applied to {file_to_scan}")
        else:
            print(f"🔍 STATS: {len(codes)} issues found. No changes saved (Dry Run).")

    print(f"{'='*60}\n")

