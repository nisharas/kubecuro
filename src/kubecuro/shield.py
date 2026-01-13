#!/usr/bin/env python3
import logging
import re
"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
PURPOSE:         The Shield Engine: API Deprecation, Resource Stability, 
                  and RBAC Security Guard.
--------------------------------------------------------------------------------
"""
class Shield:
    """The Stability Engine: Standardized with Professional Severity Levels."""
    
    # --- Standardized Severity Constants ---
    # Used to ensure consistency across all scan methods
    CRITICAL = "🔴 CRITICAL"  # Immediate failure/outage risk
    HIGH     = "🟠 HIGH"      # Major security risk
    MEDIUM   = "🟡 MEDIUM"    # Deprecations/Best practices
    LOW      = "🔵 INFO"      # Hardening/Audit suggestions

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def add_finding(self, code, severity, msg, line):
        """Helper to standardize finding structure."""
        return {
            "code": code.upper(),
            "severity": severity,
            "msg": msg,
            "line": line
        }
    
    # Comprehensive Database of retired/deprecated APIs (unchanged)
    DEPRECATIONS = {
        "extensions/v1beta1": {
            "Ingress": "networking.k8s.io/v1",
            "Deployment": "apps/v1",
            "DaemonSet": "apps/v1",
            "ReplicaSet": "apps/v1",
            "NetworkPolicy": "networking.k8s.io/v1",
            "PodSecurityPolicy": "REMOVED (Use Admission Controllers)",
            "default": "apps/v1"
        },
        "networking.k8s.io/v1beta1": "networking.k8s.io/v1",
        "policy/v1beta1": "policy/v1",
        "rbac.authorization.k8s.io/v1beta1": "rbac.authorization.k8s.io/v1",
        "autoscaling/v2beta1": "autoscaling/v2",
        "autoscaling/v2beta2": "autoscaling/v2",
        "admissionregistration.k8s.io/v1beta1": "admissionregistration.k8s.io/v1",
        "apiextensions.k8s.io/v1beta1": "apiextensions.k8s.io/v1",
        "storage.k8s.io/v1beta1": "storage.k8s.io/v1",
        "scheduling.k8s.io/v1beta1": "scheduling.k8s.io/v1",
        "node.k8s.io/v1beta1": "node.k8s.io/v1",
        "discovery.k8s.io/v1beta1": "discovery.k8s.io/v1",
        "flowcontrol.apiserver.k8s.io/v1beta2": "flowcontrol.apiserver.k8s.io/v1beta3",
        "apiregistration.k8s.io/v1beta1": "apiregistration.k8s.io/v1"
    }

    def get_line(self, doc, key=None):
        """Helper to extract line number from ruamel.yaml-parsed dict."""
        try:
            if doc is None:
                return 1
            
            if key and hasattr(doc, 'lc') and hasattr(doc.lc, 'data') and key in doc.lc.data:
                return doc.lc.data[key][0] + 1
            
            if hasattr(doc, 'lc') and hasattr(doc.lc, 'line'):
                return doc.lc.line + 1
            
            return 1
        except Exception:
            return 1

    def scan(self, doc: dict, all_docs: list = None) -> list:
        """
        Analyzes a single Kubernetes resource against logic rules.
        """
        if not doc or not isinstance(doc, dict):
            self.logger.debug("Empty or invalid document skipped")
            return []
    
        # Get the starting line of the resource for fallback
        base_line = self.get_line(doc)
        raw_findings = []
    
        # 1. API Version & Pod Security (Triggers: ROOT_USER_UID, PRIV_ESC_TRUE, RO_ROOT_FS)
        raw_findings.extend(self.check_version_and_security(doc))
        
        # 2. RBAC Specific Security Checks (Triggers: RBAC_WILD_RES)
        raw_findings.extend(self.check_rbac_security(doc))
    
        # 3. RESOURCE LIMITS (Triggers: HPA_MISS_REQ)
        raw_findings.extend(self.check_limits(doc))
        
        # 4. Cross-Resource Logic (Triggers: GHOST_SELECT, SVC_PORT_MISS)
        if all_docs:
            # Note: Some HPA checks require looking at the Target Deployment
            raw_findings.extend(self.audit_hpa(doc, all_docs))
            raw_findings.extend(self.check_ingress_service_alignment(doc, all_docs))
    
        # --- Line Number Attachment & Consistency Check ---
        # This ensures the UI points to the correct line in the IDE
        for f in raw_findings:
            # Normalize code to uppercase to match CONFIG
            if 'code' in f:
                f['code'] = f['code'].upper()
                
            if f.get('line') is None or f.get('line', 0) <= 0:
                f['line'] = base_line
        
        return raw_findings

    def check_limits(self, doc):
        """Detects missing resource limits to prevent OOMKills."""
        findings = []
        kind = doc.get('kind')
        workloads = ['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob']
        
        if kind in workloads:
            spec = doc.get('spec', {}) or {}
            
            # Consistent Navigation Logic
            if kind == 'CronJob':
                t_spec = spec.get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})
            elif kind == 'Pod':
                t_spec = spec
            else:
                t_spec = spec.get('template', {}).get('spec', {})
            
            if not isinstance(t_spec, dict):
                return findings

            for c in t_spec.get('containers', []):
                res = c.get('resources', {}) or {}
                if 'limits' not in res:
                    findings.append(self.add_finding(
                        "OOM_RISK", 
                        self.CRITICAL, 
                        f"Container '{c.get('name')}' has no resource limits. One memory leak could crash the Node.",
                        self.get_line(c)
                    ))
        return findings

    def check_ingress_service_alignment(self, doc, all_docs):
        """Checks if Ingress backends point to valid Services and Ports."""
        findings = []
        if doc.get('kind') != 'Ingress':
            return findings
            
        ingress_name = doc.get('metadata', {}).get('name', 'unknown')
        ingress_ns = doc.get('metadata', {}).get('namespace', 'default')
        spec = doc.get('spec', {}) or {}
        
        for rule in spec.get('rules', []):
            http = rule.get('http', {}) or {}
            for path in http.get('paths', []):
                backend = path.get('backend', {}) or {}
                svc_node = backend.get('service', backend) 
                target_svc = svc_node.get('name') or backend.get('serviceName')
                
                port_node = svc_node.get('port', {})
                target_port = port_node.get('number') if isinstance(port_node, dict) else port_node
    
                if not target_svc: 
                    continue
    
                matched_svc = next((d for d in all_docs if d.get('kind') == 'Service' 
                                   and d.get('metadata', {}).get('name') == target_svc
                                   and d.get('metadata', {}).get('namespace', 'default') == ingress_ns), None)
                    
                if matched_svc:
                      svc_spec_ports = matched_svc.get('spec', {}).get('ports', [])
                      svc_port_numbers = [p.get('port') for p in svc_spec_ports if p.get('port')]
                      svc_port_names = [p.get('name') for p in svc_spec_ports if p.get('name')]
                      
                      is_match = False
                      if isinstance(target_port, int):
                          if target_port in svc_port_numbers:
                              is_match = True
                      elif isinstance(target_port, str):
                          if target_port in svc_port_names:
                              is_match = True
                      
                      if target_port and not is_match:
                          available = svc_port_numbers + svc_port_names
                          # ✅ FIXED: Use add_finding and CRITICAL constant
                          findings.append(self.add_finding(
                              "INGRESS_PORT_MISMATCH",
                              self.CRITICAL,
                              f"Ingress '{ingress_name}' targets port '{target_port}', but Service '{target_svc}' only exposes {available}.",
                              self.get_line(doc)
                          ))
                else:
                    if all_docs and len(all_docs) > 1:
                        # ✅ FIXED: Use add_finding and MEDIUM constant
                        findings.append(self.add_finding(
                            "INGRESS_ORPHAN",
                            self.MEDIUM,
                            f"Ingress '{ingress_name}' points to Service '{target_svc}', but that Service was not found in this scan context.",
                            self.get_line(doc)
                        ))
        return findings

    def check_version_and_security(self, doc: dict) -> list:
        """Checks for retired API versions and Container Security (Privileged/Tokens)."""
        findings = []
        api = doc.get('apiVersion')
        kind = doc.get('kind', 'Object')
        name = doc.get('metadata', {}).get('name', 'unknown')
        
        # 1. API Deprecation Check
        if api in self.DEPRECATIONS:
            mapping = self.DEPRECATIONS[api]
            better = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
            findings.append(self.add_finding(
                "API_DEPRECATED",
                self.MEDIUM,
                f"🛡️ {kind} '{name}' uses '{api}'. Upgrade to '{better}'.",
                self.get_line(doc, 'apiVersion')
            ))
        
        # 2. Workload Security Checks (Pod, Deployment, etc.)
        workloads = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'CronJob', 'Job']
        if kind in workloads:
            spec = doc.get('spec') or {}
            
            # Navigate to the actual Pod Spec (t_spec)
            if kind == 'CronJob':
                # Path: spec -> jobTemplate -> spec -> template -> spec
                t_spec = spec.get('jobTemplate', {}).get('spec', {}).get('template', {}).get('spec', {})
            elif kind == 'Pod':
                t_spec = spec
            else:
                # Path: spec -> template -> spec (Deployments, STS, DS, Jobs)
                t_spec = spec.get('template', {}).get('spec', {})

            if not isinstance(t_spec, dict):
                return findings
            
            # Check A: ServiceAccount Token Auto-mounting
            # Note: We now check t_spec directly
            if t_spec.get('automountServiceAccountToken') is not False:
                findings.append(self.add_finding(
                    "SEC_TOKEN_AUDIT",
                    self.LOW,
                    "ServiceAccount token is auto-mounting. This increases attack surface if the pod is compromised.",
                    self.get_line(t_spec, 'automountServiceAccountToken') if 'automountServiceAccountToken' in t_spec else self.get_line(doc)
                ))
            
            # Check B: Privileged Containers
            for c in t_spec.get('containers', []):
                if isinstance(c, dict) and c.get('securityContext', {}).get('privileged'):
                    findings.append(self.add_finding(
                        "SEC_PRIVILEGED",
                        self.HIGH,
                        f"🚨 Security Risk: Container '{c.get('name')}' in {kind} '{name}' is Privileged.",
                        self.get_line(c)
                    ))
                    
        return findings

    def check_rbac_security(self, resource: dict) -> list:
        findings = []
        kind = resource.get("kind")
        name = resource.get('metadata', {}).get('name', 'unknown')
        rules = resource.get("rules") or resource.get("spec", {}).get("rules", [])

        if kind in ["Role", "ClusterRole"]:
            for rule in rules:
                verbs = rule.get("verbs", [])
                res_list = rule.get("resources", [])

                if "*" in verbs and "*" in res_list:
                    findings.append(self.add_finding(
                        "RBAC_WILD",
                        self.HIGH,
                        f"🚨 Security Risk: {kind} '{name}' uses global wildcards (*).",
                        self.get_line(rule)
                    ))
                elif "secrets" in res_list and any(v in verbs for v in ["*", "get", "list", "watch"]):
                    findings.append(self.add_finding(
                        "RBAC_SECRET",
                        self.MEDIUM,
                        f"🛡️ Warning: {kind} '{name}' allows read access to Secrets.",
                        self.get_line(rule)
                    ))
        return findings

    def audit_hpa(self, hpa_doc: dict, all_docs: list) -> list:
        findings = []
        if hpa_doc.get('kind') != 'HorizontalPodAutoscaler':
            return findings
    
        spec = hpa_doc.get('spec', {})
        target = spec.get('scaleTargetRef', {})
        t_name = target.get('name')
        
        metrics = []
        if spec.get('targetCPUUtilizationPercentage'): metrics.append('cpu')
        for m in spec.get('metrics', []):
            if m.get('type') == 'Resource':
                metrics.append(m['resource']['name'])
    
        workload = next((d for d in all_docs if d.get('metadata', {}).get('name') == t_name 
                         and d.get('kind') in ['Deployment', 'StatefulSet']), None)
    
        if not workload:
            # ✅ FIXED: Use add_finding and MEDIUM constant
            findings.append(self.add_finding(
                "HPA_ORPHAN",
                self.MEDIUM,
                f"HPA targets '{t_name}', but no such Deployment/StatefulSet found in this scan.",
                self.get_line(hpa_doc)
            ))
            return findings
    
        containers = workload.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
        for metric in set(metrics):
            for c in containers:
                if metric not in c.get('resources', {}).get('requests', {}):
                    # ✅ FIXED: Use add_finding and HIGH constant
                    findings.append(self.add_finding(
                        "HPA_MISSING_REQ",
                        self.HIGH,
                        f"HPA scales on {metric}, but container '{c.get('name')}' lacks {metric} requests.",
                        self.get_line(c)
                    ))
        return findings
      
class RegexShield:
    """Sanitizes raw text to prevent YAML Parser crashes from human 'dirty' typing."""
    
    @staticmethod
    def sanitize(text: str) -> tuple[str, list]:
        fixes = []
        original = text

        # 0. FIX: Detect and "Ghost" empty documents
        if re.search(r'^---\s*$', text, re.MULTILINE) and not text.strip().replace('---', ''):
            fixes.append("SYNTAX_EMPTY_DOCUMENT")
            return "", fixes  # Return empty string to signify this block should be dropped
        
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
