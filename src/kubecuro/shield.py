#!/usr/bin/env python3
import logging
"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
PURPOSE:         The Shield Engine: API Deprecation, Resource Stability, 
                  and RBAC Security Guard.
--------------------------------------------------------------------------------
"""

class Shield:
    """The Stability Engine: Protects against outdated APIs, insecure RBAC, and misconfigured HPA logic."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
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
        if not doc or not isinstance(doc, dict):
            self.logger.debug("Empty or invalid document skipped")
            return []

        base_line = self.get_line(doc)
        raw_findings = []

        # 1. API Version & Pod Security Checks
        raw_findings.extend(self.check_version_and_security(doc))
        
        # 2. RBAC Specific Security Checks
        raw_findings.extend(self.check_rbac_security(doc))

        # 3. RESOURCE LIMITS
        raw_findings.extend(self.check_limits(doc))
        
        # 4. Cross-Resource Logic (HPA & Ingress)
        if all_docs:
            raw_findings.extend(self.audit_hpa(doc, all_docs))
            raw_findings.extend(self.check_ingress_service_alignment(doc, all_docs))

        # --- Line Number Attachment & Consistency Check ---
        for f in raw_findings:
            if 'line' not in f or f['line'] is None or f['line'] <= 0:
                f['line'] = base_line
        
        return raw_findings  # ✅ FIXED: Return raw_findings
       
    def check_limits(self, doc):
        """Fix 5: Detects missing resource limits to prevent OOMKills."""
        findings = []
        if doc.get('kind') in ['Deployment', 'StatefulSet', 'DaemonSet', 'Job']:
            spec = doc.get('spec', {}) or {}
            template = spec.get('template', {}) or {}
            t_spec = template.get('spec', {}) or {}
            
            for c in t_spec.get('containers', []):
                res = c.get('resources', {}) or {}
                if 'limits' not in res:
                    findings.append({
                        "code": "OOM_RISK",
                        "severity": "🔴 CRITICAL",
                        "msg": f"Container '{c.get('name')}' has no resource limits. One memory leak could crash the entire Node.",
                        "line": self.get_line(c)
                    })
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
                    svc_ports = [p.get('port') for p in matched_svc.get('spec', {}).get('ports', []) if p.get('port')]
                    if target_port and target_port not in svc_ports:
                        findings.append({
                            "code": "INGRESS_PORT_MISMATCH",
                            "severity": "🔴 CRITICAL",
                            "msg": f"Ingress '{ingress_name}' points to port {target_port}, but Service '{target_svc}' only exposes {svc_ports}.",
                            "line": self.get_line(doc)  # ✅ FIXED: Use doc (Ingress root)
                        })
                else:
                    if len(all_docs) > 1:
                        findings.append({
                            "code": "INGRESS_ORPHAN",
                            "severity": "🟠 WARNING",
                            "msg": f"Ingress '{ingress_name}' points to Service '{target_svc}', but that Service was not found in this scan context.",
                            "line": self.get_line(doc)  # ✅ FIXED: Use doc (Ingress root)
                        })
        return findings

    def check_version_and_security(self, doc: dict) -> list:
        """Checks for retired API versions and Container Security."""
        findings = []
        api = doc.get('apiVersion')
        kind = doc.get('kind', 'Object')
        name = doc.get('metadata', {}).get('name', 'unknown')
        
        if api in self.DEPRECATIONS:
            mapping = self.DEPRECATIONS[api]
            better = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
            findings.append({
                "severity": "🟡 API",
                "code": "API_DEPRECATED",
                "msg": f"🛡️ {kind} '{name}' uses '{api}'. Upgrade to '{better}'.",
                "line": self.get_line(doc, 'apiVersion')
            })
        
        if kind in ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet']:
            spec = doc.get('spec') or {}
            template = spec.get('template') or {} if kind != 'Pod' else doc
            t_spec = template.get('spec') or {}
            
            # Fix 3: Descriptive Security Message
            if t_spec.get('automountServiceAccountToken') is not False:
                findings.append({
                    "severity": "🟡 WARN",
                    "code": "SEC_TOKEN_AUDIT",
                    "msg": "ServiceAccount token is auto-mounting. This increases attack surface if the pod is compromised.",
                    "line": self.get_line(t_spec, 'automountServiceAccountToken') if 'automountServiceAccountToken' in t_spec else self.get_line(doc)
                })
            
            for c in t_spec.get('containers', []):
                if c.get('securityContext', {}).get('privileged'):
                    findings.append({
                        "severity": "🔴 HIGH",
                        "code": "SEC_PRIVILEGED",
                        "msg": f"🚨 Security Risk: Container '{c.get('name')}' in {kind} '{name}' is Privileged.",
                        "line": self.get_line(c)
                    })
        return findings

    def check_rbac_security(self, resource: dict) -> list:
        """Audits RBAC for wildcard permissions and secret access."""
        findings = []
        kind = resource.get("kind")
        name = resource.get('metadata', {}).get('name', 'unknown')
        rules = resource.get("rules") or resource.get("spec", {}).get("rules", [])
    
        if kind in ["Role", "ClusterRole"]:
            for rule in rules:
                verbs = rule.get("verbs", [])
                res_list = rule.get("resources", [])

                if "*" in verbs and "*" in res_list:
                    findings.append({
                        "severity": "🔴 HIGH", 
                        "code": "RBAC_WILD",
                        "msg": f"🚨 Critical Security Risk: {kind} '{name}' uses global wildcards (*).",
                        "line": self.get_line(rule)
                    })
                elif "secrets" in res_list and any(v in verbs for v in ["*", "get", "list", "watch"]):
                     findings.append({
                        "severity": "🟠 MED", 
                        "code": "RBAC_SECRET",
                        "msg": f"🛡️ Security Warning: {kind} '{name}' allows read access to Secrets.",
                        "line": self.get_line(rule)
                    })
        return findings

    def audit_hpa(self, hpa_doc: dict, all_docs: list) -> list:
        """Validates HPA scales on workloads that have resource requests."""
        findings = []
        if hpa_doc.get('kind') != 'HorizontalPodAutoscaler':
            return findings

        spec = hpa_doc.get('spec', {}) or {}
        target_ref = spec.get('scaleTargetRef', {}) or {}
        target_name = target_ref.get('name')
        hpa_ns = hpa_doc.get('metadata', {}).get('namespace', 'default')
        
        resource_checks = []
        if spec.get('targetCPUUtilizationPercentage'):
            resource_checks.append('cpu')
            
        for m in spec.get('metrics', []):
            if m.get('type') == 'Resource':
                res_name = m.get('resource', {}).get('name')
                if res_name: resource_checks.append(res_name)
        
        if not resource_checks: return findings

        target_workload = next((w for w in all_docs if w.get('metadata', {}).get('name') == target_name 
                               and w.get('metadata', {}).get('namespace', 'default') == hpa_ns
                               and w.get('kind') in ['Deployment', 'StatefulSet']), None)
        
        if target_workload:
            containers = target_workload.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
            for res in set(resource_checks):
                for c in containers:
                    requests = c.get('resources', {}).get('requests', {}) or {}
                    if res not in requests:
                        findings.append({
                            "severity": "🔴 HIGH",
                            "code": "HPA_MISSING_REQ",
                            "msg": f"📈 HPA Logic Error: Scales on {res}, but '{target_name}' lacks {res} requests.",
                            "line": self.get_line(c)
                        })
        return findings
