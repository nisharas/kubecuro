"""
--------------------------------------------------------------------------------
AUTHOR:          Nishar A Sunkesala / FixMyK8s
PURPOSE:          The Shield Engine: API Deprecation, Resource Stability, 
                  and RBAC Security Guard.
--------------------------------------------------------------------------------
"""

class Shield:
    """The Stability Engine: Protects against outdated APIs, insecure RBAC, and misconfigured HPA logic."""
    
    # Comprehensive Database of retired/deprecated APIs
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
        "discovery.k8s.io/v1beta1": "discovery.k8s.io/v1"
    }

    def scan(self, doc: dict, all_docs: list = None) -> list:
        """
        The main entry point for the Shield Engine. 
        Runs all security and stability checks against a document.
        """
        findings = []
        if not doc or not isinstance(doc, dict):
            return findings

        # 1. API Version & Pod Security Checks
        findings.extend(self.check_version_and_security(doc))
        
        # 2. RBAC Specific Security Checks
        findings.extend(self.check_rbac_security(doc))
        
        # 3. HPA Logic Cross-Reference (Requires all docs in the directory)
        if all_docs:
            findings.extend(self.audit_hpa(doc, all_docs))
            
        return findings

    def check_version_and_security(self, doc: dict) -> list:
        """Checks for retired API versions and Container Privileged mode."""
        findings = []
        api = doc.get('apiVersion')
        kind = doc.get('kind', 'Object')
        name = doc.get('metadata', {}).get('name', 'unknown')
        
        # --- API Deprecation Check ---
        if api in self.DEPRECATIONS:
            mapping = self.DEPRECATIONS[api]
            better = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
            findings.append({
                "severity": "🟡 API",
                "code": "API_DEPRECATED",
                "msg": f"🛡️ {kind} '{name}' uses '{api}'. Upgrade to '{better}'."
            })
        
        # --- Security Check: Privileged Mode ---
        if kind in ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet']:
            spec = doc.get('spec') or {}
            template = spec.get('template') or {} if kind != 'Pod' else doc
            t_spec = template.get('spec') or {}
            containers = t_spec.get('containers') or []
            
            for c in containers:
                if c.get('securityContext', {}).get('privileged'):
                    findings.append({
                        "severity": "🔴 HIGH",
                        "code": "SEC_PRIVILEGED",
                        "msg": f"🚨 Security Risk: Container '{c.get('name')}' in {kind} '{name}' is Privileged."
                    })
        return findings

    def check_rbac_security(self, resource: dict) -> list:
        """Audits RBAC for wildcard permissions and secret access."""
        findings = []
        kind = resource.get("kind")
        name = resource.get('metadata', {}).get('name', 'unknown')
        rules = resource.get("rules", [])
    
        if kind in ["Role", "ClusterRole"]:
            for rule in rules:
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])

                # Global Wildcards
                if "*" in verbs and "*" in resources:
                    findings.append({
                        "severity": "🔴 HIGH",
                        "code": "RBAC_WILD",
                        "msg": f"🚨 Critical Security Risk: {kind} '{name}' uses global wildcards (*)."
                    })
                
                # Broad Secret Access
                elif "secrets" in resources and any(v in verbs for v in ["*", "get", "list", "watch"]):
                     findings.append({
                        "severity": "🟠 MED",
                        "code": "RBAC_SECRET",
                        "msg": f"🛡️ Security Warning: {kind} '{name}' allows read access to Secrets."
                    })
        return findings

    def audit_hpa(self, hpa_doc: dict, workload_docs: list) -> list:
        """
        Validates HPA logic against targeted workloads.
        """
        findings = []
        if hpa_doc.get('kind') != 'HorizontalPodAutoscalers' and hpa_doc.get('kind') != 'HorizontalPodAutoscaler':
            return findings

        spec = hpa_doc.get('spec') or {}
        target_ref = spec.get('scaleTargetRef') or {}
        target_name = target_ref.get('name')
        
        # Extract resource metrics to check
        resource_checks = []
        if spec.get('targetCPUUtilizationPercentage'):
            resource_checks.append('cpu')
            
        metrics = spec.get('metrics') or []
        for m in metrics:
            if m.get('type') == 'Resource':
                res_data = m.get('resource') or {}
                res_name = res_data.get('name')
                if res_name:
                    resource_checks.append(res_name)
        
        if not resource_checks:
            return findings

        # Find the target workload (Deployment/StatefulSet) in the bundle
        target_workload = next((w for w in workload_docs if w.get('metadata', {}).get('name') == target_name), None)
        
        if target_workload:
            kind = target_workload.get('kind')
            w_spec = target_workload.get('spec') or {}
            pod_template = w_spec.get('template') or {} if kind != 'Pod' else target_workload
            p_spec = pod_template.get('spec') or {}
            containers = p_spec.get('containers') or []
            
            for res_to_check in set(resource_checks):
                for c in containers:
                    res_config = c.get('resources') or {}
                    requests = res_config.get('requests') or {}
                    if res_to_check not in requests:
                        findings.append({
                            "severity": "🔴 HIGH",
                            "code": "HPA_MISSING_REQ",
                            "msg": f"📈 HPA Logic Error: Scales on {res_to_check}, but '{target_name}' lacks {res_to_check} requests."
                        })
        
        return findings
