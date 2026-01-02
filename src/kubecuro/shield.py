"""
--------------------------------------------------------------------------------
AUTHOR:          Nishar A Sunkesala / FixMyK8s
PURPOSE:          The Shield Engine: API Deprecation & Resource Stability Guard.
--------------------------------------------------------------------------------
"""

class Shield:
    """The Stability Engine: Protects against outdated APIs and misconfigured HPA logic."""
    
    # Comprehensive Database of retired/deprecated APIs (Expanded)
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

    def check_version(self, doc: dict) -> str:
        """Checks for retired API versions and suggests the modern replacement."""
        if not doc or not isinstance(doc, dict):
            return None
            
        api = doc.get('apiVersion')
        kind = doc.get('kind', 'Object')
        
        if api in self.DEPRECATIONS:
            mapping = self.DEPRECATIONS[api]
            # If mapping is a dict, look for Kind-specific replacement, else use default
            better = mapping.get(kind, mapping.get("default")) if isinstance(mapping, dict) else mapping
            return f"🛡️ [DEPRECATED API] {kind} uses '{api}'. Upgrade to '{better}'."
        
        return None

    def audit_hpa(self, hpa_doc: dict, workload_docs: list) -> list:
        """
        Validates HorizontalPodAutoscaler logic.
        Ensures the Target workload has the necessary resource requests.
        """
        issues = []
        if hpa_doc.get('kind') != 'HorizontalPodAutoscaler':
            return issues

        spec = hpa_doc.get('spec', {})
        target_ref = spec.get('scaleTargetRef', {})
        target_name = target_ref.get('name')
        
        # Analyze Metrics block
        metrics = spec.get('metrics', [])
        
        # Legacy support for HPA v1 (cpu only)
        target_cpu_util = spec.get('targetCPUUtilizationPercentage')
        resource_checks = []
        
        if target_cpu_util:
            resource_checks.append('cpu')
            
        # Modern v2 metrics support
        for m in metrics:
            if m.get('type') == 'Resource':
                res_name = m.get('resource', {}).get('name')
                if res_name:
                    resource_checks.append(res_name)
        
        if not resource_checks:
            return issues

        # Cross-reference with the workload bundle
        target_workload = next((w for w in workload_docs if w.get('metadata', {}).get('name') == target_name), None)
        
        if target_workload:
            pod_template = target_workload.get('spec', {}).get('template', {})
            containers = pod_template.get('spec', {}).get('containers', [])
            
            for res_to_check in set(resource_checks):
                for c in containers:
                    requests = c.get('resources', {}).get('requests', {})
                    if res_to_check not in requests:
                        issues.append(
                            f"📈 [HPA LOGIC ERROR] Scales on {res_to_check}, but '{target_name}' container '{c.get('name')}' lacks {res_to_check} requests."
                        )
        
        return issues
