"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
DATE:           2025-12-31
PURPOSE:        The Shield Engine: API Deprecation Guard.
                Maps legacy K8s API versions to modern, stable alternatives.
--------------------------------------------------------------------------------
"""

class Shield:
    """The Deprecation Engine: Protects against outdated API versions."""
    
    # Database of retired APIs
    DEPRECATIONS = {
        "extensions/v1beta1": {
            "Ingress": "networking.k8s.io/v1",
            "Deployment": "apps/v1",
            "DaemonSet": "apps/v1",
            "ReplicaSet": "apps/v1",
            "NetworkPolicy": "networking.k8s.io/v1",
            "default": "apps/v1"
        },
        "networking.k8s.io/v1beta1": "networking.k8s.io/v1",
        "policy/v1beta1": "policy/v1",
        "rbac.authorization.k8s.io/v1beta1": "rbac.authorization.k8s.io/v1",
        "admissionregistration.k8s.io/v1beta1": "admissionregistration.k8s.io/v1",
        "apiextensions.k8s.io/v1beta1": "apiextensions.k8s.io/v1"
    }

    def check_version(self, doc):
        """Returns a high-impact warning if the API version is retired."""
        if not doc or not isinstance(doc, dict):
            return None
            
        api = doc.get('apiVersion')
        kind = doc.get('kind', 'Object')
        
        if api in self.DEPRECATIONS:
            mapping = self.DEPRECATIONS[api]
            
            # Handle complex mappings (like extensions/v1beta1)
            if isinstance(mapping, dict):
                better = mapping.get(kind, mapping.get("default"))
            else:
                better = mapping
                
            return f"🛡️  [DEPRECATED API] {kind} uses '{api}'. This is retired in modern clusters! Use '{better}' instead."
        
        return None
