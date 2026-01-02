"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
PURPOSE:        The Synapse Engine: Maps cross-resource logic gaps.
--------------------------------------------------------------------------------
"""
import os
from typing import List, Dict, Set
from ruamel.yaml import YAML

# Import the standardized model from the sibling file
from .models import AuditIssue

class Synapse:
    def __init__(self):
        self.yaml = YAML()
        self.producers = []  # Deployments, Pods, StatefulSets
        self.consumers = []  # Services
        # Tracking files that have already been flagged
        self.files_with_issues: Dict[str, Set[str]] = {} 

    def scan_file(self, file_path: str):
        """Extracts metadata, labels, and ports to build the logic map."""
        try:
            with open(file_path, 'r') as f:
                docs = list(self.yaml.load_all(f))
            
            for doc in docs:
                if not doc or 'kind' not in doc: 
                    continue
                
                kind = doc['kind']
                name = doc.get('metadata', {}).get('name', 'unknown')
                namespace = doc.get('metadata', {}).get('namespace', 'default')
                fname = os.path.basename(file_path)

                # --- Identify Producers (The things that run the code) ---
                if kind in ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet']:
                    spec = doc.get('spec', {})
                    # Controllers have nested pod specs; Pods are flat
                    template = spec.get('template', {}) if kind != 'Pod' else doc
                    labels = template.get('metadata', {}).get('labels', {})
                    
                    pod_spec = spec.get('template', {}).get('spec', {}) if kind != 'Pod' else spec
                    containers = pod_spec.get('containers', [])
                    
                    container_ports = []
                    for c in containers:
                        for p in c.get('ports', []):
                            if p.get('containerPort'): 
                                container_ports.append(p.get('containerPort'))
                            if p.get('name'): 
                                container_ports.append(p.get('name'))

                    self.producers.append({
                        'name': name,
                        'kind': kind,
                        'labels': labels,
                        'namespace': namespace,
                        'ports': container_ports,
                        'file': fname
                    })

                # --- Identify Consumers (The things that route traffic) ---
                elif kind == 'Service':
                    spec = doc.get('spec', {})
                    selector = spec.get('selector', {})
                    
                    # Skip headless or external services without selectors
                    if not selector: 
                        continue 

                    self.consumers.append({
                        'name': name,
                        'selector': selector,
                        'namespace': namespace,
                        'ports': spec.get('ports', []),
                        'file': fname
                    })
        except Exception:
            # Silently skip unparseable or non-YAML files during the scan phase
            pass

    def audit(self) -> List[AuditIssue]:
        """Performs cross-resource analysis to find the 'Logic Gap'."""
        results = []
        
        for svc in self.consumers:
            fname = svc['file']
            
            # 1. Label Check (GHOST SERVICE)
            # Find all producers that match EVERY label in the service selector
            matches = [
                p for p in self.producers 
                if all(item in p['labels'].items() for item in svc['selector'].items())
            ]
            
            if not matches:
                results.append(AuditIssue(
                    engine="Synapse",
                    code="GHOST",
                    severity="🔴 HIGH",
                    file=fname,
                    message=f"Service '{svc['name']}' targets labels {dict(svc['selector'])} but matches 0 Pods.",
                    remediation=f"Check labels in Deployment/Pod or update Service selector in {fname}."
                ))
                continue

            # 2. Namespace Check (NAMESPACE MISMATCH)
            # K8s Services only route to Pods in the same namespace
            ns_match = [p for p in matches if p['namespace'] == svc['namespace']]
            if not ns_match:
                # We found matching labels, but they are in a different namespace
                offending_ns = matches[0]['namespace']
                results.append(AuditIssue(
                    engine="Synapse",
                    code="NAMESPACE",
                    severity="🟠 MED",
                    file=fname,
                    message=f"Service '{svc['name']}' matches Pods, but they are in Namespace '{offending_ns}'.",
                    remediation=f"Move Service '{svc['name']}' to the '{offending_ns}' namespace."
                ))
                continue

            # 3. Port Check (PORT GAP)
            # Check if targetPort on Service exists as containerPort on matched Pods
            for svc_port in svc['ports']:
                # If targetPort is missing, K8s defaults it to the 'port' value
                target = svc_port.get('targetPort') or svc_port.get('port')
                
                # Check both numeric matches and named port matches
                port_found = any(target in p['ports'] for p in ns_match)
                
                if not port_found:
                    results.append(AuditIssue(
                        engine="Synapse",
                        code="PORT",
                        severity="🔴 HIGH",
                        file=fname,
                        message=f"Service '{svc['name']}' routes to port '{target}', but matched Pods don't expose it.",
                        remediation=f"Add 'containerPort: {target}' to the container spec in your Deployment."
                    ))
        
        return results
