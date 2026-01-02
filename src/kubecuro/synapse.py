"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
PURPOSE:        The Synapse Engine: Maps cross-resource logic.
--------------------------------------------------------------------------------
"""
from ruamel.yaml import YAML
import os
from dataclasses import dataclass
from typing import List, Dict, Set

@dataclass
class AuditIssue:
    engine: str
    code: str
    severity: str
    file: str
    message: str
    remediation: str

class Synapse:
    def __init__(self):
        self.yaml = YAML()
        self.producers = []  # Pods, Deployments, StatefulSets
        self.consumers = []  # Services
        self.files_with_issues: Dict[str, Set[str]] = {} 

    def scan_file(self, file_path: str):
        """Extracts metadata, labels, and ports from manifests."""
        try:
            with open(file_path, 'r') as f:
                docs = list(self.yaml.load_all(f))
            
            for doc in docs:
                if not doc or 'kind' not in doc: continue
                
                kind = doc['kind']
                name = doc.get('metadata', {}).get('name', 'unknown')
                namespace = doc.get('metadata', {}).get('namespace', 'default')
                fname = os.path.basename(file_path)

                if kind in ['Deployment', 'Pod', 'StatefulSet']:
                    spec = doc.get('spec', {})
                    template = spec.get('template', {}) if kind != 'Pod' else doc
                    labels = template.get('metadata', {}).get('labels', {})
                    
                    pod_spec = spec.get('template', {}).get('spec', {}) if kind != 'Pod' else spec
                    containers = pod_spec.get('containers', [])
                    
                    container_ports = []
                    for c in containers:
                        for p in c.get('ports', []):
                            if p.get('containerPort'): container_ports.append(p.get('containerPort'))
                            if p.get('name'): container_ports.append(p.get('name'))

                    self.producers.append({
                        'name': name, 'labels': labels, 'namespace': namespace, 
                        'ports': container_ports, 'file': fname
                    })

                elif kind == 'Service':
                    spec = doc.get('spec', {})
                    selector = spec.get('selector', {})
                    if not selector: continue 

                    self.consumers.append({
                        'name': name, 'selector': selector, 'namespace': namespace,
                        'ports': spec.get('ports', []), 'file': fname
                    })
        except Exception:
            pass

    def audit(self) -> List[AuditIssue]:
        """Analyzes relationships and returns structured AuditIssue objects."""
        results = []
        for svc in self.consumers:
            fname = svc['file']
            
            # 1. Label Match (GHOST)
            matches = [p for p in self.producers if all(item in p['labels'].items() for item in svc['selector'].items())]
            
            if not matches:
                results.append(AuditIssue(
                    engine="Synapse", code="GHOST", severity="🔴 HIGH", file=fname,
                    message=f"Service '{svc['name']}' targets labels {dict(svc['selector'])} but matches NO Pods.",
                    remediation=f"Update Service selector or Pod labels in {fname}."
                ))
                continue

            # 2. Namespace Match
            ns_match = [p for p in matches if p['namespace'] == svc['namespace']]
            if not ns_match:
                results.append(AuditIssue(
                    engine="Synapse", code="NAMESPACE", severity="🟠 MED", file=fname,
                    message=f"Service '{svc['name']}' matches Pods, but they are in a different Namespace.",
                    remediation="Ensure Service and Deployment share the same namespace."
                ))
                continue

            # 3. Port Match (PORT)
            for svc_port in svc['ports']:
                target = svc_port.get('targetPort') or svc_port.get('port')
                port_found = any(target in p['ports'] for p in ns_match)
                if not port_found:
                    results.append(AuditIssue(
                        engine="Synapse", code="PORT", severity="🔴 HIGH", file=fname,
                        message=f"Service '{svc['name']}' targets port '{target}', but Pods don't expose it.",
                        remediation=f"Add containerPort: {target} to your Deployment spec."
                    ))
        return results
