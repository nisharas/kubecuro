"""
--------------------------------------------------------------------------------
AUTHOR:         Nishar A Sunkesala / FixMyK8s
DATE:           2025-12-31
PURPOSE:        The Synapse Engine: Maps cross-resource logic, 
                detecting Ghost Services, Namespace Isolation, and Port Gaps.
--------------------------------------------------------------------------------
"""
from ruamel.yaml import YAML
import os

class Synapse:
    def __init__(self):
        self.yaml = YAML()
        self.producers = []  # Pods, Deployments, StatefulSets
        self.consumers = []  # Services
        # Stores structured issues for the Main Summary Table: { 'filename': {'GHOST', 'PORT'} }
        self.files_with_issues = {} 

    def scan_file(self, file_path):
        """Deep scan for labels, namespaces, and ports."""
        try:
            with open(file_path, 'r') as f:
                docs = list(self.yaml.load_all(f))
            
            for doc in docs:
                if not doc or 'kind' not in doc: continue
                
                kind = doc['kind']
                name = doc.get('metadata', {}).get('name', 'unknown')
                namespace = doc.get('metadata', {}).get('namespace', 'default')

                # ENGINE: Identify Producers (Pods/Deployments/StatefulSets)
                if kind in ['Deployment', 'Pod', 'StatefulSet']:
                    spec = doc.get('spec', {})
                    # Get labels from the template if it's a Controller, else direct metadata
                    template = spec.get('template', {}) if kind != 'Pod' else doc
                    labels = template.get('metadata', {}).get('labels', {})
                    
                    # Extract Ports (Numbers and Names)
                    container_ports = []
                    # Controllers have nested pod specs; Pods are flat
                    pod_spec = spec.get('template', {}).get('spec', {}) if kind != 'Pod' else spec
                    containers = pod_spec.get('containers', [])
                    
                    for c in containers:
                        for p in c.get('ports', []):
                            # Store both port number and name for flexible matching
                            if p.get('containerPort'):
                                container_ports.append(p.get('containerPort'))
                            if p.get('name'):
                                container_ports.append(p.get('name'))

                    self.producers.append({
                        'name': name, 
                        'labels': labels, 
                        'namespace': namespace, 
                        'ports': container_ports, 
                        'file': os.path.basename(file_path)
                    })

                # ENGINE: Identify Consumers (Services)
                elif kind == 'Service':
                    spec = doc.get('spec', {})
                    selector = spec.get('selector', {})
                    
                    # Skip services without selectors (ExternalName or manual Endpoints)
                    if not selector: continue 

                    ports = spec.get('ports', [])
                    self.consumers.append({
                        'name': name, 
                        'selector': selector, 
                        'namespace': namespace,
                        'ports': ports, 
                        'file': os.path.basename(file_path)
                    })
        except Exception:
            # Silent skip on unparsable docs during initial scan
            pass

    def audit(self):
        """The Ultimate Pulse Check: Analyzes the relationship between producers and consumers."""
        issues = []
        for svc in self.consumers:
            fname = svc['file']
            if fname not in self.files_with_issues:
                self.files_with_issues[fname] = set()

            # 1. Look for matching labels
            # Compares Service Selectors against Pod Labels
            matches = [p for p in self.producers if all(item in p['labels'].items() for item in svc['selector'].items())]
            
            if not matches:
                issues.append(f"👻 [GHOST SERVICE] '{svc['name']}' in {svc['file']} targets labels {dict(svc['selector'])} but NO matching Pods exist.")
                self.files_with_issues[fname].add("GHOST")
                continue

            # 2. Check Namespaces (K8s Services cannot cross namespace boundaries by default)
            ns_match = [p for p in matches if p['namespace'] == svc['namespace']]
            if not ns_match:
                issues.append(f"🌐 [NAMESPACE MISMATCH] Service '{svc['name']}' found Pods with matching labels, but they are in different Namespaces!")
                self.files_with_issues[fname].add("NAMESPACE")
                continue

            # 3. Check Ports (Supports numeric and named targetPorts)
            for svc_port in svc['ports']:
                target = svc_port.get('targetPort')
                # If targetPort is not defined, K8s defaults it to the 'port' value
                if not target:
                    target = svc_port.get('port')
                
                # Check if any matched Pod exposes this target
                port_found = any(target in p['ports'] for p in ns_match)
                if not port_found and target:
                    issues.append(f"🔌 [PORT GAP] Service '{svc['name']}' targets port '{target}', but matching Pods in {svc['namespace']} don't expose it.")
                    self.files_with_issues[fname].add("PORT")

        return issues
