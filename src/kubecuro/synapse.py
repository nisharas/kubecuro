"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:     The Synapse Engine: Maps cross-resource logic gaps (Expanded).
--------------------------------------------------------------------------------
"""
import os
from typing import List, Dict, Set
from ruamel.yaml import YAML

# Import the standardized model
from .models import AuditIssue

class Synapse:
    def __init__(self):
        self.yaml = YAML(typ='safe', pure=True)
        self.producers = []  # Deployments, Pods, StatefulSets
        self.consumers = []  # Services
        self.ingresses = []  # Ingress objects
        self.configs = []    # ConfigMaps and Secrets

    def scan_file(self, file_path: str):
        """Extracts deep metadata to build the logic map."""
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
                spec = doc.get('spec', {})

                # --- 1. Identify Producers (Workloads) ---
                if kind in ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet']:
                    template = spec.get('template', {}) if kind != 'Pod' else doc
                    labels = template.get('metadata', {}).get('labels', {})
                    pod_spec = template.get('spec', {}) if kind != 'Pod' else spec
                    containers = pod_spec.get('containers', [])
                    
                    # Capture ports and probe data
                    container_ports = []
                    probes = []
                    for c in containers:
                        for p in c.get('ports', []):
                            if p.get('containerPort'): container_ports.append(p.get('containerPort'))
                            if p.get('name'): container_ports.append(p.get('name'))
                        
                        # Extract Probes
                        for p_type in ['livenessProbe', 'readinessProbe', 'startupProbe']:
                            p_data = c.get(p_type)
                            if p_data and 'httpGet' in p_data:
                                probes.append({'type': p_type, 'port': p_data['httpGet'].get('port')})

                    self.producers.append({
                        'name': name, 'kind': kind, 'labels': labels, 
                        'namespace': namespace, 'ports': container_ports, 
                        'probes': probes, 'file': fname,
                        'serviceName': spec.get('serviceName') # For StatefulSets
                    })

                # --- 2. Identify Consumers (Services) ---
                elif kind == 'Service':
                    self.consumers.append({
                        'name': name, 'namespace': namespace, 'file': fname,
                        'selector': spec.get('selector', {}),
                        'ports': spec.get('ports', []),
                        'clusterIP': spec.get('clusterIP')
                    })

                # --- 3. Identify Ingress ---
                elif kind == 'Ingress':
                    rules = spec.get('rules', [])
                    tls = spec.get('tls', [])
                    self.ingresses.append({
                        'name': name, 'namespace': namespace, 'file': fname,
                        'rules': rules, 'tls': tls
                    })

                # --- 4. Identify Configs/Secrets ---
                elif kind in ['ConfigMap', 'Secret']:
                    self.configs.append({'name': name, 'kind': kind, 'namespace': namespace})

        except Exception:
            pass

    def audit(self) -> List[AuditIssue]:
        """Performs deep cross-resource analysis."""
        results = []
        
        # --- AUDIT: Service to Pod Matching ---
        for svc in self.consumers:
            if not svc['selector']: continue
            
            matches = [p for p in self.producers if all(item in p['labels'].items() for item in svc['selector'].items())]
            
            if not matches:
                results.append(AuditIssue("Synapse", "GHOST", "🔴 HIGH", svc['file'], 
                    f"Service '{svc['name']}' targets labels {svc['selector']} but matches 0 Pods.", "Update selector."))
                continue

            # Check Namespace Alignment
            ns_match = [p for p in matches if p['namespace'] == svc['namespace']]
            if not ns_match:
                results.append(AuditIssue("Synapse", "NAMESPACE", "🟠 MED", svc['file'], 
                    f"Service '{svc['name']}' matches Pods in wrong namespace.", "Align namespaces."))
                continue

        # --- AUDIT: StatefulSet Headless Service ---
        for sts in [p for p in self.producers if p['kind'] == 'StatefulSet']:
            svc_name = sts.get('serviceName')
            match = next((s for s in self.consumers if s['name'] == svc_name), None)
            if not match:
                results.append(AuditIssue("Synapse", "STS_SVC", "🔴 HIGH", sts['file'], 
                    f"StatefulSet '{sts['name']}' missing Headless Service '{svc_name}'", "Create Headless Service."))
            elif match.get('clusterIP') != 'None':
                results.append(AuditIssue("Synapse", "STS_IP", "🟠 MED", sts['file'], 
                    f"Service '{svc_name}' must have clusterIP: None for StatefulSet.", "Set clusterIP: None."))

        # --- AUDIT: Probe Port Consistency ---
        for p in self.producers:
            for probe in p.get('probes', []):
                if probe['port'] and probe['port'] not in p['ports']:
                    results.append(AuditIssue("Synapse", "PROBE_GAP", "🟠 MED", p['file'], 
                        f"Probe '{probe['type']}' uses port {probe['port']} not exposed in container.", "Expose port in containerPort."))

        # --- AUDIT: Ingress Backends ---
        for ing in self.ingresses:
            for rule in ing.get('rules', []):
                paths = rule.get('http', {}).get('paths', [])
                for path in paths:
                    svc_ref = path.get('backend', {}).get('service', {}).get('name') or path.get('backend', {}).get('serviceName')
                    if svc_ref and not any(s['name'] == svc_ref for s in self.consumers):
                        results.append(AuditIssue("Synapse", "INGRESS_GAP", "🔴 HIGH", ing['file'], 
                            f"Ingress backend Service '{svc_ref}' not found.", "Create the missing Service."))

        return results
