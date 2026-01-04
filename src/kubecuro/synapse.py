"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:     The Synapse Engine: Maps cross-resource logic gaps (Fully Expanded).
--------------------------------------------------------------------------------
"""
import os
from typing import List
from ruamel.yaml import YAML

from .models import AuditIssue


class Synapse:
    def __init__(self):
        # We use 'safe' type for analysis to prevent arbitrary code execution
        self.yaml = YAML(typ='safe', pure=True)
        self.all_docs = []       # EVERY doc encountered (For 100% API Coverage)
        self.producers = []      # Workload metadata for logic mapping
        self.workload_docs = []  # Specifically Pod-bearing docs for HPA checks
        self.consumers = []      # Services
        self.ingresses = []      # Ingress objects
        self.configs = []        # ConfigMaps and Secrets
        self.hpas = []           # HPA objects
        self.netpols = []        # NetworkPolicies

    def scan_file(self, file_path: str):
        """Extracts deep metadata and tags origin file for every resource."""
        try:
            fname = os.path.basename(file_path)
            with open(file_path, 'r') as f:
                content = f.read()
                if not content.strip(): return # Skip empty files
                # Load all documents in a multi-doc YAML file
                docs = list(self.yaml.load_all(content))
            
            for doc in docs:
                if not doc or not isinstance(doc, dict) or 'kind' not in doc: continue
                
                # 1. Tag origin and store in the master list for Shield API checks
                doc['_origin_file'] = fname
                self.all_docs.append(doc)
                
                kind = doc['kind']
                name = doc.get('metadata', {}).get('name', 'unknown')
                ns = doc.get('metadata', {}).get('namespace', 'default')
                spec = doc.get('spec', {}) or {}

                # --- 2. Workloads (Producers) ---
                if kind in ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet']:
                    self.workload_docs.append(doc)
                    template = spec.get('template', {}) if kind in ['Deployment', 'StatefulSet', 'DaemonSet'] else doc
                    # Safety guard: Ensure labels is always a dict
                    labels = template.get('metadata', {}).get('labels') or {}
                    pod_spec = template.get('spec', {}) if kind != 'Pod' else spec
                    containers = pod_spec.get('containers') or []
                    
                    container_ports = []
                    probes = []
                    volumes = pod_spec.get('volumes') or []
                    
                    for c in containers:
                        # Extract ports for Probe/Service validation
                        for p in c.get('ports') or []:
                            if p.get('containerPort'): container_ports.append(p.get('containerPort'))
                            if p.get('name'): container_ports.append(p.get('name'))
                        
                        # Extract Health Probes
                        for p_type in ['livenessProbe', 'readinessProbe', 'startupProbe']:
                            p_data = c.get(p_type)
                            if p_data and 'httpGet' in p_data:
                                probes.append({'type': p_type, 'port': p_data['httpGet'].get('port')})

                    self.producers.append({
                        'name': name, 'kind': kind, 'labels': labels, 'namespace': ns, 
                        'ports': container_ports, 'probes': probes, 'file': fname,
                        'serviceName': spec.get('serviceName'), 'volumes': volumes
                    })

                # --- 3. Services (Consumers) ---
                elif kind == 'Service':
                    self.consumers.append({
                        'name': name, 'namespace': ns, 'file': fname,
                        'selector': spec.get('selector') or {},
                        'ports': spec.get('ports') or [],
                        'clusterIP': spec.get('clusterIP')
                    })

                # --- 4. Ingress, HPA, Configs ---
                elif kind == 'Ingress':
                    self.ingresses.append({'name': name, 'namespace': ns, 'file': fname, 'spec': spec})
                elif kind == 'HorizontalPodAutoscaler':
                    self.hpas.append({'name': name, 'file': fname, 'doc': doc})
                elif kind in ['ConfigMap', 'Secret']:
                    self.configs.append({'name': name, 'kind': kind, 'namespace': ns, 'file': fname})
                elif kind == 'NetworkPolicy':
                    self.netpols.append({'name': name, 'file': fname, 'selector': spec.get('podSelector') or {}})

        except Exception: 
            # Silent fail for unparseable YAMLs to prevent tool crash
            pass

    def audit(self) -> List[AuditIssue]:
        from .shield import Shield
        """Performs deep cross-resource analysis and returns issues."""
        results = []
        shield = Shield()

        # --- AUDIT: Service to Pod Matching (Ghost Service Detection) ---
        for svc in self.consumers:
            if not svc['selector']: continue
            
            # Logic: All Service selector labels must exist in the Workload labels
            matches = [
                p for p in self.producers 
                if p['namespace'] == svc['namespace'] and 
                svc['selector'].items() <= p['labels'].items()
            ]
            
            if not matches:
                results.append(AuditIssue(
                    code="GHOST", 
                    severity="🔴 HIGH", 
                    file=svc['file'], 
                    message=f"GHOST SERVICE: Service '{svc['name']}' matches 0 workload pods.", 
                    fix="Update Service selector to match Deployment labels.",
                    source="Synapse"
                ))

        # --- AUDIT: Ingress to Service Mapping ---
        for ing in self.ingresses:
            rules = ing['spec'].get('rules') or []
            for rule in rules:
                paths = rule.get('http', {}).get('paths') or []
                for path in paths:
                    backend = path.get('backend', {})
                    svc_name = backend.get('serviceName') or backend.get('service', {}).get('name')
                    if svc_name:
                        match = next((s for s in self.consumers if s['name'] == svc_name and s['namespace'] == ing['namespace']), None)
                        if not match:
                            results.append(AuditIssue(
                                code="INGRESS_ORPHAN", 
                                severity="🔴 HIGH", 
                                file=ing['file'], 
                                message=f"Ingress references non-existent Service '{svc_name}'.", 
                                fix="Create the missing Service or fix the backend name.",
                                source="Synapse"
                            ))

        # --- AUDIT: ConfigMap/Secret Volume Existence ---
        for p in self.producers:
            for vol in p.get('volumes') or []:
                ref_name = None
                if 'configMap' in vol: ref_name = vol['configMap'].get('name')
                if 'secret' in vol: ref_name = vol['secret'].get('secretName')
                
                if ref_name:
                    exists = any(c['name'] == ref_name and c['namespace'] == p['namespace'] for c in self.configs)
                    if not exists:
                        results.append(AuditIssue(
                            code="VOL_MISSING", 
                            severity="🟠 MED", 
                            file=p['file'], 
                            message=f"Workload '{p['name']}' references missing ConfigMap/Secret '{ref_name}'.", 
                            fix="Verify the resource name and namespace.",
                            source="Synapse"
                        ))

        # In Synapse.audit()
        for hpa in self.hpas:
            hpa_errors = shield.audit_hpa(hpa['doc'], self.workload_docs)
            for err in hpa_errors:
                results.append(AuditIssue(
                    code=err['code'], # Extract from dict
                    severity=err['severity'], 
                    file=hpa['file'], 
                    message=err['msg'], 
                    line=err.get('line'),
                    fix="Add CPU/Memory resource requests to the target Deployment.",
                    source="Shield"
                ))

        # --- AUDIT: Health Probe Gaps ---
        for p in self.producers:
            for probe in p.get('probes') or []:
                if probe['port'] and probe['port'] not in p['ports']:
                    results.append(AuditIssue(
                        code="PROBE_GAP", 
                        severity="🟠 MED", 
                        file=p['file'], 
                        message=f"Health probe port '{probe['port']}' is not exposed in containerPorts.", 
                        fix="Add the port to the container's ports list.",
                        source="Synapse"
                    ))

        # --- AUDIT: Service Port Alignment ---
        for svc in self.consumers:
            # Find matching producers
            for p in self.producers:
                if p['namespace'] == svc['namespace'] and svc['selector'].items() <= p['labels'].items():
                    for s_port in svc['ports']:
                        t_port = s_port.get('targetPort')
                        # Check if targetPort (int or name) exists in the producer's ports
                        if t_port and t_port not in p['ports']:
                            results.append(AuditIssue(
                                code="PORT_MISMATCH",
                                severity="🟠 MED",
                                file=svc['file'],
                                message=f"Service '{svc['name']}' targetPort '{t_port}' not found in workload '{p['name']}'.",
                                fix=f"Expose port {t_port} in {p['kind']} '{p['name']}' container ports.",
                                source="Synapse"
                            ))

        return results
