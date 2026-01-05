"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:      The Synapse Engine: Maps cross-resource logic gaps (Fully Expanded).
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
                    labels = template.get('metadata', {}).get('labels') or {}
                    pod_spec = template.get('spec', {}) if kind != 'Pod' else spec
                    containers = pod_spec.get('containers') or []
                    
                    container_ports = []
                    probes = []
                    volumes = pod_spec.get('volumes') or []
                    
                    for c in containers:
                        for p in c.get('ports') or []:
                            if p.get('containerPort'): container_ports.append(p.get('containerPort'))
                            if p.get('name'): container_ports.append(p.get('name'))
                        
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
                    self.ingresses.append({'name': name, 'namespace': ns, 'file': fname, 'spec': spec, 'raw_doc': doc})
                elif kind == 'HorizontalPodAutoscaler':
                    self.hpas.append({'name': name, 'file': fname, 'doc': doc})
                elif kind in ['ConfigMap', 'Secret']:
                    self.configs.append({'name': name, 'kind': kind, 'namespace': ns, 'file': fname})
                elif kind == 'NetworkPolicy':
                    self.netpols.append({'name': name, 'file': fname, 'selector': spec.get('podSelector') or {}})

        except Exception: 
            pass

    def audit(self) -> List[AuditIssue]:
        from .shield import Shield
        """Performs deep cross-resource analysis and returns issues."""
        results = []
        shield = Shield()

        # --- AUDIT: Service to Pod Matching (Ghost Service Detection) ---
        for svc in self.consumers:
            selector = svc.get('selector') or {}
            if not selector: continue
            
            # Robust matching: ensures labels are not None and selector items match
            matches = [
                p for p in self.producers 
                if p['namespace'] == svc['namespace'] and 
                p.get('labels') is not None and 
                selector.items() <= p['labels'].items()
            ]
            
            if not matches:
                # Precisely match the document from all_docs
                raw_svc = next((d for d in self.all_docs if 
                                d.get('kind') == 'Service' and 
                                d.get('metadata', {}).get('name') == svc['name']), None)
                
                results.append(AuditIssue(
                    code="GHOST", 
                    severity="🔴 HIGH", 
                    file=svc['file'], 
                    line=shield.get_line(raw_svc, 'selector') if raw_svc else 1,
                    message=f"GHOST SERVICE: Service '{svc['name']}' matches 0 workload pods.", 
                    fix="Update Service selector to match Deployment labels.",
                    source="Synapse"
                ))

        # --- AUDIT: Ingress to Service Mapping & Port Alignment ---
        for ing in self.ingresses:
            rules = ing['spec'].get('rules') or []
            for rule in rules:
                paths = rule.get('http', {}).get('paths') or []
                for path in paths:
                    backend = path.get('backend', {})
                    svc_node = backend.get('service', backend)
                    svc_name = svc_node.get('name') or backend.get('serviceName')
                    port_node = svc_node.get('port', {})
                    t_port = port_node.get('number') if isinstance(port_node, dict) else port_node

                    if svc_name:
                        match = next((s for s in self.consumers if s['name'] == svc_name and s['namespace'] == ing['namespace']), None)
                        
                        if not match:
                            results.append(AuditIssue(
                                code="INGRESS_ORPHAN", 
                                severity="🔴 HIGH", 
                                file=ing['file'],
                                line=shield.get_line(path),
                                message=f"Ingress references non-existent Service '{svc_name}'.", 
                                fix="Create the missing Service or fix the backend name.",
                                source="Synapse"
                            ))
                        elif t_port:
                            svc_ports = [p.get('port') for p in match.get('ports', [])]
                            if t_port not in svc_ports:
                                results.append(AuditIssue(
                                    code="INGRESS_PORT_MISMATCH",
                                    severity="🔴 CRITICAL",
                                    file=ing['file'],
                                    line=shield.get_line(path),
                                    message=f"Ingress targets port {t_port}, but Service '{svc_name}' only exposes {svc_ports}.",
                                    fix=f"Change Ingress port to one of {svc_ports}.",
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
                        # Find the container/workload line
                        raw_workload = next((d for d in self.all_docs if d.get('metadata', {}).get('name') == p['name']), None)
                        results.append(AuditIssue(
                            code="VOL_MISSING", 
                            severity="🟠 MED", 
                            file=p['file'],
                            line=shield.get_line(raw_workload, 'spec') if raw_workload else 1,
                            message=f"Workload '{p['name']}' references missing ConfigMap/Secret '{ref_name}'.", 
                            fix="Verify the resource name and namespace.",
                            source="Synapse"
                        ))

        # --- AUDIT: HPA Resource Validation (Using Shield) ---
        for hpa in self.hpas:
            hpa_errors = shield.audit_hpa(hpa['doc'], self.workload_docs)
            for err in hpa_errors:
                results.append(AuditIssue(
                    code=err['code'], 
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
                    raw_p = next((d for d in self.all_docs if d.get('metadata', {}).get('name') == p['name']), None)
                    results.append(AuditIssue(
                        code="PROBE_GAP", 
                        severity="🟠 MED", 
                        file=p['file'],
                        line=shield.get_line(raw_p, 'spec') if raw_p else 1,
                        message=f"Health probe port '{probe['port']}' is not exposed in containerPorts.", 
                        fix="Add the port to the container's ports list.",
                        source="Synapse"
                    ))

        # --- AUDIT: Service Port Alignment (Type-Safe Comparison) ---
        for svc in self.consumers:
            raw_svc_doc = next((d for d in self.all_docs if d.get('metadata', {}).get('name') == svc['name'] and d.get('kind') == 'Service'), None)
            
            for p in self.producers:
                # Logic Match: Same namespace and selector matches labels
                if p['namespace'] == svc['namespace'] and (svc.get('selector') or {}).items() <= (p.get('labels') or {}).items():
                    for s_port in svc['ports']:
                        target_p = s_port.get('targetPort')
                        if not target_p: continue
                        
                        # Type-Safe check: convert all to string to handle 80 vs "80"
                        workload_ports = [str(x) for x in p.get('ports', [])]
                        
                        if str(target_p) not in workload_ports:
                            err_line = shield.get_line(raw_svc_doc, 'spec') if raw_svc_doc else 1
                            
                            results.append(AuditIssue(
                                code="PORT_MISMATCH",
                                severity="🟠 MED",
                                file=svc['file'],
                                line=err_line, 
                                message=f"Service '{svc['name']}' targetPort '{target_p}' not found in workload '{p['name']}'.",
                                fix=f"Expose port {target_p} in {p['kind']} '{p['name']}' container ports.",
                                source="Synapse"
                            ))

        return results
