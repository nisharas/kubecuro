#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:      The Synapse Engine: Maps cross-resource logic gaps.
--------------------------------------------------------------------------------
"""
import os
from typing import List
from ruamel.yaml import YAML

# Robust model import
try:
    from kubecuro.models import AuditIssue
except ImportError:
    try:
        from models import AuditIssue
    except ImportError:
        from .models import AuditIssue

class Synapse:
    def __init__(self):
        """Initializes the correlation engine with Round-Trip YAML support."""
        self.yaml = YAML(typ='rt')
        self.yaml.preserve_quotes = True
        self.yaml.allow_duplicate_keys = True
        
        # Resource Registry
        self.all_docs = []
        self.producers = []      # Workloads (Deployments/Pods)
        self.workload_docs = []  # Raw workload dicts for HPA audit
        self.consumers = []      # Services
        self.ingresses = []      # Ingress resources
        self.configs = []        # ConfigMaps/Secrets
        self.hpas = []           # HPAs
        self.netpols = []        # Network Policies

    def get_line(self, doc, key=None):
        """Extract line from ruamel.yaml object (Shield-compatible)."""
        try:
            if not doc:
                return 1
            if key and hasattr(doc, 'lc') and hasattr(doc.lc, 'data') and key in doc.lc.data:
                return doc.lc.data[key][0] + 1
            if hasattr(doc, 'lc') and hasattr(doc.lc, 'line'):
                return doc.lc.line + 1
            return 1
        except Exception:
            return 1

    def scan_file(self, file_path: str):
        """Deep-scans YAML, preserving document references."""
        try:
            fname = os.path.basename(file_path)
            if not os.path.exists(file_path):
                return

            with open(file_path, 'r') as f:
                content = f.read()
                if not content.strip():
                    return
                    
                docs = list(self.yaml.load_all(content))
            
            for doc in docs:
                if not doc or not isinstance(doc, dict) or 'kind' not in doc:
                    continue
                
                doc['_origin_file'] = fname
                self.all_docs.append(doc)
                
                kind = doc['kind']
                metadata = doc.get('metadata', {})
                name = metadata.get('name', 'unknown')
                ns = metadata.get('namespace', 'default')
                spec = doc.get('spec', {}) or {}
 
                # --- 1. Workload Processing (Deployments, Pods, CronJobs, etc.) ---
                workloads = ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet', 'CronJob', 'Job']
                if kind in workloads:
                    self.workload_docs.append(doc)
                    
                    # 1a. Extract Pod Spec and Metadata based on Kind
                    if kind == 'Pod':
                        t_metadata = metadata
                        p_spec = spec
                    elif kind == 'CronJob':
                        job_spec = spec.get('jobTemplate', {}).get('spec', {})
                        template = job_spec.get('template', {})
                        t_metadata = template.get('metadata', {})
                        p_spec = template.get('spec', {})
                    else:
                        template = spec.get('template', {})
                        t_metadata = template.get('metadata', {})
                        p_spec = template.get('spec', {})

                    labels = t_metadata.get('labels') or {}
                    containers = p_spec.get('containers') or []
                    
                    # 1b. Map Ports and Probes
                    c_ports = []
                    probes = []
                    for c in containers:
                        for p in c.get('ports') or []:
                            if p.get('containerPort'):
                                c_ports.append(str(p.get('containerPort')))
                            if p.get('name'):
                                c_ports.append(p.get('name'))
                        
                        for p_type in ['livenessProbe', 'readinessProbe', 'startupProbe']:
                            p_data = c.get(p_type)
                            if p_data and 'httpGet' in p_data:
                                probes.append({
                                    'type': p_type, 
                                    'port': str(p_data['httpGet'].get('port')),
                                    'path': p_data['httpGet'].get('path')
                                })

                    # 1c. Register as Producer
                    self.producers.append({
                        'name': name, 
                        'kind': kind, 
                        'labels': labels, 
                        'namespace': ns,
                        'ports': c_ports, 
                        'probes': probes, 
                        'file': fname,
                        'volumes': p_spec.get('volumes') or [], 
                        'raw_doc': doc
                    })

                # --- 2. Service Processing ---
                elif kind == 'Service':
                    self.consumers.append({
                        'name': name, 'namespace': ns, 'file': fname,
                        'selector': spec.get('selector') or {},
                        'ports': spec.get('ports') or [],
                        'type': spec.get('type', 'ClusterIP'),
                        'raw_doc': doc
                    })

                # --- 3. Other Resources ---
                elif kind == 'Ingress':
                    self.ingresses.append({
                        'name': name, 'namespace': ns, 'file': fname,
                        'spec': spec, 'raw_doc': doc
                    })
                elif kind == 'HorizontalPodAutoscaler':
                    self.hpas.append({
                        'name': name, 'namespace': ns, 'file': fname, 'doc': doc
                    })
                elif kind in ['ConfigMap', 'Secret']:
                    self.configs.append({
                        'name': name, 'kind': kind, 'namespace': ns, 'file': fname
                    })
                elif kind == 'NetworkPolicy':
                    self.netpols.append({
                        'name': name, 'namespace': ns, 'file': fname,
                        'selector': spec.get('podSelector', {}).get('matchLabels') or {}
                    })

        except Exception:
            pass

    def audit(self) -> List[AuditIssue]:
        """Complete correlation suite across manifest graph."""
        try:
            from shield import Shield
        except ImportError:
            return []
            
        results = []
        shield = Shield()

        # --- A. DEEP SCAN (Shield logic) ---
        # Runs individual resource audits (API version, Security Context, etc.)
        for doc in self.all_docs:
            findings = shield.scan(doc, self.all_docs)
            for f in findings:
                results.append(AuditIssue(
                    code=f['code'], severity=f['severity'], 
                    file=doc.get('_origin_file', 'unknown'),
                    line=f.get('line', 1), message=f['msg'],
                    fix="Check manifest for compliance.", source="Shield"
                ))

        # --- B. CROSS-RESOURCE CORRELATIONS (Synapse logic) ---

        # 1. GHOST SERVICE: Service exists but selects no pods
        for svc in self.consumers:
            selector = svc.get('selector')
            if not selector: continue
                
            matches = [p for p in self.producers 
                      if p['namespace'] == svc['namespace'] and 
                      selector.items() <= p['labels'].items()]
            
            if not matches:
                results.append(AuditIssue(
                    code="GHOST", severity=shield.HIGH, file=svc['file'],
                    line=self.get_line(svc['raw_doc'], 'selector'),
                    message=f"GHOST SERVICE: Service '{svc['name']}' selector matches 0 pods.",
                    fix="Align Service 'spec.selector' with Deployment labels.",
                    source="Synapse"
                ))

        # 2. INGRESS -> SERVICE VALIDATION
        # Validates that the Ingress points to a real service and correct port
        for ing in self.ingresses:
            rules = ing['spec'].get('rules') or []
            for rule in rules:
                paths = rule.get('http', {}).get('paths') or []
                for path in paths:
                    backend = path.get('backend', {})
                    svc_node = backend.get('service', backend)
                    s_name = svc_node.get('name') or backend.get('serviceName')
                    
                    p_node = svc_node.get('port', {})
                    t_port = p_node.get('number') if isinstance(p_node, dict) else p_node

                    if s_name:
                        match = next((s for s in self.consumers 
                                    if s['name'] == s_name and s['namespace'] == ing['namespace']), None)
                        if not match:
                            results.append(AuditIssue(
                                code="INGRESS_ORPHAN", severity=shield.HIGH, 
                                file=ing['file'],
                                line=self.get_line(ing['raw_doc'], 'spec'),
                                message=f"Ingress backend references missing Service '{s_name}'.",
                                fix="Ensure Service exists in same namespace.",
                                source="Synapse"
                            ))
                        elif t_port:
                            s_ports = [p.get('port') for p in match.get('ports', [])]
                            # Check both numeric and named ports
                            s_names = [p.get('name') for p in match.get('ports', [])]
                            if t_port not in s_ports and t_port not in s_names:
                                results.append(AuditIssue(
                                    code="INGRESS_PORT_MISMATCH", severity=shield.CRITICAL,
                                    file=ing['file'],
                                    line=self.get_line(ing['raw_doc'], 'spec'),
                                    message=f"Ingress targets port {t_port}, Service '{s_name}' exposes {s_ports + s_names}.",
                                    fix=f"Update Ingress port to match one of: {s_ports + s_names}",
                                    source="Synapse"
                                ))

        # 3. VOLUME MOUNT CONSISTENCY
        for p in self.producers:
            for vol in p.get('volumes') or []:
                ref = None
                if 'configMap' in vol: ref = vol['configMap'].get('name')
                if 'secret' in vol: ref = vol['secret'].get('secretName')
                
                if ref and not any(c['name'] == ref and c['namespace'] == p['namespace'] for c in self.configs):
                    results.append(AuditIssue(
                        code="VOL_MISSING", severity=shield.MEDIUM, file=p['file'],
                        line=self.get_line(p['raw_doc'], 'spec'),
                        message=f"Workload '{p['name']}' mounts missing '{ref}'.",
                        fix="Define ConfigMap/Secret in same namespace.",
                        source="Synapse"
                    ))

        # 4. PROBE PORT INTEGRITY
        for p in self.producers:
            for probe in p.get('probes'):
                valid_ports = [str(x) for x in p['ports']]
                if probe['port'] and probe['port'] not in valid_ports:
                    results.append(AuditIssue(
                        code="PROBE_GAP", severity=shield.MEDIUM, file=p['file'],
                        line=self.get_line(p['raw_doc'], 'spec'),
                        message=f"Probe targets port '{probe['port']}' not in containerPorts.",
                        fix="Expose probe port in container 'ports' section.",
                        source="Synapse"
                    ))

        # 5. SERVICE -> WORKLOAD PORT ALIGNMENT
        
        for svc in self.consumers:
            for p in self.producers:
                if p['namespace'] == svc['namespace'] and svc['selector'].items() <= p['labels'].items():
                    for s_port in svc['ports']:
                        target = s_port.get('targetPort')
                        if target and str(target) not in p['ports']:
                            results.append(AuditIssue(
                                code="PORT_MISMATCH", severity=shield.MEDIUM, 
                                file=svc['file'],
                                line=self.get_line(svc['raw_doc'], 'spec'),
                                message=f"Service '{svc['name']}' targets port {target}, workload '{p['name']}' missing it.",
                                fix=f"Add port {target} to {p['kind']} containerPorts.",
                                source="Synapse"
                            ))

        return results
