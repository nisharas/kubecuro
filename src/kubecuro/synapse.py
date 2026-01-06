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
        """Initializes the correlation engine with Round-Trip YAML support."""
        # Using 'rt' is non-negotiable for line-number accuracy in Shield
        self.yaml = YAML(typ='rt')
        self.yaml.preserve_quotes = True
        self.yaml.allow_duplicate_keys = True
        
        # Resource Registry
        self.all_docs = []       # Global registry for Shield
        self.producers = []      # Deployments, Pods, StatefulSets, DaemonSets
        self.workload_docs = []  # Specific doc objects for HPA/Shield audits
        self.consumers = []      # Services
        self.ingresses = []      # Ingress objects
        self.configs = []        # ConfigMaps and Secrets
        self.hpas = []           # HorizontalPodAutoscalers
        self.netpols = []        # NetworkPolicies

    def scan_file(self, file_path: str):
        """
        Deep-scans a YAML file, extracting metadata and preserving 
        document references for multi-resource correlation.
        """
        try:
            fname = os.path.basename(file_path)
            if not os.path.exists(file_path):
                return

            with open(file_path, 'r') as f:
                content = f.read()
                if not content.strip():
                    return
                
                # load_all handles multi-document YAML files (---)
                docs = list(self.yaml.load_all(content))
            
            for doc in docs:
                if not doc or not isinstance(doc, dict) or 'kind' not in doc:
                    continue
                
                # Tag origin for reporting
                doc['_origin_file'] = fname
                self.all_docs.append(doc)
                
                kind = doc['kind']
                metadata = doc.get('metadata', {})
                name = metadata.get('name', 'unknown')
                ns = metadata.get('namespace', 'default')
                spec = doc.get('spec', {}) or {}

                # --- 1. Workload Processing (The "Producers") ---
                if kind in ['Deployment', 'Pod', 'StatefulSet', 'DaemonSet']:
                    self.workload_docs.append(doc)
                    
                    # Resolve Pod Template
                    is_pod = kind == 'Pod'
                    template = spec.get('template', {}) if not is_pod else doc
                    t_metadata = template.get('metadata', {})
                    labels = t_metadata.get('labels') or {}
                    
                    p_spec = template.get('spec', {}) if not is_pod else spec
                    containers = p_spec.get('containers') or []
                    
                    # Extract Ports, Probes, and Volumes
                    c_ports = []
                    probes = []
                    for c in containers:
                        # Extract container ports (numeric and named)
                        for p in c.get('ports') or []:
                            if p.get('containerPort'):
                                c_ports.append(p.get('containerPort'))
                            if p.get('name'):
                                c_ports.append(p.get('name'))
                        
                        # Extract probes for connectivity validation
                        for p_type in ['livenessProbe', 'readinessProbe', 'startupProbe']:
                            p_data = c.get(p_type)
                            if p_data and 'httpGet' in p_data:
                                probes.append({
                                    'type': p_type, 
                                    'port': p_data['httpGet'].get('port'),
                                    'path': p_data['httpGet'].get('path')
                                })

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

                # --- 2. Service Processing (The "Consumers") ---
                elif kind == 'Service':
                    self.consumers.append({
                        'name': name,
                        'namespace': ns,
                        'file': fname,
                        'selector': spec.get('selector') or {},
                        'ports': spec.get('ports') or [],
                        'type': spec.get('type', 'ClusterIP'),
                        'raw_doc': doc
                    })

                # --- 3. Connectivity & Logic Resources ---
                elif kind == 'Ingress':
                    self.ingresses.append({
                        'name': name, 
                        'namespace': ns, 
                        'file': fname, 
                        'spec': spec, 
                        'raw_doc': doc
                    })
                elif kind == 'HorizontalPodAutoscaler':
                    self.hpas.append({
                        'name': name, 
                        'namespace': ns,
                        'file': fname, 
                        'doc': doc
                    })
                elif kind in ['ConfigMap', 'Secret']:
                    self.configs.append({
                        'name': name, 
                        'kind': kind, 
                        'namespace': ns, 
                        'file': fname
                    })
                elif kind == 'NetworkPolicy':
                    self.netpols.append({
                        'name': name, 
                        'namespace': ns,
                        'file': fname, 
                        'selector': spec.get('podSelector', {}).get('matchLabels') or {}
                    })

        except Exception:
            # Silent fail for individual file parsing to prevent whole-scan crashes
            pass

    def audit(self) -> List[AuditIssue]:
        """Runs the complete correlation suite across the gathered manifest graph."""
        from .shield import Shield
        results = []
        shield = Shield()

        # --- AUDIT: Service -> Pod Mapping (GHOST Detection) ---
        for svc in self.consumers:
            selector = svc.get('selector')
            if not selector:
                continue
            
            # Match pods in same namespace where labels satisfy selector
            matches = [
                p for p in self.producers 
                if p['namespace'] == svc['namespace'] and 
                selector.items() <= p['labels'].items()
            ]
            
            if not matches:
                results.append(AuditIssue(
                    code="GHOST", severity="🔴 HIGH", file=svc['file'], 
                    line=shield.get_line(svc['raw_doc'], 'selector'),
                    message=f"GHOST SERVICE: Service '{svc['name']}' selector matches 0 pods.",
                    fix="Align Service 'spec.selector' with Deployment 'spec.template.metadata.labels'.",
                    source="Synapse"
                ))

        # --- AUDIT: Ingress -> Service Backend Validation ---
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
                        match = next((s for s in self.consumers if s['name'] == s_name and s['namespace'] == ing['namespace']), None)
                        if not match:
                            results.append(AuditIssue(
                                code="INGRESS_ORPHAN", severity="🔴 HIGH", file=ing['file'],
                                line=shield.get_line(path),
                                message=f"Ingress backend references missing Service '{s_name}'.",
                                fix="Ensure the Service exists in the same namespace as the Ingress.",
                                source="Synapse"
                            ))
                        elif t_port:
                            s_ports = [p.get('port') for p in match.get('ports', [])]
                            if t_port not in s_ports:
                                results.append(AuditIssue(
                                    code="INGRESS_PORT_MISMATCH", severity="🔴 CRITICAL", file=ing['file'],
                                    line=shield.get_line(path),
                                    message=f"Ingress targets port {t_port}, but Service '{s_name}' only exposes {s_ports}.",
                                    fix=f"Update Ingress port to match one of: {s_ports}.",
                                    source="Synapse"
                                ))

        # --- AUDIT: Volume Mount Consistency (Missing Configs/Secrets) ---
        for p in self.producers:
            for vol in p.get('volumes') or []:
                ref = None
                if 'configMap' in vol: ref = vol['configMap'].get('name')
                if 'secret' in vol: ref = vol['secret'].get('secretName')
                
                if ref:
                    if not any(c['name'] == ref and c['namespace'] == p['namespace'] for c in self.configs):
                        results.append(AuditIssue(
                            code="VOL_MISSING", severity="🟠 MED", file=p['file'],
                            line=shield.get_line(p['raw_doc'], 'spec'),
                            message=f"Workload '{p['name']}' mounts missing resource '{ref}'.",
                            fix="Check if the ConfigMap/Secret is defined in the same namespace.",
                            source="Synapse"
                        ))

        # --- AUDIT: HPA Resource Validation (Piped to Shield) ---
        for hpa in self.hpas:
            hpa_errors = shield.audit_hpa(hpa['doc'], self.workload_docs)
            for err in hpa_errors:
                results.append(AuditIssue(
                    code=err['code'], severity=err['severity'], file=hpa['file'],
                    message=err['msg'], line=err.get('line'),
                    fix="HPAs require target workloads to have explicit CPU/Memory 'requests'.",
                    source="Shield"
                ))

        # --- AUDIT: Probe Port Integrity ---
        for p in self.producers:
            for probe in p.get('probes'):
                valid_ports = [str(x) for x in p['ports']]
                if probe['port'] and str(probe['port']) not in valid_ports:
                    results.append(AuditIssue(
                        code="PROBE_GAP", severity="🟠 MED", file=p['file'],
                        line=shield.get_line(p['raw_doc'], 'spec'),
                        message=f"Health probe targets port '{probe['port']}', which is not in containerPorts.",
                        fix="Expose the probe port in the 'ports' section of the container.",
                        source="Synapse"
                    ))

        # --- AUDIT: Service -> Workload Port Alignment ---
        for svc in self.consumers:
            for p in self.producers:
                if p['namespace'] == svc['namespace'] and svc['selector'].items() <= p['labels'].items():
                    for s_port in svc['ports']:
                        target = s_port.get('targetPort')
                        if target and str(target) not in [str(x) for x in p['ports']]:
                            results.append(AuditIssue(
                                code="PORT_MISMATCH", severity="🟠 MED", file=svc['file'],
                                line=shield.get_line(svc['raw_doc'], 'spec'),
                                message=f"Service '{svc['name']}' targets port {target}, but workload '{p['name']}' doesn't expose it.",
                                fix=f"Ensure port {target} is listed in {p['kind']} containerPorts.",
                                source="Synapse"
                            ))

        return results
