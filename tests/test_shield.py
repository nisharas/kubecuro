import pytest
from kubecuro.shield import Shield

@pytest.fixture
def shield_engine():
    return Shield()

def test_rbac_wildcard_detection(shield_engine):
    """Verify that global wildcards in RBAC are flagged as 🔴 HIGH"""
    bad_rbac = {
        "kind": "ClusterRole",
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "metadata": {"name": "star-lord"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
    }
    # Use the unified scan method
    findings = shield_engine.scan(bad_rbac)
    assert any(f['code'] == "RBAC_WILD" and f['severity'] == "🟠 HIGH" for f in findings)

def test_privileged_container_detection(shield_engine):
    """Verify that privileged containers are flagged"""
    bad_pod = {
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": {"name": "unsafe-pod"},
        "spec": {
            "containers": [{
                "name": "hacker-tool",
                "securityContext": {"privileged": True}
            }]
        }
    }
    findings = shield_engine.scan(bad_pod)
    assert any(f['code'] == "SEC_PRIVILEGED" for f in findings)

def test_hpa_missing_requests(shield_engine):
    """Verify HPA flags missing requests in the target deployment"""
    deployment = {
        "kind": "Deployment",
        "apiVersion": "apps/v1",
        "metadata": {"name": "web-deploy"},
        "spec": {"template": {"spec": {"containers": [{"name": "app", "resources": {}}]}}}
    }
    hpa = {
        "kind": "HorizontalPodAutoscaler",
        "apiVersion": "autoscaling/v2",
        "metadata": {"name": "web-hpa"},
        "spec": {
            "scaleTargetRef": {"name": "web-deploy", "kind": "Deployment"},
            "metrics": [{"type": "Resource", "resource": {"name": "cpu"}}]
        }
    }
    
    # Test the cross-resource linkage via the all_docs parameter
    findings = shield_engine.scan(hpa, all_docs=[deployment, hpa])
    assert any(f['code'] == "HPA_MISSING_REQ" for f in findings)

def test_api_deprecation_detection(shield_engine):
    """Verify that old API versions (used by Healer) are correctly flagged"""
    old_ingress = {
        "apiVersion": "networking.k8s.io/v1beta1",
        "kind": "Ingress",
        "metadata": {"name": "old-ingress"}
    }
    findings = shield_engine.scan(old_ingress)
    assert any(f['code'] == "API_DEPRECATED" for f in findings)
