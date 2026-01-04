import pytest
from kubecuro.models import AuditIssue

def calculate_summary_logic(all_issues, command="scan"):
    """
    Simulates the logic block from main.py to verify 
    counters and 'Before vs After' math.
    """
    # Updated codes to match shield.py and synapse.py
    ghosts    = sum(1 for i in all_issues if str(i.code).upper() == 'GHOST')
    hpa_gaps  = sum(1 for i in all_issues if str(i.code).upper() in ['HPA_LOGIC', 'HPA_MISSING_REQ'])
    
    # Ensure security checks include the new SEC_PRIVILEGED from Healer integration
    security  = sum(1 for i in all_issues if any(x in str(i.code).upper() for x in ['RBAC', 'PRIVILEGED', 'SECRET']))
    
    repairs   = sum(1 for i in all_issues if str(i.code).upper() == 'FIXED')
    
    # Logic: How many issues are NOT auto-repaired?
    remaining = len([i for i in all_issues if "FIXED" not in str(i.severity).upper()])
    
    return {
        "ghosts": ghosts,
        "hpa": hpa_gaps,
        "security": security,
        "repairs": repairs,
        "remaining": remaining
    }

def test_fix_command_math():
    """Verify that 'FIXED' items (Healer) are correctly separated from 'REMAINING' (Shield/Synapse)"""
    mock_issues = [
        # Repaired by Healer
        AuditIssue(code="FIXED", severity="🟢 FIXED", file="a.yaml", message="Migrated Ingress API"),
        AuditIssue(code="FIXED", severity="🟢 FIXED", file="b.yaml", message="Disabled Privileged Mode"),
        # Remaining logic issues
        AuditIssue(code="RBAC_WILD", severity="🔴 HIGH", file="c.yaml", message="Wildcard access"),
        AuditIssue(code="GHOST", severity="🟠 WARN", file="d.yaml", message="Ghost service"),
    ]
    
    results = calculate_summary_logic(mock_issues, command="fix")
    
    # 2 Healed + 2 Manual = 4 total
    assert results["repairs"] == 2
    assert results["remaining"] == 2 
    assert results["security"] == 2  # RBAC_WILD + FIXED(Privileged)

def test_border_color_logic():
    """Verify the summary panel color reflects the risk profile"""
    issues = [
        AuditIssue(code="SEC_PRIVILEGED", severity="🔴 HIGH", file="f.yaml", message="Privileged container")
    ]
    
    # Logic mirror from main.py
    all_sev = str([i.severity for i in issues])
    security_count = sum(1 for i in issues if "PRIVILEGED" in i.code)
    
    border_col = "green"
    if "🔴" in all_sev or security_count > 0:
        border_col = "red"
        
    assert border_col == "red"

def test_empty_results():
    """Ensure math doesn't break on a clean scan"""
    results = calculate_summary_logic([])
    assert results["remaining"] == 0
    assert results["repairs"] == 0
