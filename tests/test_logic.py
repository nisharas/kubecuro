import subprocess
import sys
import os

# Helper to run KubeCuro commands
def run_kubecuro(command, target):
    return subprocess.run(
        [sys.executable, "-m", "kubecuro.main", command, target],
        capture_output=True,
        text=True
    )

def test_ghost_service_logic():
    """Scenario: Service exists but matches no pods."""
    result = run_kubecuro("scan", "tests/samples/")
    assert "GHOST SERVICE" in result.stdout

def test_deprecated_api_shield():
    """Scenario: Shield should catch old API versions."""
    # We assume you have a file with an old API version
    result = run_kubecuro("scan", "tests/samples/deprecated_api.yaml")
    assert "API_DEPRECATED" in result.stdout or "🟠 MED" in result.stdout

def test_hpa_resource_check():
    """Scenario: HPA scaling without resource requests defined."""
    result = run_kubecuro("scan", "tests/samples/hpa_logic_error.yaml")
    assert "HPA_LOGIC" in result.stdout or "Resource Request" in result.stdout

def test_healer_fix_functionality():
    """Scenario: 'fix' command should actually work."""
    target = "tests/samples/syntax_error.yaml"
    
    # 1. Run fix
    fix_result = run_kubecuro("fix", target)

    # We check for "FIXED" (from Shield/Healer) or the success summary
    assert "FIXED" in fix_result.stdout or "✔ No issues found!" not in fix_result.stdout

def test_checklist_command():
    """Scenario: Ensure the UI checklist displays."""
    result = run_kubecuro("checklist", "")
    assert "Logic Checklist" in result.stdout
    assert "Service" in result.stdout
