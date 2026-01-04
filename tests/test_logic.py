import subprocess
import sys
import os
import shutil
import pytest

# Helper to run KubeCuro commands
def run_kubecuro(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    # Force Rich to output text even in non-interactive shells
    env["FORCE_COLOR"] = "1" 
    # Tell KubeCuro we are in a test env so it prints the "Clean" logs
    env["PYTEST_CURRENT_TEST"] = "true" 
    
    return subprocess.run(
        [sys.executable, "-m", "kubecuro.main", *args],
        capture_output=True,
        text=True
    )

def test_ghost_service_logic():
    """Scenario: Service exists but matches no pods."""
    # Ensure tests/samples/ actually exists or use a temp file
    result = run_kubecuro("scan", "tests/samples/")
    assert "GHOST" in result.stdout.upper()

def test_deprecated_api_shield():
    """Scenario: Shield should catch old API versions."""
    # Using the specific output format we defined in main.py for tests
    result = run_kubecuro("scan", "tests/samples/deprecated_api.yaml")
    output = result.stdout.upper()
    assert "API_DEPRECATED" in output

def test_hpa_resource_check():
    """Scenario: HPA scaling without resource requests defined."""
    result = run_kubecuro("scan", "tests/samples/hpa_logic_error.yaml")
    output = result.stdout.upper()
    assert "HPA_MISSING_REQ" in output

def test_healer_fix_functionality(tmp_path):
    """Scenario: 'fix' command should repair a file without destroying it."""
    # Create a temporary file so we don't modify the real sample
    src = "tests/samples/syntax_error.yaml"
    if not os.path.exists(src):
        pytest.skip("Sample syntax_error.yaml not found")
        
    temp_file = tmp_path / "fix_test.yaml"
    shutil.copy(src, temp_file)

    # Add the "-y" flag here to avoid the EOFError in CI
    fix_result = run_kubecuro("fix", str(temp_file), "-y")
    
    assert "FIXED" in fix_result.stdout.upper()
    # Verify file actually changed
    with open(temp_file, 'r') as f:
        content = f.read()
        assert "\t" not in content # Healer should have replaced tabs with spaces

def test_checklist_command():
    """Scenario: Ensure the UI checklist displays."""
    result = run_kubecuro("checklist")
    assert "Checklist" in result.stdout or "Logic" in result.stdout
