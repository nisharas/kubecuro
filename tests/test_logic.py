import sys
import os
import shutil
import pytest
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr # Added redirect_stderr

# TRIPLE-CHECK: Inject src at the absolute highest priority
abs_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if abs_src not in sys.path:
    sys.path.insert(0, abs_src)

# DEBUG: Print exactly where 'rich' is coming from before we try to use it
try:
    import rich
    print(f"DEBUG: Rich loaded from {rich.__file__}")
except Exception as e:
    print(f"DEBUG: Rich failed to load: {e}")

# Now do your imports
from kubecuro.main import main 

def run_kubecuro(*args):
    """Execute KubeCuro main() and capture all output streams."""
    out = StringIO()
    err = StringIO()
    
    # Mock sys.argv
    sys.argv = ["kubecuro"] + list(args)
    
    try:
        # Capture both stdout AND stderr
        with redirect_stdout(out), redirect_stderr(err):
            main()
    except SystemExit:
        pass
    
    combined_output = out.getvalue() + err.getvalue()
    
    class MockResult:
        def __init__(self, stdout):
            self.stdout = stdout
            
    return MockResult(combined_output)

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
    output = result.stdout.upper()
    assert "CHECKLIST" in output or "LOGIC" in output
