import subprocess
import pytest

def test_ghost_service_detection():
    """
    Test that Kubecuro correctly identifies a 'Ghost Service' 
    (A Service with no matching Pod).
    """
    # We run the actual kubecuro command against our 'broken' sample
    result = subprocess.run(
        ["kubecuro", "check", "tests/samples/ghost_service_error.yaml"],
        capture_output=True,
        text=True
    )
    
    # We EXPECT to see the error message we defined in our Logic Library
    assert "SYN-001" in result.stdout
    assert "Ghost Service" in result.stdout

def test_healthy_connection():
    """
    Test that Kubecuro does NOT report errors for a 
    perfectly connected Service and Pod.
    """
    result = subprocess.run(
        ["kubecuro", "check", "tests/samples/valid_connection.yaml"],
        capture_output=True,
        text=True
    )
    
    # We expect NO error codes in the output
    assert "SYN-001" not in result.stdout
    assert "No logical gaps found" in result.stdout
