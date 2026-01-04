import subprocess
import sys
import os

def test_ghost_service_detection():
    # We use 'sys.executable' to make sure we use the EXACT same Python 
    # that just installed our updated requirements.
    result = subprocess.run(
        [sys.executable, "-m", "kubecuro.main", "scan", "tests/samples/ghost_service_error.yaml"],
        capture_output=True,
        text=True
    )
    
    # If the tool crashed (returncode 1), we want to see why in the test failure
    if result.returncode != 0 and "TypeError" in result.stderr:
        print(f"\nCRITICAL ERROR: {result.stderr}")

    assert "SYN-001" in result.stdout
    assert "Ghost Service" in result.stdout

def test_healthy_connection():
    result = subprocess.run(
        [sys.executable, "-m", "kubecuro.main", "scan", "tests/samples/valid_connection.yaml"],
        capture_output=True,
        text=True
    )
    assert "SYN-001" not in result.stdout
