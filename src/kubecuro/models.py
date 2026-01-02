"""
--------------------------------------------------------------------------------
AUTHOR:      Nishar A Sunkesala / FixMyK8s
PURPOSE:     Standardized Data Models for KubeCuro Audit results.
--------------------------------------------------------------------------------
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class AuditIssue:
    engine: str           # Healer, Shield, or Synapse
    code: str             # e.g., GHOST, HPA_LOGIC, PROBE_GAP
    severity: str         # 🔴 HIGH, 🟠 MED, 🟡 LOW
    file: str             # The filename where the issue was detected
    message: str          # Clear description of the logical error
    remediation: str      # Actionable steps to fix the issue
    line_number: Optional[int] = None # Optional: specific line location

    def __post_init__(self):
        """Clean up engine names for consistent display."""
        self.engine = self.engine.capitalize()
