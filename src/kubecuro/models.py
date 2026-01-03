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
    """
    Standardized object for all KubeCuro findings.
    Ensures consistent reporting across the UI and internal engines.
    """
    code: str             # Internal identifier (e.g., GHOST, HPA_LOGIC, PROBE_GAP)
    severity: str         # UI ready string: 🔴 HIGH, 🟠 MED, 🟢 FIXED
    file: str             # The filename where the issue was detected
    message: str          # Detailed description of the logical gap or fix
    fix: str              # Actionable remediation steps (referred to as remediation in logic)
    source: str           # The engine that generated the issue: Healer, Shield, or Synapse
    line_number: Optional[int] = None # Optional: specific line location for future deep-tracing

    def __post_init__(self):
        """
        Validation and cleanup for consistent UI rendering.
        Ensures sources are properly capitalized for the results table.
        """
        self.source = self.source.capitalize()
        
        # Mapping 'remediation' alias to 'fix' if needed for legacy logic compatibility
        if not hasattr(self, 'remediation'):
            self.remediation = self.fix

    def is_critical(self) -> bool:
        """Helper to identify blocking issues for CI/CD exit codes."""
        return "🔴" in self.severity

    def __str__(self):
        return f"[{self.severity}] {self.file}: {self.message}"
