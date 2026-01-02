# models.py
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class AuditIssue:
    engine: str        # Healer, Shield, Synapse
    code: str          # GHOST, PORT, API, etc.
    severity: str      # 🔴 HIGH, 🟠 MED, 🟡 LOW
    file: str
    message: str
    remediation: str
