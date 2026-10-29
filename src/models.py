from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

@dataclass
class Finding:
    agent: str                   # "Code Analysis" or "Security"
    category: str                # e.g., "Code Smell", "OWASP-A03: Injection"
    severity: str                # "High", "Medium", "Low"
    message: str                 # Description of the issue
    line_number: Optional[int]   # Line number where flaw occurs
    cwe: Optional[str] = None      # e.g., "CWE-798"
    owasp: Optional[str] = None    # e.g., "A07:2025 Authentication Failures"
    recommendation: Optional[str] = None # Remediation advice

class SupportedLanguage(str, Enum):
    PYTHON = "python"
    JAVA = "java"

class CodeSubmissionRequest(BaseModel):
    language: SupportedLanguage
    code: str

class ValidationResult(BaseModel):
    is_valid: bool
    language: str
    error_message: Optional[str] = None
    line_number: Optional[int] = None