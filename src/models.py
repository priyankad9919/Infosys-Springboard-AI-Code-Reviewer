from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum

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