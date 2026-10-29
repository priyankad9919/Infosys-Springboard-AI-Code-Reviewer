import re
import ast
import javalang
from src.models import Finding
from src.rag_engine import query_knowledge_base

def run_security_scan(code: str, language: str) -> list[Finding]:
    findings = []
    lines = code.splitlines()

    # --- 1. Universal Keyword / Regex Checks (Covers both Python & Java) ---
    for idx, line in enumerate(lines, 1):
        # Hardcoded Secrets & Tokens (CWE-798 / OWASP A07)
        if re.search(r"(password|secret|api_key|jwt_secret|TOKEN|KEY)\s*=\s*['\"].*?['\"]", line, re.IGNORECASE):
            rag_docs = query_knowledge_base("Hardcoded secrets API key JWT", k=1)
            remediation = rag_docs[0].page_content if rag_docs else "Use secure configuration stores or environment variables."
            findings.append(Finding(
                agent="Security",
                category="OWASP-A07: Authentication Failures",
                severity="High",
                message="Hardcoded sensitive credential or secret detected in source code.",
                line_number=idx,
                cwe="CWE-798",
                owasp="A07:2025 Authentication Failures",
                recommendation=remediation[:300] + "..."
            ))

        # SQL Injection (CWE-89 / OWASP A03) - catches f-strings, concatenation, or format statements with SQL keywords
        # Robust SQL Injection check (Catches f-strings, concatenation, format strings, and SQL keywords)
        if any(sql_kw in line.upper() for sql_kw in ["SELECT ", "INSERT ", "UPDATE ", "DELETE "]) and any(marker in line for marker in ["f\"", "f'", "+", "%", ".format"]):
            findings.append(Finding(
                agent="Security",
                category="OWASP-A03: Injection",
                severity="High",
                message="Potential SQL Injection vulnerability via string formatting or concatenation.",
                line_number=idx,
                cwe="CWE-89",
                owasp="A03:2025 Injection",
                recommendation="Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE username = ?', (username,))) instead of string interpolation."
            ))

        # Command Injection / Unsafe Shell Execution (CWE-78)
        if any(term in line for term in ["subprocess", "shell=True", "os.system", "Runtime.getRuntime().exec"]):
            findings.append(Finding(
                agent="Security",
                category="OWASP-A03: Injection",
                severity="High",
                message="Potential Command Injection or insecure shell execution detected.",
                line_number=idx,
                cwe="CWE-78",
                owasp="A03:2025 Injection",
                recommendation="Avoid shell=True, validate inputs strictly, and pass arguments as structured arrays."
            ))

        # Weak Cryptography & Insecure Cipher Modes (CWE-328 / CWE-327)
        if any(weak in line for weak in ["MD5", "SHA-1", "AES/ECB", "DES"]):
            findings.append(Finding(
                agent="Security",
                category="OWASP-A04: Cryptographic Failures",
                severity="Medium",
                message="Weak cryptographic hash algorithm or insecure block cipher mode (e.g., ECB/SHA-1) detected.",
                line_number=idx,
                cwe="CWE-328",
                owasp="A04:2025 Cryptographic Failures",
                recommendation="Use strong cryptographic standards like SHA-256/SHA-3 and secure cipher modes like AES/GCM."
            ))

        # Java String Comparison using '==' instead of '.equals()' (CWE-476 / Code Smell)
        if language == "java" and "==" in line and ("String" in line or "\"" in line or "token" in line or "secret" in line):
            findings.append(Finding(
                agent="Code Analysis",
                category="Code Smell / Bug",
                severity="High",
                message="String comparison using '==' operator instead of '.equals()'.",
                line_number=idx,
                cwe="CWE-476",
                owasp="A10:2025 Mishandling of Exceptional Conditions",
                recommendation="Use .equals() to compare object contents rather than memory references."
            ))

    # --- 2. Python AST Deep Semantic Checks ---
    if language == "python":
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # Detect eval() or exec() usage (CWE-95)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
                    findings.append(Finding(
                        agent="Code Analysis",
                        category="Code Smell / Security Risk",
                        severity="High",
                        message=f"Use of built-in '{node.func.id}()' function detected, posing severe security risks.",
                        line_number=node.lineno,
                        cwe="CWE-95",
                        owasp="A03:2025 Injection",
                        recommendation="Avoid eval/exec completely; use ast.literal_eval() or explicit parsing logic."
                    ))
        except SyntaxError:
            pass

    return findings