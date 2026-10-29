import ast
import javalang
from src.models import Finding

def run_code_analysis(code: str, language: str) -> list[Finding]:
    findings = []
    
    if language == "python":
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # Check for global variables or dangerous constructs like eval()
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'eval':
                    findings.append(Finding(
                        agent="Code Analysis",
                        category="Code Smell / Security Risk",
                        severity="High",
                        message="Use of built-in 'eval()' function detected, which poses a severe security and stability risk.",
                        line_number=node.lineno,
                        cwe="CWE-95",
                        owasp="A03:2025 Injection",
                        recommendation="Avoid eval(); use safer parsing alternatives like ast.literal_eval() or explicit logic."
                    ))
        except SyntaxError:
            pass # Handled by validator
            
    elif language == "java":
        try:
            tokens = javalang.tokenizer.tokenize(code)
            parser = javalang.parser.Parser(tokens)
            tree = parser.parse()
            
            # Example check for string comparisons using '==' instead of '.equals()'
            lines = code.splitlines()
            for idx, line in enumerate(lines, 1):
                if "==" in line and ("String" in line or "\"" in line):
                    findings.append(Finding(
                        agent="Code Analysis",
                        category="Code Smell",
                        severity="Medium",
                        message="String comparison using '==' operator instead of '.equals()'.",
                        line_number=idx,
                        cwe="CWE-476",
                        owasp="A10:2025 Mishandling of Exceptional Conditions",
                        recommendation="Use string.equals() to compare object contents rather than references."
                    ))
        except Exception:
            pass
            
    return findings