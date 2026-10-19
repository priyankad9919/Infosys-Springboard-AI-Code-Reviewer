import ast
import javalang
from src.models import ValidationResult

def detect_and_validate(code: str) -> ValidationResult:
    if not code.strip():
        return ValidationResult(is_valid=False, language="unknown", error_message="Source code cannot be empty.")

    # Attempt Python validation
    try:
        ast.parse(code)
        return ValidationResult(is_valid=True, language="python")
    except SyntaxError as py_err:
        python_error = py_err

    # Attempt Java validation
    try:
        tokens = javalang.tokenizer.tokenize(code)
        parser = javalang.parser.Parser(tokens)
        parser.parse()
        return ValidationResult(is_valid=True, language="java")
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as java_err:
        java_error = java_err

    # If both fail, guess the intended language to provide the correct error message
    java_keywords = ["public class", "public static void main", "import java", "System.out.println"]
    if any(keyword in code for keyword in java_keywords):
        line_no = getattr(java_error, 'at', None)
        line_number = None
        if line_no:
            if hasattr(line_no, 'line'):
                line_number = line_no.line
            elif hasattr(line_no, 'position') and line_no.position:
                line_number = getattr(line_no.position, 'line', None)
            elif hasattr(line_no, 'lineno'):
                line_number = line_no.lineno
        return ValidationResult(
            is_valid=False,
            language="java",
            error_message=f"Java Syntax Error: {str(java_error)}",
            line_number=line_number
        )
    else:
        return ValidationResult(
            is_valid=False,
            language="python",
            error_message=f"Python Syntax Error: {python_error.msg}",
            line_number=python_error.lineno
        )
