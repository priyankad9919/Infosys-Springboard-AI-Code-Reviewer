# OWASP Top 10 Secure Coding Guidelines

## 1. SQL Injection (SQLi)
**Description:** SQL Injection occurs when untrusted user input is concatenated directly into a database query. This allows an attacker to manipulate the query, potentially reading, modifying, or deleting arbitrary data.

### Prevention in Python
Never use string formatting (`f-strings`, `.format()`, or `%`) to build SQL queries. Always use parameterized queries provided by the database driver.
**Insecure:** `cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")`
**Secure:** `cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))`

### Prevention in Java
Do not concatenate strings to build SQL. Use `PreparedStatement` to automatically escape inputs.
**Insecure:** `Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE username = '" + userInput + "'");`
**Secure:** `PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM users WHERE username = ?"); pstmt.setString(1, userInput); ResultSet rs = pstmt.executeQuery();`

## 2. Cross-Site Scripting (XSS)
**Description:** XSS vulnerabilities occur when an application includes untrusted data in a web page without proper validation or escaping. This allows attackers to execute malicious scripts in the victim's browser.

### Prevention Strategies
*   **Context-Aware Escaping:** Always escape user input before rendering it in HTML, JavaScript, CSS, or URLs.
*   **Use Framework Protections:** Modern frameworks like React, Angular, and Django templates automatically escape output by default.
*   **Content Security Policy (CSP):** Implement strict CSP headers to mitigate the impact of XSS flaws.

## 3. Hardcoded Secrets
**Description:** Storing sensitive information such as API keys, database passwords, or cryptographic keys directly in source code exposes them to anyone with access to the repository.

### Prevention Strategies
*   **Environment Variables:** Store secrets in environment variables (`os.environ.get('API_KEY')` in Python, `System.getenv("API_KEY")` in Java).
*   **Secrets Management:** Use dedicated secret vaults like AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.
*   **.env Files:** Use `.env` files for local development but ensure they are included in your `.gitignore` file to prevent committing them to version control.

## 4. Broken Access Control
**Description:** Failures in access control allow users to act outside of their intended permissions. This can lead to unauthorized information disclosure, modification, or destruction of data.

### Prevention Strategies
*   **Deny by Default:** Except for public resources, deny access by default.
*   **Principle of Least Privilege:** Ensure that users and service accounts are granted only the minimum permissions necessary to perform their tasks.
*   **Server-Side Checks:** Never rely on the client or UI to enforce access controls. Always verify permissions on the server using secure, centralized authorization modules.