# Vulnerable Test Application

This is a deliberately vulnerable Flask application for testing the CTI security pipeline.

## 🚨 Intentional Vulnerabilities

### 1. SQL Injection
- **Endpoint**: `/login`
- **Method**: POST
- **Vulnerability**: Direct string concatenation in SQL query
- **Payload**: `' OR '1'='1`

### 2. Cross-Site Scripting (XSS)
- **Endpoint**: `/search`
- **Method**: GET
- **Vulnerability**: Reflected XSS in query parameter
- **Payload**: `<script>alert('XSS')</script>`

### 3. Command Injection
- **Endpoint**: `/ping`
- **Method**: GET
- **Vulnerability**: Command injection in subprocess
- **Payload**: `127.0.0.1; ls`

### 4. Path Traversal
- **Endpoint**: `/file`
- **Method**: GET
- **Vulnerability**: Direct file path access
- **Payload**: `../../../etc/passwd`

### 5. Insecure Deserialization
- **Endpoint**: `/api/data`
- **Method**: GET
- **Vulnerability**: Unsafe pickle deserialization
- **Payload**: Base64-encoded pickle object

### 6. Information Disclosure
- **Endpoint**: `/debug`
- **Method**: GET
- **Vulnerability**: Debug information exposure
- **Data**: Server info, headers, environment

## 🎯 Expected Security Findings

When running the CTI pipeline, you should expect:

- **P1 Scanner**: Multiple vulnerabilities detected
- **P2 Enrichment**: CVEs mapped to real vulnerabilities
- **P3 Decision**: Critical decisions for high-severity findings
- **P4 Dashboard**: Visual representation of security posture

## 🚀 Running the Application

```bash
cd target_app
pip install -r requirements.txt
python vulnerable_app.py
```

Access at: http://localhost:5000

## 📋 Testing the Pipeline

1. Start the vulnerable app
2. Run the CTI pipeline
3. Monitor the dashboard for results
4. Verify AI decisions and recommendations

## ⚠️ For Testing Only

This application contains intentional security vulnerabilities and should **NEVER** be deployed to production environments.
