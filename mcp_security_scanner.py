import os
import re
import tempfile
import subprocess
import shutil
import json
from typing import List, Dict, Any, Set, Optional, Tuple
import git
import importlib.metadata
import pkg_resources
import yaml
from packaging import version

class MCPSecurityScanner:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.findings = []
        self.category_scores = {
            "authentication": 0,
            "data_protection": 0,
            "input_validation": 0,
            "prompt_security": 0,
            "infrastructure": 0
        }
        # Common vulnerability patterns - expand as needed
        self.vuln_patterns = {
            "ssrf": [
                r"requests\.get\s*\(\s*.*\)",
                r"urllib\.request\.urlopen\s*\(\s*.*\)",
                r"http\.client\.HTTPConnection\s*\(\s*.*\)"
            ],
            "rce": [
                r"eval\s*\(\s*.*\)",
                r"exec\s*\(\s*.*\)",
                r"subprocess\.(?:call|run|Popen)\s*\(\s*.*(?:shell\s*=\s*True|.*\+.*\))",
                r"os\.system\s*\(\s*.*\)",
                r"os\.popen\s*\(\s*.*\)"
            ],
            "sqli": [
                r"execute\s*\(\s*.*\+.*\)",
                r"execute\s*\(\s*f['\"].*\{.*\}.*['\"]",
                r"cursor\.execute\s*\(\s*['\"].*\%.*['\"].*\)",
            ],
            "prompt_injection": [
                r"prompt\s*=\s*f['\"].*\{.*\}.*['\"]",
                r"prompt\s*\+=\s*user_input",
                r"system_prompt\s*=\s*.*user",
            ],
            "keys_and_secrets": [
                r"api[_-]?key\s*=\s*['\"][\w\-]+['\"]",
                r"password\s*=\s*['\"][\w\-]+['\"]",
                r"secret\s*=\s*['\"][\w\-]+['\"]",
                r"token\s*=\s*['\"][\w\-]+['\"]",
                r"auth\s*=\s*['\"][\w\-]+['\"]"
            ]
        }
        # Known vulnerable dependency versions
        self.known_vulnerable_deps = {
            "flask": "2.2.0",  # Example: versions below this have vulnerabilities
            "django": "3.2.0",
            "fastapi": "0.80.0",
            "requests": "2.25.0",
            "pyyaml": "5.4",
            "cryptography": "3.3.2",
            "openai": "0.27.0",
            "anthropic": "0.3.0",
            "langchain": "0.0.200"
        }
        
    def scan(self) -> Dict[str, Any]:
        """Run all security validations on the MCP server implementation"""
        self.check_authentication_mechanisms()
        self.check_authorization_controls()
        self.check_multi_tenancy()
        self.check_data_at_rest()
        self.check_data_in_transit()
        self.check_sensitive_data_handling()
        self.check_request_validation()
        self.check_error_handling()
        self.check_prompt_injection_safeguards()
        self.check_content_filtering()
        self.check_rate_limiting()
        self.check_logging_security()
        self.check_dependency_security()
        self.check_configuration_security()
        
        # Add code snippets to findings
        for finding in self.findings:
            if finding['file'] != 'N/A':
                finding['code_snippet'] = self._extract_code_snippet(finding['file'], finding.get('line_number'))
        
        # Calculate overall scores
        self._calculate_scores()
        
        # Determine certification level
        certification = self._determine_certification_level()
        
        # Prepare the final report
        report = {
            "metadata": {
                "repository": self.repo_path,
                "scan_date": self._get_current_date(),
                "certification_level": certification["level"],
                "certification_details": certification["details"]
            },
            "scores": {
                "overall": self._calculate_overall_score(),
                "authentication": self.category_scores["authentication"],
                "data_protection": self.category_scores["data_protection"],
                "input_validation": self.category_scores["input_validation"],
                "prompt_security": self.category_scores["prompt_security"],
                "infrastructure": self.category_scores["infrastructure"]
            },
            "findings_summary": {
                "total": len(self.findings),
                "critical": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
                "high": len([f for f in self.findings if f["severity"] == "HIGH"]),
                "medium": len([f for f in self.findings if f["severity"] == "MEDIUM"]),
                "low": len([f for f in self.findings if f["severity"] == "LOW"]),
                "info": len([f for f in self.findings if f["severity"] == "INFO"])
            },
            "findings": self.findings,
            "grouped_findings": self._group_findings_by_severity(),
            "strengths": self._identify_strengths(),
            "weaknesses": self._identify_weaknesses()
        }
        
        return report
    
    def _extract_code_snippet(self, file_path, line_number=None, context_lines=5):
        """
        Extract a code snippet from a file with context lines around the issue.
        
        Args:
            file_path: Path to the file
            line_number: Line number of the issue (if known)
            context_lines: Number of lines to include before and after
            
        Returns:
            String containing the code snippet
        """
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                
            if line_number and 1 <= line_number <= len(lines):
                start = max(0, line_number - context_lines - 1)
                end = min(len(lines), line_number + context_lines)
                relevant_lines = lines[start:end]
                return ''.join(relevant_lines)
            else:
                # If no line number or invalid, return a portion of the file
                if len(lines) <= context_lines * 2:
                    return ''.join(lines)
                else:
                    return ''.join(lines[:context_lines * 2])
        except Exception as e:
            return f"Error extracting code snippet: {str(e)}"
    
    def _calculate_scores(self):
        """Calculate security scores for each category based on findings"""
        # Initialize base scores (starting from 10 and deducting based on findings)
        for category in self.category_scores:
            self.category_scores[category] = 10
        
        # Deduct points based on findings severity and category
        for finding in self.findings:
            category = finding.get("category", "").lower()
            severity = finding.get("severity", "")
            
            # Map finding categories to our scoring categories
            score_category = None
            if category in ["authentication", "authorization", "access control"]:
                score_category = "authentication"
            elif category in ["data persistence", "encryption", "data protection"]:
                score_category = "data_protection"
            elif category in ["data validation", "api security", "input validation"]:
                score_category = "input_validation"
            elif category in ["prompt injection", "content security"]:
                score_category = "prompt_security"
            elif category in ["rate limiting", "logging", "dependencies", "configuration"]:
                score_category = "infrastructure"
            
            # Deduct points based on severity
            if score_category and score_category in self.category_scores:
                if severity == "CRITICAL":
                    self.category_scores[score_category] -= 4
                elif severity == "HIGH":
                    self.category_scores[score_category] -= 2
                elif severity == "MEDIUM":
                    self.category_scores[score_category] -= 1
                elif severity == "LOW":
                    self.category_scores[score_category] -= 0.5
            
        # Ensure no negative scores
        for category in self.category_scores:
            self.category_scores[category] = max(1, self.category_scores[category])
            # Round to nearest 0.5
            self.category_scores[category] = round(self.category_scores[category] * 2) / 2
    
    def _calculate_overall_score(self):
        """Calculate overall security score based on category scores"""
        # Weighted average of category scores
        weights = {
            "authentication": 0.25,
            "data_protection": 0.2,
            "input_validation": 0.2,
            "prompt_security": 0.2,
            "infrastructure": 0.15
        }
        
        overall_score = sum(self.category_scores[cat] * weights[cat] for cat in weights)
        return round(overall_score * 2) / 2  # Round to nearest 0.5
    
    def _determine_certification_level(self):
        """Determine certification level based on findings and scores"""
        critical_count = len([f for f in self.findings if f["severity"] == "CRITICAL"])
        high_count = len([f for f in self.findings if f["severity"] == "HIGH"])
        medium_count = len([f for f in self.findings if f["severity"] == "MEDIUM"])
        overall_score = self._calculate_overall_score()
        
        # Check for Bronze certification
        has_auth = any(self._find_files_with_pattern(r"auth|authenticate|security"))
        has_input_validation = any(self._find_files_with_pattern(r"validate|schema|check"))
        has_https = any(self._find_files_with_pattern(r"https|ssl|tls"))
        has_rate_limiting = any(self._find_files_with_pattern(r"rate_limit|throttle|limiter"))
        
        # Default to no certification
        level = "None"
        details = "Does not meet minimum certification requirements"
        
        # Bronze requirements
        if critical_count == 0 and has_auth and has_input_validation and has_https and not self._has_hardcoded_secrets():
            level = "Bronze"
            details = "Meets basic security requirements"
            
            # Silver requirements
            if high_count == 0 and overall_score >= 7.0 and self._has_strong_auth() and self._has_proper_error_handling():
                level = "Silver"
                details = "Implements recommended security practices"
                
                # Gold requirements
                if medium_count == 0 and overall_score >= 8.5 and self._has_rbac() and self._has_encryption_at_rest():
                    level = "Gold"
                    details = "Follows security best practices with no critical/high/medium vulnerabilities"
        
        return {
            "level": level,
            "details": details
        }
    
    def _has_hardcoded_secrets(self):
        """Check if the codebase has hardcoded secrets"""
        for finding in self.findings:
            if finding["category"] == "Secrets Management" and "hardcoded" in finding["description"].lower():
                return True
        return False
    
    def _has_strong_auth(self):
        """Check if the codebase has strong authentication"""
        strong_auth_patterns = [r"oauth", r"jwt", r"token.*verify", r"password.*hash"]
        for pattern in strong_auth_patterns:
            if any(self._find_files_with_pattern(pattern)):
                return True
        return False
    
    def _has_proper_error_handling(self):
        """Check if the codebase has proper error handling"""
        # Count error handling findings
        error_findings = [f for f in self.findings if "error handling" in f["category"].lower()]
        # If there are no or few low-severity error handling findings, consider it good
        return len(error_findings) <= 2 and not any(f["severity"] in ["CRITICAL", "HIGH"] for f in error_findings)
    
    def _has_rbac(self):
        """Check if the codebase has role-based access control"""
        rbac_patterns = [r"role.*based", r"rbac", r"permission.*check", r"access.*control"]
        for pattern in rbac_patterns:
            if any(self._find_files_with_pattern(pattern)):
                return True
        return False
    
    def _has_encryption_at_rest(self):
        """Check if the codebase has encryption at rest"""
        encryption_patterns = [r"encrypt.*data", r"data.*encrypt", r"cipher", r"aes", r"cryptography"]
        for pattern in encryption_patterns:
            if any(self._find_files_with_pattern(pattern)):
                return True
        return False
    
    def _group_findings_by_severity(self):
        """Group findings by severity for easier review"""
        grouped = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }
        
        for finding in self.findings:
            severity = finding.get("severity", "INFO")
            if severity in grouped:
                grouped[severity].append(finding)
        
        return grouped
    
    def _identify_strengths(self):
        """Identify security strengths based on findings and code patterns"""
        strengths = []
        
        # Check for authentication
        if any(self._find_files_with_pattern(r"auth|authenticate|security")) and not any(f["severity"] in ["CRITICAL", "HIGH"] and "Authentication" in f["category"] for f in self.findings):
            strengths.append("Authentication mechanisms implemented")
        
        # Check for HTTPS
        if any(self._find_files_with_pattern(r"https|ssl|tls")):
            strengths.append("HTTPS/TLS implemented for data in transit")
        
        # Check for input validation
        if any(self._find_files_with_pattern(r"validate|schema|check")):
            strengths.append("Input validation mechanisms present")
        
        # Check for rate limiting
        if any(self._find_files_with_pattern(r"rate_limit|throttle|limiter")):
            strengths.append("Rate limiting implemented")
        
        # Check for proper error handling
        if any(self._find_files_with_pattern(r"try|except|error")) and not any(f["severity"] in ["CRITICAL", "HIGH"] and "Error Handling" in f["category"] for f in self.findings):
            strengths.append("Error handling implemented")
        
        # Check for logging
        if any(self._find_files_with_pattern(r"log\.|logger|logging")):
            strengths.append("Logging mechanisms implemented")
        
        return strengths
    
    def _identify_weaknesses(self):
        """Identify security weaknesses based on findings"""
        weaknesses = []
        
        # Group findings by category
        category_findings = {}
        for finding in self.findings:
            category = finding.get("category", "Other")
            if category not in category_findings:
                category_findings[category] = []
            category_findings[category].append(finding)
        
        # Identify categories with multiple issues
        for category, findings in category_findings.items():
            critical_high = [f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]
            if len(critical_high) >= 2:
                weaknesses.append(f"Multiple high-severity issues in {category}")
            elif len(findings) >= 3:
                weaknesses.append(f"Multiple issues in {category}")
        
        # Check for specific weaknesses
        if not any(self._find_files_with_pattern(r"auth|authenticate|security")):
            weaknesses.append("No authentication mechanisms detected")
        
        if not any(self._find_files_with_pattern(r"validate|schema|check")):
            weaknesses.append("Limited input validation")
        
        if not any(self._find_files_with_pattern(r"https|ssl|tls")):
            weaknesses.append("No HTTPS/TLS implementation detected")
        
        if not any(self._find_files_with_pattern(r"rate_limit|throttle|limiter")):
            weaknesses.append("No rate limiting mechanisms detected")
        
        return weaknesses
    
    def _get_current_date(self):
        """Get current date in YYYY-MM-DD format"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")
    
    def check_authentication_mechanisms(self):
        """Check if proper authentication is implemented for MCP endpoints"""
        # Look for authentication mechanisms in the codebase
        auth_files = self._find_files_with_pattern(r"auth|authenticate|security")
        
        if not auth_files:
            self.findings.append({
                "severity": "HIGH",
                "file": "N/A",
                "category": "Authentication",
                "description": "No authentication mechanisms detected for MCP endpoints",
                "recommendation": "Implement proper authentication using industry-standard libraries like JWT, OAuth, or API keys"
            })
        
        # Check for API keys or token validation
        for file_path in self._find_python_files():
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    if re.search(r"@app\.(?:get|post|put|delete)", content) and not re.search(r"api_key|token|auth|authenticate", content):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "file": file_path,
                            "category": "Authentication",
                            "description": "MCP endpoint may lack authentication checks",
                            "recommendation": "Add authentication middleware or decorators to protect API endpoints"
                        })
                    
                    # Check for weak authentication methods
                    if re.search(r"basic_auth|http_basic_auth", content, re.IGNORECASE):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "file": file_path,
                            "category": "Authentication",
                            "description": "Basic HTTP authentication detected, which transmits credentials with base64 encoding only",
                            "recommendation": "Use more secure authentication methods like JWT or OAuth over HTTPS"
                        })
                except UnicodeDecodeError:
                    # Skip binary files
                    pass
    
    def check_authorization_controls(self):
        """Check for proper authorization controls"""
        auth_files = self._find_files_with_pattern(r"auth|rbac|role|permission|access")
        
        # Check for role-based access control
        has_rbac = False
        for file_path in auth_files:
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    if re.search(r"role|permission|rbac", content, re.IGNORECASE):
                        has_rbac = True
                        break
                except UnicodeDecodeError:
                    pass
        
        if not has_rbac and auth_files:
            self.findings.append({
                "severity": "MEDIUM",
                "file": auth_files[0] if auth_files else "N/A",
                "category": "Authorization",
                "description": "No role-based access control detected",
                "recommendation": "Implement RBAC to provide granular control over permissions"
            })
        
        # Check for authorization checks in endpoints
        for file_path in self._find_files_with_pattern(r"@app\.(?:get|post|put|delete)"):
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    if re.search(r"@app\.(?:get|post|put|delete)", content) and not re.search(r"authorize|permission|can_|allowed_to|has_permission", content, re.IGNORECASE):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "file": file_path,
                            "category": "Authorization",
                            "description": "Endpoint may lack authorization checks",
                            "recommendation": "Add authorization checks to ensure users can only access resources they're permitted to"
                        })
                except UnicodeDecodeError:
                    pass
    
    def check_multi_tenancy(self):
        """Check for proper multi-tenant isolation"""
        tenant_files = self._find_files_with_pattern(r"tenant|organization|customer|client")
        
        if tenant_files:
            for file_path in tenant_files:
                with open(file_path, 'r') as f:
                    try:
                        content = f.read()
                        # Check for tenant ID in queries/filters
                        if re.search(r"query|filter|where|find", content) and not re.search(r"tenant_id|org_id|customer_id|client_id", content):
                            self.findings.append({
                                "severity": "HIGH",
                                "file": file_path,
                                "category": "Multi-tenancy",
                                "description": "Multi-tenant system may lack proper tenant isolation in queries",
                                "recommendation": "Ensure all database queries filter by tenant ID to prevent data leakage between tenants"
                            })
                    except UnicodeDecodeError:
                        pass
    
    def check_data_at_rest(self):
        """Check for proper encryption of data at rest"""
        storage_files = self._find_files_with_pattern(r"save|store|database|db|persist")
        
        has_encryption = False
        for file_path in storage_files:
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    if re.search(r"encrypt|cipher|aes|cryptography", content, re.IGNORECASE):
                        has_encryption = True
                        break
                except UnicodeDecodeError:
                    pass
        
        if storage_files and not has_encryption:
            self.findings.append({
                "severity": "MEDIUM",
                "file": storage_files[0] if storage_files else "N/A",
                "category": "Data Protection",
                "description": "No encryption detected for data at rest",
                "recommendation": "Implement encryption for sensitive data stored in databases or files"
            })
    
    def check_data_in_transit(self):
        """Check for proper encryption of data in transit"""
        config_files = []
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file in ["app.py", "main.py", "server.py", "settings.py", "config.py"]:
                    config_files.append(os.path.join(root, file))
        
        has_https = False
        for file_path in config_files:
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    if re.search(r"https|ssl|tls|ssl_context", content, re.IGNORECASE):
                        has_https = True
                        break
                except UnicodeDecodeError:
                    pass
        
        if config_files and not has_https:
            self.findings.append({
                "severity": "HIGH",
                "file": config_files[0] if config_files else "N/A",
                "category": "Data Protection",
                "description": "No HTTPS/TLS implementation detected for data in transit",
                "recommendation": "Configure the application to use HTTPS and redirect HTTP to HTTPS"
            })
        
        # Check for insecure SSL/TLS configurations
        for file_path in config_files:
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    if re.search(r"ssl_context|SSL|TLS", content) and re.search(r"SSLv2|SSLv3|TLSv1\.0|TLSv1\.1", content):
                        self.findings.append({
                            "severity": "HIGH",
                            "file": file_path,
                            "category": "Data Protection",
                            "description": "Insecure SSL/TLS protocol versions may be allowed",
                            "recommendation": "Use only TLSv1.2+ and disable older protocols"
                        })
                except UnicodeDecodeError:
                    pass
    
    def check_sensitive_data_handling(self):
        """Check for proper handling of sensitive data"""
        for file_path in self._find_python_files():
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    
                    # Check for PII handling
                    if re.search(r"email|phone|address|name|ssn|social|credit|card", content, re.IGNORECASE) and not re.search(r"mask|redact|encrypt|hash", content, re.IGNORECASE):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "file": file_path,
                            "category": "Data Protection",
                            "description": "Potential PII data without proper protection",
                            "recommendation": "Implement masking, redaction, or encryption for personally identifiable information"
                        })
                    
                    # Check for sensitive data in logs
                    if re.search(r"log\.|logger|logging", content) and re.search(r"password|token|key|secret", content, re.IGNORECASE):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "file": file_path,
                            "category": "Data Protection",
                            "description": "Sensitive data may be logged",
                            "recommendation": "Ensure sensitive data is not included in logs"
                        })
                except UnicodeDecodeError:
                    pass
    
    def check_request_validation(self):
        """Check for proper validation of API requests"""
        # Look for validation mechanisms
        validation_files = self._find_files_with_pattern(r"validate|schema|pydantic|BaseModel")
        
        # Check API endpoints for validation
        api_files = self._find_files_with_pattern(r"@app\.(?:get|post|put|delete)")
        for file_path in api_files:
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    
                    # Check for validation in route handlers
                    route_handlers = re.findall(r"@app\.(?:get|post|put|delete).*?\ndef\s+([a-zA-Z0-9_]+)", content, re.DOTALL)
                    
                    for handler in route_handlers:
                        # Find the handler function
                        handler_match = re.search(rf"def\s+{handler}\s*\((.*?)\)\s*(?:->.*?)?:", content, re.DOTALL)
                        
                        if handler_match:
                            params = handler_match.group(1)
                            
                            # Check if parameters have type hints
                            if params.strip() and not re.search(r":\s*\w+", params):
                                self.findings.append({
                                    "severity": "LOW",
                                    "file": file_path,
                                    "category": "Input Validation",
                                    "description": f"Function '{handler}' lacks type hints which can help with validation",
                                    "recommendation": "Add type hints to function parameters to enforce type checking"
                                })
                            
                            # Check if there's validation in the function body
                            handler_body_match = re.search(rf"def\s+{handler}.*?:(.*?)(?:def|\Z)", content, re.DOTALL)
                            
                            if handler_body_match:
                                handler_body = handler_body_match.group(1)
                                
                                if not re.search(r"validate|check|assert|schema|pydantic", handler_body, re.IGNORECASE):
                                    self.findings.append({
                                        "severity": "MEDIUM",
                                        "file": file_path,
                                        "category": "Input Validation",
                                        "description": f"API handler '{handler}' may lack input validation",
                                        "recommendation": "Implement input validation using Pydantic models or custom validation logic"
                                    })
                except UnicodeDecodeError:
                    pass
    
    def check_error_handling(self):
        """Check for proper error handling"""
        for file_path in self._find_python_files():
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    
                    # Check for exception handling that might leak information
                    if re.search(r"except.*?:\s*return\s+.*?str\(e\)", content, re.DOTALL):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "file": file_path,
                            "category": "Error Handling",
                            "description": "Error handling may leak sensitive information through exception messages",
                            "recommendation": "Use generic error messages and log details instead of returning exception details"
                        })
                    
                    # Check for overly broad exception handling
                    if re.search(r"except\s*:", content) and not re.search(r"except\s+\w+", content):
                        self.findings.append({
                            "severity": "LOW",
                            "file": file_path,
                            "category": "Error Handling",
                            "description": "Overly broad exception handling (bare except clause)",
                            "recommendation": "Catch specific exceptions instead of using bare except clauses"
                        })
                    
                    # Check for proper API error responses
                    if re.search(r"@app\.(?:get|post|put|delete)", content) and not re.search(r"try|except", content):
                        self.findings.append({
                            "severity": "LOW",
                            "file": file_path,
                            "category": "Error Handling",
                            "description": "API endpoint lacks error handling",
                            "recommendation": "Implement try-except blocks to gracefully handle errors in API endpoints"
                        })
                except UnicodeDecodeError:
                    pass
    
    def check_prompt_injection_safeguards(self):
        """Check for safeguards against prompt injection attacks"""
        model_files = self._find_files_with_pattern(r"model|llm|gpt|openai|anthropic|claude|prompt")
        
        if model_files:
            for file_path in model_files:
                with open(file_path, 'r') as f:
                    try:
                        content = f.read()
                        
                        # Check for user input directly in prompts
                        for pattern in self.vuln_patterns["prompt_injection"]:
                            if re.search(pattern, content):
                                self.findings.append({
                                    "severity": "HIGH",
                                    "file": file_path,
                                    "category": "Prompt Security",
                                    "description": "Potential prompt injection vulnerability with unsanitized user input",
                                    "recommendation": "Sanitize user input before incorporating it into prompts and use clear role separation"
                                })
                                
                        # Check for prompt sanitization
                        if re.search(r"prompt.*user|user.*prompt", content) and not re.search(r"sanitize|clean|validate|filter", content):
                            self.findings.append({
                                "severity": "MEDIUM",
                                "file": file_path,
                                "category": "Prompt Security",
                                "description": "User input may be used in prompts without sanitization",
                                "recommendation": "Implement prompt sanitization to filter out potential injection attempts"
                            })
                            
                        # Check for system/user role separation
                        if re.search(r"prompt", content) and not re.search(r"system|user|assistant|role", content):
                            self.findings.append({
                                "severity": "LOW",
                                "file": file_path,
                                "category": "Prompt Security",
                                "description": "Prompts may not use clear role separation",
                                "recommendation": "Use explicit role separation (system/user/assistant) in prompts"
                            })
                    except UnicodeDecodeError:
                        pass
        else:
            self.findings.append({
                "severity": "INFO",
                "file": "N/A",
                "category": "Prompt Security",
                "description": "No prompt handling code detected",
                "recommendation": "If using LLMs, ensure proper prompt sanitization is implemented"
            })
    
    def check_content_filtering(self):
        """Check for content filtering mechanisms"""
        content_files = self._find_files_with_pattern(r"content|filter|moderate|inappropriate|harmful")
        
        if not content_files and any(self._find_files_with_pattern(r"model|llm|gpt|openai|anthropic|claude")):
            self.findings.append({
                "severity": "MEDIUM",
                "file": "N/A",
                "category": "Content Security",
                "description": "No content filtering mechanisms detected for LLM interactions",
                "recommendation": "Implement content filtering to prevent harmful or inappropriate content"
            })
    
    def check_rate_limiting(self):
        """Check for rate limiting mechanisms"""
        rate_limit_files = self._find_files_with_pattern(r"rate_limit|throttle|limiter")
        
        if not rate_limit_files:
            self.findings.append({
                "severity": "MEDIUM",
                "file": "N/A",
                "category": "Rate Limiting",
                "description": "No rate limiting mechanisms detected",
                "recommendation": "Implement rate limiting to prevent abuse and control costs"
            })
        else:
            # Check if rate limits are per-user
            for file_path in rate_limit_files:
                with open(file_path, 'r') as f:
                    try:
                        content = f.read()
                        if not re.search(r"user_id|tenant|client", content):
                            self.findings.append({
                                "severity": "LOW",
                                "file": file_path,
                                "category": "Rate Limiting",
                                "description": "Rate limiting may not be user-specific",
                                "recommendation": "Implement per-user rate limiting to prevent individual users from consuming all resources"
                            })
                    except UnicodeDecodeError:
                        pass
    
    def check_logging_security(self):
        """Check for secure logging practices"""
        log_files = self._find_files_with_pattern(r"log\.|logger|logging")
        
        if log_files:
            for file_path in log_files:
                with open(file_path, 'r') as f:
                    try:
                        content = f.read()
                        
                        # Check for sensitive data in logs
                        if re.search(r"log.*\(.*(?:password|token|key|secret)", content, re.IGNORECASE):
                            self.findings.append({
                                "severity": "HIGH",
                                "file": file_path,
                                "category": "Logging",
                                "description": "Sensitive data may be logged",
                                "recommendation": "Avoid logging sensitive information like passwords, tokens, or keys"
                            })
                            
                        # Check for proper log levels
                        if re.search(r"log\.debug|logger\.debug", content) and not re.search(r"if\s+debug|DEBUG|development", content):
                            self.findings.append({
                                "severity": "LOW",
                                "file": file_path,
                                "category": "Logging",
                                "description": "Debug logging may be enabled in production",
                                "recommendation": "Ensure debug logging is only enabled in development environments"
                            })
                    except UnicodeDecodeError:
                        pass
        else:
            self.findings.append({
                "severity": "LOW",
                "file": "N/A",
                "category": "Logging",
                "description": "No logging mechanisms detected",
                "recommendation": "Implement proper logging with appropriate security measures"
            })
    
    def check_dependency_security(self):
        """Check for vulnerable dependencies"""
        req_file_paths = []
        
        # Find requirements.txt files
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file == "requirements.txt" or file == "setup.py" or file == "pyproject.toml":
                    req_file_paths.append(os.path.join(root, file))
        
        if not req_file_paths:
            self.findings.append({
                "severity": "LOW",
                "file": "N/A",
                "category": "Dependencies",
                "description": "No requirements.txt, setup.py or pyproject.toml found for dependency analysis",
                "recommendation": "Ensure the project has dependency specifications for security analysis"
            })
            return
        
        for req_file in req_file_paths:
            dependencies = self._extract_dependencies(req_file)
            for dep_name, dep_version in dependencies.items():
                # Check if this is a known vulnerable dependency
                if dep_name.lower() in self.known_vulnerable_deps:
                    vulnerable_ver = self.known_vulnerable_deps[dep_name.lower()]
                    # If we have a version and it's older than the known vulnerable version
                    if dep_version and version.parse(dep_version) < version.parse(vulnerable_ver):
                        self.findings.append({
                            "severity": "HIGH",
                            "file": req_file,
                            "category": "Dependencies",
                            "description": f"Vulnerable dependency: {dep_name}=={dep_version} (should be >= {vulnerable_ver})",
                            "recommendation": f"Update {dep_name} to version {vulnerable_ver} or newer"
                        })
                
                # Check for unspecified versions (e.g., "package" with no version)
                if not dep_version:
                    self.findings.append({
                        "severity": "MEDIUM",
                        "file": req_file,
                        "category": "Dependencies",
                        "description": f"Dependency {dep_name} has no version specified, which may lead to using vulnerable versions",
                        "recommendation": "Pin dependency versions to avoid automatic upgrades to potentially vulnerable versions"
                    })
    
    def check_configuration_security(self):
        """Check for secure configuration practices"""
        config_files = []
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith(('.json', '.yaml', '.yml', '.toml', '.ini', '.cfg')) or file in ["config.py", "settings.py"]:
                    config_files.append(os.path.join(root, file))
        
        for file_path in config_files:
            with open(file_path, 'r') as f:
                try:
                    content = f.read()
                    
                    # Look for hardcoded sensitive data in config files
                    for pattern in self.vuln_patterns["keys_and_secrets"]:
                        if re.search(pattern, content):
                            self.findings.append({
                                "severity": "HIGH",
                                "file": file_path,
                                "category": "Configuration",
                                "description": "Hardcoded sensitive data in configuration file",
                                "recommendation": "Use environment variables or a secure secrets manager for sensitive configuration"
                            })
                            
                    # Check for environment variable usage
                    if re.search(r"api_key|token|secret|password", content, re.IGNORECASE) and not re.search(r"os\.environ|getenv", content):
                        self.findings.append({
                            "severity": "MEDIUM",
                            "file": file_path,
                            "category": "Configuration",
                            "description": "Sensitive configuration may not use environment variables",
                            "recommendation": "Use environment variables for sensitive configuration values"
                        })
                except UnicodeDecodeError:
                    pass
                except (IOError, PermissionError):
                    pass
    
    def _find_files_with_pattern(self, pattern: str) -> List[str]:
        """Find files containing the specified regex pattern"""
        matching_files = []
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            try:
                                content = f.read()
                                if re.search(pattern, content):
                                    matching_files.append(file_path)
                            except UnicodeDecodeError:
                                pass
                    except (IOError, PermissionError):
                        pass
        return matching_files
    
    def _find_python_files(self) -> List[str]:
        """Find all Python files in the repository"""
        python_files = []
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        return python_files
    
    def _extract_dependencies(self, file_path: str) -> Dict[str, Optional[str]]:
        """Extract dependencies and their versions from requirements.txt or setup.py"""
        dependencies = {}
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
                if file_path.endswith('requirements.txt'):
                    # Parse requirements.txt
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Handle various formats: package==1.0.0, package>=1.0.0, package
                            parts = re.split(r'==|>=|<=|>|<|~=', line)
                            package = parts[0].strip()
                            version = parts[1].strip() if len(parts) > 1 else None
                            dependencies[package] = version
                
                elif file_path.endswith('setup.py'):
                    # Extract from setup.py using regex
                    install_requires = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
                    if install_requires:
                        reqs = install_requires.group(1)
                        for line in re.findall(r'["\'](.+?)["\']', reqs):
                            if line:
                                # Handle various formats: package==1.0.0, package>=1.0.0, package
                                parts = re.split(r'==|>=|<=|>|<|~=', line)
                                package = parts[0].strip()
                                version = parts[1].strip() if len(parts) > 1 else None
                                dependencies[package] = version
                
                elif file_path.endswith('pyproject.toml'):
                    # Try to parse as TOML
                    try:
                        import tomli
                        toml_dict = tomli.loads(content)
                        
                        # Check for dependencies in different possible locations
                        deps = {}
                        if 'dependencies' in toml_dict.get('project', {}):
                            deps.update(toml_dict['project']['dependencies'])
                        if 'dependencies' in toml_dict.get('tool', {}).get('poetry', {}):
                            deps.update(toml_dict['tool']['poetry']['dependencies'])
                        
                        for package, requirement in deps.items():
                            if isinstance(requirement, str):
                                # Handle version specifier like ">=1.0.0"
                                version_match = re.search(r'[><=~]+\s*(\d+\.\d+\.\d+)', requirement)
                                version = version_match.group(1) if version_match else None
                                dependencies[package] = version
                            elif isinstance(requirement, dict) and 'version' in requirement:
                                dependencies[package] = requirement['version']
                    except (ImportError, Exception):
                        # Fallback to regex if tomli is not available or parsing fails
                        for section in ['dependencies', 'dev-dependencies']:
                            section_match = re.search(rf'{section}\s*=\s*\[(.*?)\]', content, re.DOTALL)
                            if section_match:
                                deps_section = section_match.group(1)
                                for item in re.findall(r'[\'"]([\w-]+)[\'"](?:\s*=\s*[\'"](.+?)[\'"])?', deps_section):
                                    package, version = item
                                    if version:
                                        version_match = re.search(r'(\d+\.\d+\.\d+)', version)
                                        if version_match:
                                            dependencies[package] = version_match.group(1)
                                    else:
                                        dependencies[package] = None
        
        except Exception as e:
            self.findings.append({
                "severity": "INFO",
                "file": file_path,
                "category": "Dependencies",
                "description": f"Error parsing dependencies: {str(e)}",
                "recommendation": "Ensure dependency files are in standard format"
            })
        
        return dependencies


def clone_repo(github_url: str) -> str:
    """Clone a GitHub repository to a temporary directory and return the path"""
    temp_dir = tempfile.mkdtemp()
    try:
        git.Repo.clone_from(github_url, temp_dir)
        return temp_dir
    except Exception as e:
        shutil.rmtree(temp_dir)
        raise Exception(f"Failed to clone repository: {str(e)}")


def scan_github_repo(github_url: str) -> Dict[str, Any]:
    """Scan security of an MCP implementation from a GitHub URL"""
    temp_dir = None
    try:
        temp_dir = clone_repo(github_url)
        scanner = MCPSecurityScanner(temp_dir)
        results = scanner.scan()
        return results
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def generate_security_profile(github_url: str, output_format: str = "json") -> str:
    """Generate a security profile for an MCP implementation
    
    Args:
        github_url: URL of the GitHub repository
        output_format: Format for the report ("json" or "markdown")
        
    Returns:
        String containing the report in the specified format
    """
    try:
        results = scan_github_repo(github_url)
        
        if output_format == "json":
            return json.dumps(results, indent=2)
        elif output_format == "markdown":
            # Generate markdown report based on our template
            repo_name = github_url.split("/")[-1]
            
            md_report = f"# MCP Security Profile: {repo_name}\n\n"
            
            # Basic Information
            md_report += "## Basic Information\n"
            md_report += f"- **Name**: {repo_name}\n"
            md_report += f"- **Repository**: {github_url}\n"
            md_report += f"- **Primary Function**: [To be determined]\n"
            md_report += f"- **Evaluation Date**: {results['metadata']['scan_date']}\n"
            md_report += f"- **Evaluator**: MCP Security Scanner\n"
            md_report += f"- **Certification Level**: {results['metadata']['certification_level']}\n\n"
            
            # Security Score
            md_report += "## Security Score\n"
            md_report += f"- **Overall Score**: {results['scores']['overall']}/10\n"
            md_report += f"- **Authentication & Authorization**: {results['scores']['authentication']}/10\n"
            md_report += f"- **Data Protection**: {results['scores']['data_protection']}/10\n"
            md_report += f"- **Input Validation**: {results['scores']['input_validation']}/10\n"
            md_report += f"- **Prompt Security**: {results['scores']['prompt_security']}/10\n"
            md_report += f"- **Infrastructure Security**: {results['scores']['infrastructure']}/10\n\n"
            
            # Executive Summary
            md_report += "## Executive Summary\n\n"
            md_report += "This security profile was automatically generated by the MCP Security Scanner. "
            md_report += f"The implementation received a {results['metadata']['certification_level']} certification level with an overall security score of {results['scores']['overall']}/10.\n\n"
            
            # Strengths and weaknesses
            if results['strengths']:
                md_report += "**Strengths**:\n"
                for strength in results['strengths']:
                    md_report += f"- {strength}\n"
                md_report += "\n"
            
            if results['weaknesses']:
                md_report += "**Weaknesses**:\n"
                for weakness in results['weaknesses']:
                    md_report += f"- {weakness}\n"
                md_report += "\n"
            
            md_report += f"A total of {results['findings_summary']['total']} security findings were identified.\n\n"
            
            # Vulnerabilities
            md_report += "## Vulnerabilities\n\n"
            md_report += "| ID | Severity | Category | Description | Recommendation |\n"
            md_report += "|---|----------|----------|-------------|----------------|\n"
            
            for i, finding in enumerate(results['findings'], 1):
                md_report += f"| F{i} | {finding['severity']} | {finding['category']} | {finding['description']} | {finding['recommendation']} |\n"
            
            md_report += "\n"
            
            # Certification Details
            md_report += "## Certification Details\n\n"
            md_report += f"- **Certification Level**: {results['metadata']['certification_level']}\n"
            md_report += f"- **Justification**: {results['metadata']['certification_details']}\n"
            md_report += "- **Conditions**: This certification is based on automated analysis and should be verified by manual review.\n"
            md_report += f"- **Expiration**: {results['metadata']['scan_date']} + 6 months\n\n"
            
            # Detailed Findings
            md_report += "## Detailed Findings\n\n"
            
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                findings = results['grouped_findings'][severity]
                if findings:
                    md_report += f"### {severity} Severity Findings ({len(findings)})\n\n"
                    for i, finding in enumerate(findings, 1):
                        md_report += f"#### {i}. {finding['description']}\n\n"
                        md_report += f"- **File**: {finding['file']}\n"
                        md_report += f"- **Category**: {finding['category']}\n"
                        md_report += f"- **Recommendation**: {finding['recommendation']}\n"
                        
                        if 'code_snippet' in finding and finding['code_snippet']:
                            md_report += "\n**Code Snippet**:\n"
                            md_report += f"\n{finding['code_snippet']}\n\n"
                        
                        md_report += "\n"
            
            return md_report
        else:
            raise ValueError("Invalid output format. Use 'json' or 'markdown'.")
    except Exception as e:
        if output_format == "json":
            return json.dumps({"error": str(e)})
        else:
            return f"# Error\n\n{str(e)}"


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Security scanner for MCP implementations")
    parser.add_argument("github_url", help="URL of the GitHub repository")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown",
                        help="Output format (default: markdown)")
    parser.add_argument("--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    report = generate_security_profile(args.github_url, args.format)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
    else:
        print(report)