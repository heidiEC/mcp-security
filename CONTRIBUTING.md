```markdown
# Contributing to MCP Security Profiles

Thank you for your interest in contributing to the MCP Security Profiles repository! This document outlines the process for contributing security evaluations and other improvements.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Contributing a New MCP Security Profile

1. **Select an MCP server** that hasn't been evaluated yet or needs an updated evaluation
2. **Fork this repository** and create a new branch for your evaluation
3. **Run the security scanner** on the target repository:
   ```
   python tools/mcp_security_scanner.py https://github.com/user/repo-name
   ```
4. **Create a new profile** using the evaluation template:
   ```
   python tools/profile_generator.py --scan-results results.json --output profiles/category/server-name-profile.md
   ```
5. **Complete the profile** by filling in any missing information and conducting manual review
6. **Submit a pull request** with your completed profile

### Updating an Existing Profile

1. **Fork this repository** and create a new branch for your update
2. **Update the profile** with new information, version changes, or security fixes
3. **Add an entry to the change history** section of the profile
4. **Submit a pull request** with your changes

### Improving Tools or Documentation

1. **Fork this repository** and create a new branch for your changes
2. **Make your improvements** to the tools or documentation
3. **Add tests** for any new functionality
4. **Submit a pull request** with your changes

## Evaluation Guidelines

### Objectivity

Evaluations should be objective and based on the established criteria. Personal opinions should be minimized in favor of evidence-based assessment.

### Thoroughness

Evaluations should be thorough and cover all aspects of the security criteria. Don't skip sections or provide minimal information.

### Evidence

All claims in an evaluation should be backed by evidence, such as code references, configuration examples, or test results.

### Responsible Disclosure

If you discover a security vulnerability during your evaluation, please follow responsible disclosure practices:

1. Do not include exploit details in your public evaluation
2. Contact the maintainers of the MCP server privately
3. Allow reasonable time for them to address the issue
4. Include the vulnerability in your evaluation only after it has been fixed or disclosed

## Review Process

All contributions will be reviewed by the project maintainers. The review process includes:

1. **Technical accuracy review** - Ensuring the evaluation is technically accurate
2. **Completeness check** - Verifying all sections are properly completed
3. **Criteria compliance** - Confirming the evaluation follows the established criteria
4. **Quality control** - Checking for clarity, formatting, and overall quality

## Questions?

If you have questions about the contribution process, please open an issue or contact the maintainers.
```