
```markdown:CONTRIBUTING.md
# Contributing to MCP Security Registry

Thank you for your interest in contributing to the MCP Security Registry! This document outlines the process for contributing to the project.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Improving Evaluation Criteria

1. **Review the current criteria** in [evaluation-criterea.md](evaluation-criterea.md)
2. **Fork this repository** and create a new branch for your changes
3. **Make your improvements** to the criteria, ensuring they are clear, objective, and security-focused
4. **Submit a pull request** with your changes

### Enhancing the Evaluation Template

1. **Review the current template** in [evaluation-template.md](evaluation-template.md)
2. **Fork this repository** and create a new branch for your changes
3. **Make your improvements** to the template, ensuring it covers all relevant security aspects
4. **Submit a pull request** with your changes

### Improving the Analysis Agent

1. **Review the current implementation** in [analysis/mcp_analysis_agent.py](analysis/mcp_analysis_agent.py)
2. **Fork this repository** and create a new branch for your changes
3. **Make your improvements** to the analysis logic, LLM prompting, or result parsing
4. **Add tests** for any new functionality
5. **Submit a pull request** with your changes

### Suggesting New Security Checks

If you have ideas for new security checks that should be included in our evaluations:

1. **Open an issue** describing the security check and why it's important
2. **Provide examples** of how the vulnerability might manifest in MCP servers
3. **Suggest remediation steps** that developers could take

## Development Setup

To set up the project for local development:

1. **Clone the repository**:
   ```
   git clone https://github.com/heidiEC/mcp-security.git
   cd mcp-security
   ```

2. **Install dependencies**:
   ```
   pip install -r requirements.txt
   ```

3. **Set up MongoDB** (required for storing analysis results):
   ```
   # Example using Docker
   docker run -d -p 27017:27017 --name mcp-mongodb mongo:latest
   ```

4. **Set environment variables**:
   ```
   export OPENAI_API_KEY=your_api_key_here
   export MONGODB_URI=mongodb://localhost:27017/
   ```

## Testing Your Changes

Before submitting a pull request, please test your changes:

1. **Run the test suite**:
   ```
   pytest
   ```

2. **Test with a sample repository**:
   ```
   python -m analysis.mcp_analysis_agent https://github.com/example/mcp-server
   ```

## Review Process

All contributions will be reviewed by the project maintainers. The review process includes:

1. **Technical accuracy review** - Ensuring the changes are technically accurate
2. **Security focus review** - Verifying the changes maintain or improve security focus
3. **Code quality check** - Checking for code quality and adherence to project standards
4. **Documentation review** - Ensuring any documentation changes are clear and helpful

## Responsible Disclosure

If you discover a security vulnerability in an MCP server implementation during your work on this project, please follow responsible disclosure practices:

1. Do not include exploit details in public issues or pull requests
2. Contact the maintainers of the affected MCP server privately
3. Allow reasonable time for them to address the issue
4. Coordinate disclosure with the maintainers

## Questions?

If you have questions about the contribution process, please open an issue or contact the maintainers.