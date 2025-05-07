import os
import json
import datetime
import requests
import git
import tempfile
import shutil
from typing import Dict, List, Any, Optional
from pymongo import MongoClient
import markdown
from bson.objectid import ObjectId

# MongoDB connection
client = MongoClient(os.environ.get("MONGODB_URI", "mongodb://localhost:27017/"))
db = client["mcp_security"]

class MCPAnalysisAgent:
    """Agent for analyzing MCP server repositories using LLM"""
    
    def __init__(self, llm_api_key: str, llm_endpoint: str):
        self.llm_api_key = llm_api_key
        self.llm_endpoint = llm_endpoint
        
        # Load evaluation criteria from file
        with open("evaluation-criterea.md", "r") as f:
            self.evaluation_criteria = f.read()
            
        # Load evaluation template from file
        with open("evaluation-template.md", "r") as f:
            self.evaluation_template = f.read()
    
    def analyze_repository(self, repo_url: str) -> Dict[str, Any]:
        """
        Analyze an MCP server repository and generate a security profile
        
        Args:
            repo_url: URL of the GitHub repository
            
        Returns:
            Dictionary containing the security profile
        """
        # Clone repository to temporary directory
        repo_path = self._clone_repository(repo_url)
        try:
            # Extract repository metadata
            repo_metadata = self._extract_repo_metadata(repo_path, repo_url)
            
            # Extract security-relevant files
            security_files = self._extract_security_files(repo_path)
            
            # Store files in database
            repo_id = self._store_repository_info(repo_metadata)
            self._store_security_files(repo_id, security_files)
            
            # Generate LLM analysis prompt
            prompt = self._generate_analysis_prompt(repo_metadata, security_files)
            
            # Get LLM analysis
            analysis_result = self._get_llm_analysis(prompt)
            
            # Parse and store the analysis
            security_profile = self._parse_llm_analysis(analysis_result)
            security_profile["repo_id"] = repo_id
            
            # Store the security profile
            profile_id = self._store_security_profile(security_profile)
            
            # Update repository certification
            self._update_repository_certification(
                repo_id, 
                security_profile["certification"]["level"],
                security_profile["scores"]["overall"]
            )
            
            return {
                "repo_id": str(repo_id),
                "profile_id": str(profile_id),
                "certification_level": security_profile["certification"]["level"],
                "security_score": security_profile["scores"]["overall"]
            }
            
        finally:
            # Clean up temporary directory
            if repo_path and os.path.exists(repo_path):
                shutil.rmtree(repo_path)
    
    def _clone_repository(self, repo_url: str) -> str:
        """Clone a repository to a temporary directory"""
        temp_dir = tempfile.mkdtemp()
        try:
            git.Repo.clone_from(repo_url, temp_dir)
            return temp_dir
        except Exception as e:
            shutil.rmtree(temp_dir)
            raise Exception(f"Failed to clone repository: {str(e)}")
    
    def _extract_repo_metadata(self, repo_path: str, repo_url: str) -> Dict[str, Any]:
        """Extract metadata from the repository"""
        repo = git.Repo(repo_path)
        
        # Get the latest commit
        latest_commit = repo.head.commit
        
        # Try to extract name from repo_url
        repo_name = repo_url.split("/")[-1]
        
        # Try to determine primary function from README or other files
        primary_function = self._determine_primary_function(repo_path)
        
        return {
            "name": repo_name,
            "repo_url": repo_url,
            "primary_function": primary_function,
            "evaluation_date": datetime.datetime.now(),
            "evaluator": "MCP Security Analysis Agent",
            "version_evaluated": latest_commit.hexsha,
            "last_updated": datetime.datetime.fromtimestamp(latest_commit.committed_date)
        }
    
    def _determine_primary_function(self, repo_path: str) -> str:
        """Try to determine the primary function of the MCP server"""
        # Check README for clues
        readme_path = os.path.join(repo_path, "README.md")
        if os.path.exists(readme_path):
            with open(readme_path, "r") as f:
                content = f.read().lower()
                if "memory" in content and "store" in content:
                    return "Memory"
                elif "retrieval" in content and ("search" in content or "query" in content):
                    return "Retrieval"
                elif "tool" in content or "function" in content:
                    return "Tool"
        
        # Default if we can't determine
        return "Unknown"
    
    def _extract_security_files(self, repo_path: str) -> Dict[str, Dict[str, Any]]:
        """Extract security-relevant files from the repository"""
        security_files = {}
        
        # File patterns to look for by category
        file_patterns = {
            "config": [
                "config.py", "settings.py", ".env.example", "config.json", 
                "docker-compose.yml", "Dockerfile"
            ],
            "auth": [
                "auth.py", "authentication.py", "security.py", "login.py",
                "oauth.py", "jwt.py", "token.py"
            ],
            "api": [
                "api.py", "routes.py", "endpoints.py", "views.py", 
                "controllers.py", "handlers.py"
            ],
            "main": [
                "app.py", "main.py", "server.py", "index.py", 
                "__main__.py", "run.py"
            ],
            "docs": [
                "README.md", "SECURITY.md", "API.md", "CONTRIBUTING.md"
            ],
            "dependencies": [
                "requirements.txt", "package.json", "pyproject.toml",
                "setup.py", "Pipfile", "poetry.lock"
            ]
        }
        
        # Walk through repository and find matching files
        for root, _, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repo_path)
                
                # Skip .git directory
                if ".git" in relative_path.split(os.path.sep):
                    continue
                
                # Determine file type
                file_type = None
                for category, patterns in file_patterns.items():
                    if any(file.endswith(pattern) or file == pattern for pattern in patterns):
                        file_type = category
                        break
                
                # If no match in patterns, try to determine by content for Python files
                if not file_type and file.endswith(".py"):
                    file_type = self._determine_file_type_by_content(file_path)
                
                # If we identified a file type, read the content
                if file_type:
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                            
                            security_files[relative_path] = {
                                "file_path": relative_path,
                                "file_type": file_type,
                                "content": content,
                                "last_updated": datetime.datetime.fromtimestamp(
                                    os.path.getmtime(file_path)
                                )
                            }
                    except UnicodeDecodeError:
                        # Skip binary files
                        pass
        
        return security_files
    
    def _determine_file_type_by_content(self, file_path: str) -> Optional[str]:
        """Determine file type by examining content"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().lower()
                
                if "auth" in content or "login" in content or "token" in content:
                    return "auth"
                elif "app.route" in content or "fastapi" in content or "endpoint" in content:
                    return "api"
                elif "config" in content or "settings" in content or "environment" in content:
                    return "config"
                elif "if __name__ == '__main__'" in content:
                    return "main"
                
                return None
        except UnicodeDecodeError:
            return None
    
    def _store_repository_info(self, repo_metadata: Dict[str, Any]) -> ObjectId:
        """Store repository information in database"""
        # Check if repository already exists
        existing_repo = db.repositories.find_one({"repo_url": repo_metadata["repo_url"]})
        
        if existing_repo:
            # Update existing repository
            db.repositories.update_one(
                {"_id": existing_repo["_id"]},
                {"$set": {
                    "evaluation_date": repo_metadata["evaluation_date"],
                    "version_evaluated": repo_metadata["version_evaluated"],
                    "last_updated": repo_metadata["last_updated"]
                }}
            )
            return existing_repo["_id"]
        else:
            # Insert new repository
            result = db.repositories.insert_one(repo_metadata)
            return result.inserted_id
    
    def _store_security_files(self, repo_id: ObjectId, security_files: Dict[str, Dict[str, Any]]) -> None:
        """Store security-relevant files in database"""
        # Delete existing files for this repository
        db.security_files.delete_many({"repo_id": repo_id})
        
        # Insert new files
        for file_path, file_data in security_files.items():
            file_data["repo_id"] = repo_id
            db.security_files.insert_one(file_data)
    
    def _generate_analysis_prompt(self, repo_metadata: Dict[str, Any], security_files: Dict[str, Dict[str, Any]]) -> str:
        """Generate a prompt for LLM analysis"""
        prompt = f"""
# MCP Security Analysis Request

Please analyze the following Model Context Protocol (MCP) server implementation for security vulnerabilities and best practices.

## Repository Information
- Name: {repo_metadata['name']}
- Repository URL: {repo_metadata['repo_url']}
- Primary Function: {repo_metadata['primary_function']}
- Version: {repo_metadata['version_evaluated']}

## Evaluation Criteria
Use the following criteria to evaluate the security of this MCP server:

{self.evaluation_criteria}

## Security-Relevant Files

"""
        
        # Group files by type
        files_by_type = {}
        for file_path, file_data in security_files.items():
            file_type = file_data["file_type"]
            if file_type not in files_by_type:
                files_by_type[file_type] = []
            files_by_type[file_type].append((file_path, file_data["content"]))
        
        # Add files to prompt, grouped by type
        for file_type, files in files_by_type.items():
            prompt += f"### {file_type.title()} Files\n\n"
            
            for file_path, content in files:
                # Truncate very large files
                if len(content) > 5000:
                    content = content[:5000] + "...[truncated]"
                
                prompt += f"**File: {file_path}**\n\n{content}\n\n\n"
        
        # Add instructions for output format
        prompt += f"""
## Output Format
Please provide your analysis in the following format:

{self.evaluation_template}

Focus on practical, actionable insights rather than theoretical concerns.
"""
        
        return prompt
    
    def _get_llm_analysis(self, prompt: str) -> str:
        """Get analysis from LLM API"""
        # This is a placeholder - implement your specific LLM API call here
        # For example, using OpenAI's API:
        
        headers = {
            "Authorization": f"Bearer {self.llm_api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "gpt-4",  # or your preferred model
            "messages": [
                {"role": "system", "content": "You are a security expert analyzing MCP server implementations."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 4000
        }
        
        response = requests.post(self.llm_endpoint, headers=headers, json=data)
        
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            raise Exception(f"LLM API error: {response.status_code} - {response.text}")
    
    def _parse_llm_analysis(self, analysis_result: str) -> Dict[str, Any]:
        """Parse the LLM analysis into a structured format"""
        # Store the full markdown report
        security_profile = {
            "markdown_report": analysis_result,
            "evaluation_date": datetime.datetime.now()
        }
        
        # Extract sections using markdown parsing or regex
        # This is a simplified version - you might need more robust parsing
        
        # Extract scores
        scores = {
            "overall": 0,
            "authentication": 0,
            "data_protection": 0,
            "input_validation": 0,
            "prompt_security": 0,
            "infrastructure": 0
        }
        
        score_lines = self._extract_section(analysis_result, "Security Score", "Executive Summary")
        for line in score_lines.split("\n"):
            if "Overall Score" in line:
                scores["overall"] = self._extract_score(line)
            elif "Authentication" in line:
                scores["authentication"] = self._extract_score(line)
            elif "Data Protection" in line:
                scores["data_protection"] = self._extract_score(line)
            elif "Input Validation" in line:
                scores["input_validation"] = self._extract_score(line)
            elif "Prompt Security" in line:
                scores["prompt_security"] = self._extract_score(line)
            elif "Infrastructure" in line:
                scores["infrastructure"] = self._extract_score(line)
        
        security_profile["scores"] = scores
        
        # Extract executive summary
        security_profile["executive_summary"] = self._extract_section(
            analysis_result, "Executive Summary", "Security Features"
        )
        
        # Extract vulnerabilities
        vulnerabilities_section = self._extract_section(analysis_result, "Vulnerabilities", "Deployment Recommendations")
        vulnerabilities = []
        
        # Parse the markdown table - this is a simplified approach
        lines = vulnerabilities_section.split("\n")
        for line in lines:
            if "|" in line and not line.startswith("|-") and not line.startswith("| ID"):
                parts = line.split("|")
                if len(parts) >= 6:
                    vulnerabilities.append({
                        "id": parts[1].strip(),
                        "severity": parts[2].strip(),
                        "category": parts[3].strip(),
                        "description": parts[4].strip(),
                        "recommendation": parts[5].strip(),
                        "status": "Open"
                    })
        
        security_profile["vulnerabilities"] = vulnerabilities
        
        # Extract certification details
        certification_section = self._extract_section(analysis_result, "Certification Details", "Change History")
        certification = {
            "level": "None",
            "justification": "",
            "conditions": "",
            "expiration": datetime.datetime.now() + datetime.timedelta(days=180)
        }
        
        for line in certification_section.split("\n"):
            if "Certification Level" in line and ":" in line:
                level = line.split(":", 1)[1].strip()
                if level in ["Bronze", "Silver", "Gold"]:
                    certification["level"] = level
            elif "Justification" in line and ":" in line:
                certification["justification"] = line.split(":", 1)[1].strip()
            elif "Conditions" in line and ":" in line:
                certification["conditions"] = line.split(":", 1)[1].strip()
            elif "Expiration" in line and ":" in line:
                # Try to parse expiration date, fallback to 6 months if parsing fails
                try:
                    expiration_text = line.split(":", 1)[1].strip()
                    certification["expiration"] = datetime.datetime.strptime(expiration_text, "%Y-%m-%d")
                except:
                    pass
        
        security_profile["certification"] = certification
        
        # Extract security features
        security_features = {}
        
        # Extract each security feature section
        feature_sections = [
            ("Authentication & Authorization", "authentication"),
            ("Data Protection", "data_protection"),
            ("Input Validation & Processing", "input_validation"),
            ("Prompt Security", "prompt_security"),
            ("Infrastructure Security", "infrastructure")
        ]
        
        for section_title, feature_key in feature_sections:
            section_content = self._extract_section(analysis_result, section_title, next_section=None)
            if section_content:
                security_features[feature_key] = section_content
        
        security_profile["security_features"] = security_features
        
        # Extract deployment recommendations
        security_profile["deployment_recommendations"] = self._extract_section(
            analysis_result, "Deployment Recommendations", "Code Quality Assessment"
        )
        
        # Extract code quality assessment
        security_profile["code_quality"] = self._extract_section(
            analysis_result, "Code Quality Assessment", "Certification Details"
        )
        
        return security_profile
    
    def _extract_section(self, text: str, section_title: str, next_section: Optional[str] = None) -> str:
        """Extract a section from the markdown text"""
        import re
        
        # Pattern to match the section header
        section_pattern = rf"## {re.escape(section_title)}\s*\n"
        
        # Find the start of the section
        match = re.search(section_pattern, text)
        if not match:
            return ""
        
        start_pos = match.end()
        
        # Find the end of the section (start of the next section or end of text)
        if next_section:
            next_section_pattern = rf"## {re.escape(next_section)}\s*\n"
            next_match = re.search(next_section_pattern, text[start_pos:])
            if next_match:
                end_pos = start_pos + next_match.start()
            else:
                end_pos = len(text)
        else:
            # Look for any section header
            next_header_match = re.search(r"## ", text[start_pos:])
            if next_header_match:
                end_pos = start_pos + next_header_match.start()
            else:
                end_pos = len(text)
        
        # Extract and return the section content
        return text[start_pos:end_pos].strip()
    
    def _extract_score(self, line: str) -> float:
        """Extract a numeric score from a line of text"""
        import re
        
        # Try to find a pattern like "8/10" or "8.5/10"
        score_match = re.search(r"(\d+(?:\.\d+)?)/10", line)
        if score_match:
            return float(score_match.group(1))
        
        # Try to find just a number
        number_match = re.search(r"(\d+(?:\.\d+)?)", line)
        if number_match:
            score = float(number_match.group(1))
            # Ensure it's in the range 1-10
            if 1 <= score <= 10:
                return score
        
        # Default score if we can't extract one
        return 5.0
    
    def _store_security_profile(self, security_profile: Dict[str, Any]) -> ObjectId:
        """Store the security profile in the database"""
        # Check if a profile already exists for this repository
        existing_profile = db.security_profiles.find_one({"repo_id": security_profile["repo_id"]})
        
        if existing_profile:
            # Update existing profile
            db.security_profiles.update_one(
                {"_id": existing_profile["_id"]},
                {"$set": security_profile}
            )
            return existing_profile["_id"]
        else:
            # Insert new profile
            result = db.security_profiles.insert_one(security_profile)
            return result.inserted_id
    
    def _update_repository_certification(self, repo_id: ObjectId, certification_level: str, security_score: float) -> None:
        """Update the certification level and security score in the repository record"""
        db.repositories.update_one(
            {"_id": repo_id},
            {"$set": {
                "certification_level": certification_level,
                "security_score": security_score
            }}
        )
        
        # Add entry to certification history
        db.certification_history.insert_one({
            "repo_id": repo_id,
            "date": datetime.datetime.now(),
            "level": certification_level,
            "evaluator": "MCP Security Analysis Agent",
            "notes": f"Automated security analysis with score {security_score}/10"
        })


def analyze_github_repository(repo_url: str, llm_api_key: str, llm_endpoint: str) -> Dict[str, Any]:
    """
    Analyze a GitHub repository for MCP security
    
    Args:
        repo_url: URL of the GitHub repository
        llm_api_key: API key for the LLM service
        llm_endpoint: Endpoint URL for the LLM service
        
    Returns:
        Dictionary with analysis results
    """
    agent = MCPAnalysisAgent(llm_api_key, llm_endpoint)
    return agent.analyze_repository(repo_url)


if __name__ == "__main__":
    import argparse
    import os
    
    parser = argparse.ArgumentParser(description="Analyze MCP server security")
    parser.add_argument("repo_url", help="URL of the GitHub repository")
    parser.add_argument("--api-key", help="API key for LLM service (defaults to OPENAI_API_KEY env var)")
    parser.add_argument("--endpoint", help="Endpoint URL for LLM service", 
                        default="https://api.openai.com/v1/chat/completions")
    
    args = parser.parse_args()
    
    # Get API key from args or environment
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: No API key provided. Use --api-key or set OPENAI_API_KEY environment variable.")
        exit(1)
    
    # Run analysis
    try:
        result = analyze_github_repository(args.repo_url, api_key, args.endpoint)
        print(f"Analysis complete!")
        print(f"Repository ID: {result['repo_id']}")
        print(f"Profile ID: {result['profile_id']}")
        print(f"Certification Level: {result['certification_level']}")
        print(f"Security Score: {result['security_score']}/10")
    except Exception as e:
        print(f"Error analyzing repository: {str(e)}")
        exit(1)