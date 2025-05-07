import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.mcp_analysis_agent import MCPAnalysisAgent

def test_pipeline(repo_url):
    """Test the analysis pipeline with a given repository URL"""
    print(f"Testing analysis pipeline with repository: {repo_url}")
    
    # Initialize the analysis agent
    agent = MCPAnalysisAgent()
    
    # Run the analysis
    try:
        result = agent.analyze_repository(repo_url)
        
        print("\n=== Analysis Results ===")
        print(f"Repository ID: {result['repo_id']}")
        print(f"Profile ID: {result['profile_id']}")
        print(f"Certification Level: {result['certification_level']}")
        print(f"Security Score: {result['security_score']}/10")
        print("========================\n")
        
        return result
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        raise

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_pipeline.py <github_repo_url>")
        sys.exit(1)
    
    repo_url = sys.argv[1]
    test_pipeline(repo_url)