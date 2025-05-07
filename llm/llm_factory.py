from typing import Dict, Any
from .ollama_client import OllamaClient

def get_llm_client(provider: str, config: Dict[str, Any]):
    """
    Factory function to get the appropriate LLM client
    
    Args:
        provider: The LLM provider (ollama, openai, etc.)
        config: Configuration dictionary
        
    Returns:
        An LLM client instance
    """
    if provider.lower() == "ollama":
        base_url = config.get("LLM_ENDPOINT", "http://localhost:11434").rsplit("/api", 1)[0]
        model = config.get("LLM_MODEL", "qwen:7b")
        return OllamaClient(base_url=base_url, model=model)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")