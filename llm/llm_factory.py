from typing import Dict, Any
import os
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
    elif provider.lower() == "anthropic":
        return get_anthropic_client(config)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
    
def get_anthropic_client(config):
    """Get Anthropic Claude client"""
    from anthropic import Anthropic
    
    api_key = os.environ.get("ANTHROPIC_API_KEY") or config.get("ANTHROPIC_API_KEY")
    model = config.get("LLM_MODEL", "claude-3-sonnet-20240229")
    
    if not api_key:
        raise ValueError("Anthropic API key not found")
    
    client = Anthropic(api_key=api_key)
    
    return AnthropicClient(client, model)

class AnthropicClient:
    def __init__(self, client, model):
        self.client = client
        self.model = model
    
    def generate_completion(self, prompt, system_prompt=None, temperature=0.7):
        """Generate completion using Anthropic Claude"""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4000,
            temperature=temperature,
            system=system_prompt,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        return response.content[0].text