import requests
import json
from typing import Dict, Any, List

class OllamaClient:
    """Client for interacting with Ollama API"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen:7b"):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_endpoint = f"{self.base_url}/api/chat"
    
    def generate_completion(self, prompt: str, system_prompt: str = None, temperature: float = 0.2) -> str:
        """
        Generate a completion using Ollama
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            temperature: Temperature for generation (0.0 to 1.0)
            
        Returns:
            Generated text response
        """
        messages = []
        
        # Add system message if provided
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        # Add user message
        messages.append({"role": "user", "content": prompt})
        
        # Prepare the request payload
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        
        # Make the API request
        try:
            response = requests.post(self.api_endpoint, json=payload)
            response.raise_for_status()  # Raise exception for HTTP errors
            
            result = response.json()
            return result["message"]["content"]
        except requests.exceptions.RequestException as e:
            # Check if Ollama is running
            if "Connection refused" in str(e):
                raise Exception(f"Could not connect to Ollama at {self.base_url}. Is Ollama running?")
            raise Exception(f"Ollama API error: {str(e)}")
        except (KeyError, json.JSONDecodeError) as e:
            raise Exception(f"Error parsing Ollama response: {str(e)}")