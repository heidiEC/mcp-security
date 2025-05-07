import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB configuration
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "mcp_security")

# LLM configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")  # Options: "ollama", "openai", "anthropic", "huggingface"
LLM_MODEL = os.getenv("LLM_MODEL", "llama3")  
LLM_API_KEY = os.getenv("LLM_API_KEY", "")  # Not needed for Ollama
LLM_ENDPOINT = os.getenv("LLM_ENDPOINT", "http://localhost:11434/api/chat")  # Ollama local endpoint

# Application configuration
DEBUG = os.getenv("DEBUG", "False").lower() == "true"