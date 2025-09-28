"""
Configuration management for KubeGuard MCP server
"""

import os
from typing import Optional, Dict, Any
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class LLMConfig:
    """LLM provider configuration"""
    provider: str = "none"  # openai, anthropic, none
    model: str = "gpt-4o-mini"
    api_key: Optional[str] = None
    max_tokens: int = 4000
    temperature: float = 0.1
    max_retries: int = 3
    timeout: int = 30


@dataclass
class ServerConfig:
    """MCP server configuration"""
    name: str = "kubeguard-role-security"
    version: str = "1.0.0"
    log_level: str = "INFO"
    debug: bool = False


@dataclass
class AnalysisConfig:
    """Analysis behavior configuration"""
    security_score_threshold: float = 70.0
    enable_runtime_simulation: bool = True
    max_prompt_chain_retries: int = 3
    
    # Security scoring weights
    wildcard_penalty: float = 20.0
    excessive_permission_penalty: float = 10.0
    sensitive_resource_penalty: float = 15.0
    unused_permission_penalty: float = 5.0


class Config:
    """Main configuration class"""
    
    def __init__(self):
        self.llm = LLMConfig(
            provider=os.getenv("LLM_PROVIDER", "none"),
            model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
            api_key=self._get_llm_api_key(),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4000")),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
            max_retries=int(os.getenv("LLM_MAX_RETRIES", "3")),
            timeout=int(os.getenv("LLM_TIMEOUT", "30"))
        )
        
        self.server = ServerConfig(
            name=os.getenv("SERVER_NAME", "kubeguard-role-security"),
            version=os.getenv("SERVER_VERSION", "1.0.0"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            debug=os.getenv("DEBUG", "false").lower() == "true"
        )
        
        self.analysis = AnalysisConfig(
            security_score_threshold=float(os.getenv("SECURITY_SCORE_THRESHOLD", "70.0")),
            enable_runtime_simulation=os.getenv("ENABLE_RUNTIME_SIMULATION", "true").lower() == "true",
            max_prompt_chain_retries=int(os.getenv("MAX_PROMPT_CHAIN_RETRIES", "3")),
            wildcard_penalty=float(os.getenv("WILDCARD_PENALTY", "20.0")),
            excessive_permission_penalty=float(os.getenv("EXCESSIVE_PERMISSION_PENALTY", "10.0")),
            sensitive_resource_penalty=float(os.getenv("SENSITIVE_RESOURCE_PENALTY", "15.0")),
            unused_permission_penalty=float(os.getenv("UNUSED_PERMISSION_PENALTY", "5.0"))
        )
    
    def _get_llm_api_key(self) -> Optional[str]:
        """Get appropriate API key based on provider"""
        provider = os.getenv("LLM_PROVIDER", "none").lower()
        
        if provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        elif provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY")
        elif provider == "groq":
            return os.getenv("GROQ_API_KEY")
        elif provider == "ollama":
            return os.getenv("OLLAMA_API_KEY", "not_required")  # Ollama often doesn't need API key
        elif provider == "azure":
            return os.getenv("AZURE_OPENAI_API_KEY")
        else:
            # For generic providers, try common patterns
            provider_key = f"{provider.upper()}_API_KEY"
            return os.getenv(provider_key)
    
    @property
    def has_llm_configured(self) -> bool:
        """Check if LLM is properly configured"""
        return (
            self.llm.provider != "none" 
            and self.llm.api_key is not None 
            and len(self.llm.api_key.strip()) > 0
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary (excluding sensitive data)"""
        return {
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "has_api_key": self.llm.api_key is not None,
                "max_tokens": self.llm.max_tokens,
                "temperature": self.llm.temperature,
                "max_retries": self.llm.max_retries,
                "timeout": self.llm.timeout
            },
            "server": {
                "name": self.server.name,
                "version": self.server.version,
                "log_level": self.server.log_level,
                "debug": self.server.debug
            },
            "analysis": {
                "security_score_threshold": self.analysis.security_score_threshold,
                "enable_runtime_simulation": self.analysis.enable_runtime_simulation,
                "max_prompt_chain_retries": self.analysis.max_prompt_chain_retries,
                "scoring_weights": {
                    "wildcard_penalty": self.analysis.wildcard_penalty,
                    "excessive_permission_penalty": self.analysis.excessive_permission_penalty,
                    "sensitive_resource_penalty": self.analysis.sensitive_resource_penalty,
                    "unused_permission_penalty": self.analysis.unused_permission_penalty
                }
            }
        }


# Global configuration instance
config = Config()