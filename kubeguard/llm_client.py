"""
Universal LLM Client for KubeGuard with API Call Logging
Supports any LLM provider through a common interface
"""

import logging
import time
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
import asyncio

from .config import config

logger = logging.getLogger(__name__)


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    def __init__(self, api_key: str, model: str, **kwargs):
        self.api_key = api_key
        self.model = model
        self.extra_params = kwargs
    
    @abstractmethod
    async def call(self, prompt: str, **kwargs) -> str:
        """Call the LLM and return response"""
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        """Validate provider configuration"""
        pass


class GroqProvider(BaseLLMProvider):
    """Groq provider implementation with detailed logging"""
    
    def __init__(self, api_key: str, model: str, **kwargs):
        super().__init__(api_key, model, **kwargs)
        self.base_url = kwargs.get("base_url", "https://api.groq.com/openai/v1")
    
    async def call(self, prompt: str, **kwargs) -> str:
        start_time = time.time()
        
        # Log the API call details
        logger.info(f"  Making API call to Groq")
        logger.info(f"   Model: {self.model}")
        logger.info(f"   Base URL: {self.base_url}")
        logger.info(f"   API Key: {self.api_key[:10]}...{self.api_key[-4:]}")
        logger.info(f"   Prompt length: {len(prompt)} characters")
        logger.info(f"   Max tokens: {kwargs.get('max_tokens', config.llm.max_tokens)}")
        logger.info(f"   Temperature: {kwargs.get('temperature', config.llm.temperature)}")
        
        # Log prompt preview (first 200 chars)
        prompt_preview = prompt[:200] + "..." if len(prompt) > 200 else prompt
        logger.debug(f"   Prompt preview: {prompt_preview}")
        
        try:
            import openai  # Groq uses OpenAI-compatible API
            
            client = openai.AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url
            )
            
            # Log the request payload
            request_payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": kwargs.get("max_tokens", config.llm.max_tokens),
                "temperature": kwargs.get("temperature", config.llm.temperature),
                **self.extra_params
            }
            logger.debug(f"   Request payload: {request_payload}")
            
            response = await client.chat.completions.create(**request_payload)
            
            # Log successful response
            response_time = time.time() - start_time
            response_text = response.choices[0].message.content
            
            logger.info(f" Groq API call successful")
            logger.info(f"   Response time: {response_time:.2f}s")
            logger.info(f"   Response length: {len(response_text)} characters")
            logger.info(f"   Usage: {getattr(response, 'usage', 'N/A')}")
            
            # Log response preview
            response_preview = response_text[:200] + "..." if len(response_text) > 200 else response_text
            logger.debug(f"   Response preview: {response_preview}")
            
            return response_text
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"❌ Groq API call failed after {response_time:.2f}s")
            logger.error(f"   Error type: {type(e).__name__}")
            logger.error(f"   Error message: {str(e)}")
            logger.error(f"   Model: {self.model}")
            logger.error(f"   Base URL: {self.base_url}")
            raise
    
    def validate_config(self) -> bool:
        return (
            self.api_key and 
            len(self.api_key.strip()) > 10 and
            self.api_key.startswith("gsk_")
        )


class OpenAIProvider(BaseLLMProvider):
    """OpenAI provider implementation with detailed logging"""
    
    def __init__(self, api_key: str, model: str, **kwargs):
        super().__init__(api_key, model, **kwargs)
        self.base_url = kwargs.get("base_url", "https://api.openai.com/v1")
        self.organization = kwargs.get("organization")
    
    async def call(self, prompt: str, **kwargs) -> str:
        start_time = time.time()
        
        # Log the API call details
        logger.info(f" Making API call to OpenAI")
        logger.info(f"   Model: {self.model}")
        logger.info(f"   Base URL: {self.base_url}")
        logger.info(f"   API Key: {self.api_key[:10]}...{self.api_key[-4:]}")
        logger.info(f"   Organization: {self.organization}")
        logger.info(f"   Prompt length: {len(prompt)} characters")
        
        try:
            import openai
            
            client = openai.AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                organization=self.organization
            )
            
            response = await client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=kwargs.get("max_tokens", config.llm.max_tokens),
                temperature=kwargs.get("temperature", config.llm.temperature),
                **self.extra_params
            )
            
            # Log successful response
            response_time = time.time() - start_time
            response_text = response.choices[0].message.content
            
            logger.info(f" OpenAI API call successful")
            logger.info(f"   Response time: {response_time:.2f}s")
            logger.info(f"   Response length: {len(response_text)} characters")
            logger.info(f"   Usage: {response.usage}")
            
            return response_text
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f" OpenAI API call failed after {response_time:.2f}s")
            logger.error(f"   Error: {str(e)}")
            raise
    
    def validate_config(self) -> bool:
        return (
            self.api_key and 
            len(self.api_key.strip()) > 10 and
            self.api_key.startswith("sk-")
        )


class AnthropicProvider(BaseLLMProvider):
    """Anthropic provider implementation with detailed logging"""
    
    async def call(self, prompt: str, **kwargs) -> str:
        start_time = time.time()
        
        logger.info(f" Making API call to Anthropic")
        logger.info(f"   Model: {self.model}")
        logger.info(f"   API Key: {self.api_key[:10]}...{self.api_key[-4:]}")
        logger.info(f"   Prompt length: {len(prompt)} characters")
        
        try:
            import anthropic
            
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            
            response = await client.messages.create(
                model=self.model,
                max_tokens=kwargs.get("max_tokens", config.llm.max_tokens),
                temperature=kwargs.get("temperature", config.llm.temperature),
                messages=[{"role": "user", "content": prompt}],
                **self.extra_params
            )
            
            response_time = time.time() - start_time
            response_text = response.content[0].text
            
            logger.info(f" Anthropic API call successful")
            logger.info(f"   Response time: {response_time:.2f}s")
            logger.info(f"   Response length: {len(response_text)} characters")
            logger.info(f"   Usage: {response.usage}")
            
            return response_text
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f" Anthropic API call failed after {response_time:.2f}s")
            logger.error(f"   Error: {str(e)}")
            raise
    
    def validate_config(self) -> bool:
        return (
            self.api_key and 
            len(self.api_key.strip()) > 10 and
            self.api_key.startswith("sk-ant-")
        )


class UniversalLLMClient:
    """Universal LLM client supporting multiple providers with detailed logging"""
    
    # Registry of supported providers
    PROVIDERS = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "groq": GroqProvider,
        # Add other providers as needed
    }
    
    def __init__(self, provider_config: Optional[Dict[str, Any]] = None):
        """
        Initialize universal LLM client with logging
        
        Args:
            provider_config: Optional provider configuration override
        """
        if provider_config:
            self.provider_name = provider_config["provider"]
            self.api_key = provider_config["api_key"]
            self.model = provider_config["model"]
            self.extra_config = provider_config.get("config", {})
        else:
            # Use global config
            if not config.has_llm_configured:
                raise ValueError("LLM must be configured. Set LLM_PROVIDER and API key in .env")
            
            self.provider_name = config.llm.provider.lower()
            self.api_key = config.llm.api_key
            self.model = config.llm.model
            self.extra_config = {}
        
        # Log initialization
        logger.info(f" Initializing LLM client")
        logger.info(f"   Provider: {self.provider_name}")
        logger.info(f"   Model: {self.model}")
        logger.info(f"   API Key configured: {bool(self.api_key)}")
        logger.info(f"   API Key preview: {self.api_key[:10]}...{self.api_key[-4:] if self.api_key else 'None'}")
        
        # Initialize provider
        self.provider = self._create_provider()
        
        # Validate configuration
        if not self.provider.validate_config():
            logger.error(f" Invalid configuration for {self.provider_name} provider")
            raise ValueError(f"Invalid configuration for {self.provider_name} provider")
        
        logger.info(f" Universal LLM client ready: {self.provider_name} ({self.model})")
    
    def _create_provider(self) -> BaseLLMProvider:
        """Create provider instance based on configuration"""
        
        if self.provider_name not in self.PROVIDERS:
            logger.warning(f" Unknown provider '{self.provider_name}', available: {list(self.PROVIDERS.keys())}")
            raise ValueError(f"Unsupported provider: {self.provider_name}")
        
        provider_class = self.PROVIDERS[self.provider_name]
        return provider_class(
            api_key=self.api_key,
            model=self.model,
            **self.extra_config
        )
    
    async def call(self, prompt: str, **kwargs) -> str:
        """Call LLM and return response with detailed logging"""
        logger.info(f" LLM Call initiated")
        logger.info(f"   Provider: {self.provider_name}")
        logger.info(f"   Model: {self.model}")
        
        start_time = time.time()
        try:
            response = await self.provider.call(prompt, **kwargs)
            total_time = time.time() - start_time
            logger.info(f" LLM Call completed in {total_time:.2f}s")
            return response
        except Exception as e:
            total_time = time.time() - start_time
            logger.error(f" LLM Call failed after {total_time:.2f}s: {e}")
            raise
    
    @classmethod
    def create_from_config(
        cls, 
        provider: str, 
        api_key: str, 
        model: str, 
        **extra_config
    ) -> "UniversalLLMClient":
        """Create client from explicit configuration"""
        provider_config = {
            "provider": provider,
            "api_key": api_key,
            "model": model,
            "config": extra_config
        }
        
        return cls(provider_config)
    
    @classmethod
    def get_supported_providers(cls) -> List[str]:
        """Get list of supported provider names"""
        return list(cls.PROVIDERS.keys())
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about current provider"""
        return {
            "provider": self.provider_name,
            "model": self.model,
            "api_key_configured": bool(self.api_key),
            "api_key_preview": f"{self.api_key[:10]}...{self.api_key[-4:]}" if self.api_key else None,
            "extra_config": self.extra_config
        }


class MockLLMClient:
    """Mock LLM client for testing without API keys"""
    
    def __init__(self):
        self.provider_name = "mock"
        self.model = "mock-model"
        logger.info(" Using mock LLM client for testing")
    
    async def call(self, prompt: str, **kwargs) -> str:
        """Return mock LLM response with logging"""
        logger.info(f" Mock LLM call")
        logger.info(f"   Prompt length: {len(prompt)} characters")
        logger.info(f"   Simulating API delay...")
        
        await asyncio.sleep(0.1)  # Simulate API delay
        
        # Return different mock responses based on prompt content
        if "role_understanding" in prompt.lower() or "step 1" in prompt:
            response = """{
                "role_identity": {
                    "name": "test-role",
                    "namespace": "default",
                    "inferred_purpose": "Mock analysis for testing",
                    "scope_assessment": "narrow"
                },
                "permission_structure": [
                    {
                        "rule_index": 0,
                        "api_groups": [""],
                        "resources": ["pods"],
                        "verbs": ["get", "list", "watch"],
                        "resource_scope": "specific",
                        "verb_scope": "read-only"
                    }
                ],
                "initial_security_observations": ["Mock security analysis"]
            }"""
        
        elif "permission_analysis" in prompt.lower() or "step 2" in prompt:
            response = """{
                "excessive_permissions": [],
                "privilege_escalation_risks": [],
                "sensitive_resource_exposure": [],
                "security_score": 85,
                "critical_issues": []
            }"""
        
        elif "runtime_correlation" in prompt.lower() or "step 3" in prompt:
            response = """{
                "usage_analysis": {
                    "actively_used_permissions": [
                        {"permission": "get:pods", "frequency": "high"}
                    ]
                },
                "over_privilege_assessment": {"severity": "low"},
                "usage_recommendations": ["Monitor usage patterns"]
            }"""
        
        elif "risk_assessment" in prompt.lower() or "step 4" in prompt:
            response = """{
                "overall_risk_assessment": {
                    "security_score": 85,
                    "risk_level": "low",
                    "confidence": "high"
                },
                "risk_breakdown": {"immediate_risks": []},
                "compliance_issues": []
            }"""
        
        elif "recommendation" in prompt.lower() or "step 5" in prompt:
            response = """{
                "immediate_actions": [
                    {"action": "continue_monitoring", "priority": "low"}
                ],
                "monitoring_recommendations": ["Regular security reviews"],
                "implementation_plan": [
                    {"step": 1, "action": "No changes needed"}
                ]
            }"""
        
        else:
            response = '{"mock_response": "Mock LLM analysis completed"}'
        
        logger.info(f" Mock response generated ({len(response)} characters)")
        logger.debug(f"   Mock response preview: {response[:100]}...")
        
        return response
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get mock provider info"""
        return {
            "provider": "mock",
            "model": "mock-model",
            "api_key_configured": False,
            "mock": True
        }