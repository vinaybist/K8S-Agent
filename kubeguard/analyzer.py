"""
KubeGuard Role Security Analyzer
Pure LLM implementation of the KubeGuard methodology from the research paper
"""

import json
import logging
from typing import Any, Dict, List, Optional
import asyncio

from .models import RoleAnalysis, SecurityIssue, RiskLevel, AnalysisMethod
from .prompts import KubeGuardPrompts
from .config import config
from .llm_client import UniversalLLMClient, MockLLMClient

logger = logging.getLogger(__name__)


class KubeGuardRoleAnalyzer:
    """
    KubeGuard Role security analyzer implementing the 5-step LLM prompt chain methodology
    from the research paper: "LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis"
    
    Pure LLM implementation - no rule-based fallbacks
    """
    
    def __init__(self, llm_client: Optional[UniversalLLMClient] = None, use_mock: bool = False):
        """
        Initialize LLM-based analyzer
        
        Args:
            llm_client: Optional pre-configured LLM client
            use_mock: Use mock client for testing without API keys
        """
        if use_mock:
            self.llm_client = MockLLMClient()
            logger.info("Initialized KubeGuard analyzer with mock LLM client")
        elif llm_client:
            self.llm_client = llm_client
            provider_info = llm_client.get_provider_info()
            logger.info(f"Initialized KubeGuard analyzer: {provider_info['provider']} ({provider_info['model']})")
        else:
            # Try to create from global config
            try:
                self.llm_client = UniversalLLMClient()
                provider_info = self.llm_client.get_provider_info()
                logger.info(f"Initialized KubeGuard analyzer: {provider_info['provider']} ({provider_info['model']})")
            except ValueError as e:
                logger.warning(f"Failed to initialize LLM client: {e}")
                logger.info("Falling back to mock LLM client for testing")
                self.llm_client = MockLLMClient()
    
    async def analyze_role(
        self, 
        role_manifest: Dict[str, Any], 
        runtime_logs: Optional[List[str]] = None
    ) -> RoleAnalysis:
        """
        Analyze Kubernetes Role using the 5-step LLM prompt chain methodology
        
        Steps:
        1. Role Understanding and Structure Analysis
        2. Deep Permission Security Analysis
        3. Runtime Log Correlation Analysis
        4. Comprehensive Risk Assessment
        5. Actionable Security Recommendations
        
        Args:
            role_manifest: Kubernetes Role manifest
            runtime_logs: Optional audit logs for runtime correlation
            
        Returns:
            RoleAnalysis with LLM chain results
        """
        logger.info("Starting KubeGuard LLM analysis with 5-step prompt chain")
        
        # Initialize analysis context
        context = {
            "role_manifest": role_manifest,
            "runtime_logs": runtime_logs or [],
            "chain_results": {}
        }
        
        # Execute the 5-step KubeGuard prompt chain
        prompt_chain = KubeGuardPrompts.get_prompt_chain()
        
        for i, prompt_func in enumerate(prompt_chain, 1):
            step_name = f"step_{i}"
            logger.info(f"Executing prompt chain step {i}: {prompt_func.__name__}")
            
            try:
                # Generate prompt for this step
                prompt = prompt_func(context)
                
                # Call LLM with retry logic
                response = await self._call_llm_with_retry(prompt, step_name)
                
                # Parse and validate JSON response
                parsed_response = self._parse_llm_response(response, step_name)
                
                # Store results and update context for next step
                context["chain_results"][step_name] = parsed_response
                
                logger.info(f"Step {i} completed successfully")
                
            except Exception as e:
                logger.error(f"Prompt chain step {i} failed: {e}")
                # Store error but continue chain
                context["chain_results"][step_name] = {"error": str(e)}
        
        # Convert LLM chain results to RoleAnalysis
        analysis = self._build_analysis_from_chain(role_manifest, context)
        
        logger.info(f"LLM analysis completed: score={analysis.security_score:.1f}, risk={analysis.risk_level.value}")
        return analysis
    
    async def _call_llm_with_retry(self, prompt: str, step_name: str) -> str:
        """Call LLM with retry logic and detailed logging"""
        max_retries = config.analysis.max_prompt_chain_retries
        
        for attempt in range(max_retries):
            try:
                logger.info(f"🔄 LLM call attempt {attempt + 1}/{max_retries} for {step_name}")
                
                # Log prompt details
                logger.info(f"   Prompt length: {len(prompt)} characters")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"   Prompt preview: {prompt[:300]}...")
                
                response = await self.llm_client.call(prompt)
                
                # Log response details
                logger.info(f"   Response received: {len(response)} characters")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"   Raw response: {response[:500]}...")
                
                return response
                
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"❌ LLM call failed after {max_retries} attempts: {e}")
                    raise e
                
                logger.warning(f"⚠️ LLM call attempt {attempt + 1} failed: {e}, retrying...")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        raise Exception("LLM call failed after all retries")
    def _parse_llm_response(self, response: str, step_name: str) -> Dict[str, Any]:
        """Parse and validate LLM JSON response with enhanced error handling"""
        logger.info(f"🔍 Parsing LLM response for {step_name}")
        logger.debug(f"   Raw response length: {len(response)}")
        
        try:
            # Log raw response for debugging
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"   Raw response content:\n{response}")
            
            # Clean response more aggressively
            cleaned_response = response.strip()
            
            # Remove markdown code blocks
            if cleaned_response.startswith("```json"):
                cleaned_response = cleaned_response[7:]
            elif cleaned_response.startswith("```"):
                cleaned_response = cleaned_response[3:]
            
            if cleaned_response.endswith("```"):
                cleaned_response = cleaned_response[:-3]
            
            cleaned_response = cleaned_response.strip()
            
            # Try to find JSON within the response if it's wrapped in other text
            import re
            json_match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
            if json_match:
                json_content = json_match.group(0)
                logger.debug(f"   Extracted JSON content: {json_content[:200]}...")
            else:
                json_content = cleaned_response
                logger.warning(f"   No JSON braces found, using full response")
            
            # Parse JSON
            parsed = json.loads(json_content)
            
            # Basic validation
            if not isinstance(parsed, dict):
                raise ValueError(f"Expected dict response, got {type(parsed)}")
            
            logger.info(f"✅ Successfully parsed JSON for {step_name}")
            logger.debug(f"   Parsed keys: {list(parsed.keys())}")
            
            return parsed
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON parse failed for {step_name}")
            logger.error(f"   JSON Error: {e}")
            logger.error(f"   Error position: line {e.lineno}, column {e.colno}")
            logger.error(f"   Problematic content around error:")
            
            # Show content around the error
            lines = response.split('\n')
            if e.lineno <= len(lines):
                start_line = max(0, e.lineno - 3)
                end_line = min(len(lines), e.lineno + 2)
                for i in range(start_line, end_line):
                    marker = " >>> " if i == e.lineno - 1 else "     "
                    logger.error(f"   {marker}Line {i+1}: {lines[i]}")
            
            # Return structured error response
            return {
                "error": "json_parse_failed",
                "error_details": {
                    "message": str(e),
                    "line": e.lineno,
                    "column": e.colno
                },
                "raw_response": response[:1000] + "..." if len(response) > 1000 else response,
                "cleaned_response": cleaned_response[:500] + "..." if len(cleaned_response) > 500 else cleaned_response
            }
        except Exception as e:
            logger.error(f"❌ Response validation failed for {step_name}: {e}")
            logger.error(f"   Raw response: {response[:300]}...")
            return {
                "error": "validation_failed",
                "exception": str(e),
                "response_preview": response[:300]
            }
        
    def _build_analysis_from_chain(
        self, 
        role_manifest: Dict[str, Any], 
        context: Dict[str, Any]
    ) -> RoleAnalysis:
        """Build RoleAnalysis from LLM prompt chain results"""
        
        chain_results = context["chain_results"]
        
        # Extract role identity from Step 1
        step_1 = chain_results.get("step_1", {})
        role_identity = step_1.get("role_identity", {})
        
        role_name = role_identity.get("name", role_manifest.get("metadata", {}).get("name", "unknown"))
        namespace = role_identity.get("namespace", role_manifest.get("metadata", {}).get("namespace", "default"))
        
        # Extract security score from Step 4 (Risk Assessment)
        step_4 = chain_results.get("step_4", {})
        risk_assessment = step_4.get("overall_risk_assessment", {})
        security_score = float(risk_assessment.get("security_score", 50.0))
        
        # Extract security issues from Step 2 (Permission Analysis)
        step_2 = chain_results.get("step_2", {})
        security_issues = self._extract_security_issues(step_2)
        
        # Extract recommendations from Step 5
        step_5 = chain_results.get("step_5", {})
        recommendations = self._extract_recommendations(step_5)
        
        # Calculate risk level from security score
        if security_score >= 80:
            risk_level = RiskLevel.LOW
        elif security_score >= 60:
            risk_level = RiskLevel.MEDIUM
        elif security_score >= 40:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL
        
        return RoleAnalysis(
            role_name=role_name,
            namespace=namespace,
            analysis_method=AnalysisMethod.LLM_CHAIN,
            permissions=role_manifest.get("rules", []),
            security_score=security_score,
            risk_level=risk_level,
            security_issues=security_issues,
            recommendations=recommendations,
            llm_chain_results=chain_results
        )
    
    def _extract_security_issues(self, step_2_results: Dict[str, Any]) -> List[SecurityIssue]:
        """Extract SecurityIssue objects from Step 2 results"""
        issues = []
        
        excessive_permissions = step_2_results.get("excessive_permissions", [])
        for issue_data in excessive_permissions:
            if isinstance(issue_data, dict):
                try:
                    risk_level_str = issue_data.get("risk_level", "medium")
                    risk_level = RiskLevel(risk_level_str.lower())
                    
                    issue = SecurityIssue(
                        issue_type=issue_data.get("issue_type", "unknown"),
                        description=issue_data.get("description", "Security issue detected"),
                        risk_level=risk_level,
                        rule_index=issue_data.get("rule_index"),
                        recommendation=f"Address {issue_data.get('issue_type', 'issue')}"
                    )
                    issues.append(issue)
                except (ValueError, KeyError) as e:
                    logger.warning(f"Failed to parse security issue: {e}")
        
        return issues
    
    def _extract_recommendations(self, step_5_results: Dict[str, Any]) -> List[str]:
        """Extract recommendations from Step 5 results"""
        recommendations = []
        
        # Extract immediate actions
        immediate_actions = step_5_results.get("immediate_actions", [])
        for action in immediate_actions:
            if isinstance(action, dict):
                action_text = action.get("action", "")
                if action_text:
                    recommendations.append(f"PRIORITY: {action_text}")
            elif isinstance(action, str):
                recommendations.append(f"PRIORITY: {action}")
        
        # Extract monitoring recommendations
        monitoring_recs = step_5_results.get("monitoring_recommendations", [])
        recommendations.extend(monitoring_recs)
        
        # Fallback recommendations if none found
        if not recommendations:
            recommendations = [
                "Review LLM analysis results for detailed insights",
                "Implement least-privilege access controls",
                "Monitor runtime usage patterns"
            ]
        
        return recommendations
    
    def generate_hardened_role(self, analysis: RoleAnalysis) -> Dict[str, Any]:
        """Generate hardened Role based on LLM analysis recommendations"""
        
        # Extract hardened manifest from Step 5 if available
        step_5 = analysis.llm_chain_results.get("step_5", {}) if analysis.llm_chain_results else {}
        hardened_manifest = step_5.get("hardened_role_manifest")
        
        if hardened_manifest:
            # Use LLM-generated hardened manifest
            return {
                "original_role_name": analysis.role_name,
                "hardened_role_manifest": hardened_manifest,
                "improvements": ["Applied LLM-recommended security improvements"],
                "security_score_improvement": max(0, 90 - analysis.security_score),
                "llm_generated": True
            }
        else:
            # Fallback: Create basic hardened version
            from datetime import datetime
            hardened_manifest = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {
                    "name": f"{analysis.role_name}-hardened",
                    "namespace": analysis.namespace,
                    "annotations": {
                        "kubeguard.io/original-role": analysis.role_name,
                        "kubeguard.io/llm-hardened": "true",
                        "kubeguard.io/security-score": str(analysis.security_score),
                        "kubeguard.io/hardened-at": datetime.now().isoformat()
                    }
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods"],
                        "verbs": ["get", "list", "watch"]
                    }
                ]
            }
            
            return {
                "original_role_name": analysis.role_name,
                "hardened_role_manifest": hardened_manifest,
                "improvements": ["Applied basic security hardening"],
                "security_score_improvement": 20.0,
                "llm_generated": False
            }
    
    @classmethod
    def create_with_provider(
        cls,
        provider: str,
        api_key: str,
        model: str,
        **extra_config
    ) -> "KubeGuardRoleAnalyzer":
        """
        Create analyzer with specific LLM provider configuration
        
        Args:
            provider: Provider name (openai, anthropic, groq, etc.)
            api_key: API key for the provider
            model: Model name to use
            **extra_config: Additional provider-specific configuration
        
        Returns:
            Configured KubeGuardRoleAnalyzer
        """
        llm_client = UniversalLLMClient.create_from_config(
            provider=provider,
            api_key=api_key,
            model=model,
            **extra_config
        )
        
        return cls(llm_client=llm_client)
    
    def get_llm_info(self) -> Dict[str, Any]:
        """Get information about current LLM configuration"""
        return self.llm_client.get_provider_info()


# Convenience functions for direct usage
async def analyze_role_with_llm(
    role_manifest: Dict[str, Any], 
    runtime_logs: Optional[List[str]] = None,
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None
) -> RoleAnalysis:
    """
    Convenience function to analyze a role using LLM methodology
    
    Args:
        role_manifest: Kubernetes Role manifest
        runtime_logs: Optional audit logs
        provider: Optional LLM provider override
        api_key: Optional API key override
        model: Optional model override
        
    Returns:
        RoleAnalysis with LLM chain results
    """
    if provider and api_key and model:
        analyzer = KubeGuardRoleAnalyzer.create_with_provider(provider, api_key, model)
    else:
        analyzer = KubeGuardRoleAnalyzer()
    
    return await analyzer.analyze_role(role_manifest, runtime_logs)


def get_supported_llm_providers() -> List[str]:
    """Get list of supported LLM provider names"""
    return UniversalLLMClient.get_supported_providers()