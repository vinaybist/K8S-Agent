#!/usr/bin/env python3
"""
KubeGuard FastMCP Server
Pure LLM implementation of the KubeGuard research paper methodology
"""

import json
import logging
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from .analyzer import KubeGuardRoleAnalyzer
from .config import config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.server.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("kubeguard-fastmcp")

# Initialize FastMCP server
mcp = FastMCP(config.server.name)


# Pydantic models for type safety
class AnalyzeRoleRequest(BaseModel):
    """Request model for role analysis"""
    role_manifest: Dict[str, Any] = Field(..., description="Kubernetes Role manifest in JSON format")
    runtime_logs: List[str] = Field(default=[], description="Optional Kubernetes audit logs for runtime analysis")


class ValidateRoleRequest(BaseModel):
    """Request model for role validation"""
    role_manifest: Dict[str, Any] = Field(..., description="Kubernetes Role manifest to validate")
    security_threshold: float = Field(default=70, description="Minimum security score threshold (0-100)")


class RiskAssessmentRequest(BaseModel):
    """Request model for focused risk assessment"""
    role_manifest: Dict[str, Any] = Field(..., description="Kubernetes Role manifest")
    focus_areas: List[str] = Field(default=[], description="Specific areas to focus on")


# Validate LLM configuration
def validate_llm_setup():
    """Ensure LLM is configured for KubeGuard analysis"""
    if not config.has_llm_configured:
        raise ValueError(
            "KubeGuard requires LLM configuration. "
            "Set LLM_PROVIDER (openai/anthropic) and API key in .env file."
        )


# FastMCP Tools
@mcp.tool()
async def analyze_role_security(request: AnalyzeRoleRequest) -> Dict[str, Any]:
    """
    Analyze Kubernetes Role using KubeGuard's 5-step LLM prompt chain methodology.
    
    Implements the complete research paper methodology:
    1. Role Understanding and Structure Analysis
    2. Deep Permission Security Analysis
    3. Runtime Log Correlation Analysis  
    4. Comprehensive Risk Assessment
    5. Actionable Security Recommendations
    """
    try:
        validate_llm_setup()
        
        analyzer = KubeGuardRoleAnalyzer()
        role_name = request.role_manifest.get('metadata', {}).get('name', 'unknown')
        
        logger.info(f"Analyzing role: {role_name}")
        
        # Perform LLM-based analysis
        analysis = await analyzer.analyze_role(request.role_manifest, request.runtime_logs)
        
        # Format results
        result = {
            "success": True,
            "analysis_method": "llm_chain",
            "llm_provider": config.llm.provider,
            "llm_model": config.llm.model,
            "role_security_analysis": analysis.to_dict(),
            "summary": {
                "role_name": analysis.role_name,
                "namespace": analysis.namespace,
                "security_score": analysis.security_score,
                "risk_level": analysis.risk_level.value,
                "total_issues": len(analysis.security_issues),
                "critical_issues": len([i for i in analysis.security_issues if i.risk_level.value == "critical"]),
                "recommendations_count": len(analysis.recommendations),
                "prompt_chain_completed": len(analysis.llm_chain_results) if analysis.llm_chain_results else 0
            }
        }
        
        return result
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return {
            "success": False,
            "error": "llm_not_configured",
            "message": str(e),
            "setup_instructions": [
                "Add LLM_PROVIDER=openai (or anthropic) to .env",
                "Add OPENAI_API_KEY=your_key to .env", 
                "Restart the server"
            ]
        }
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return {
            "success": False,
            "error": "analysis_failed",
            "message": str(e)
        }


@mcp.tool()
async def generate_hardened_role(request: AnalyzeRoleRequest) -> Dict[str, Any]:
    """
    Generate a hardened version of a Kubernetes Role using LLM analysis.
    
    Uses the KubeGuard prompt chain to analyze the role and generate
    an improved version following security best practices.
    """
    try:
        validate_llm_setup()
        
        analyzer = KubeGuardRoleAnalyzer()
        role_name = request.role_manifest.get('metadata', {}).get('name', 'unknown')
        
        logger.info(f"Generating hardened role for: {role_name}")
        
        # First analyze the role
        analysis = await analyzer.analyze_role(request.role_manifest, request.runtime_logs)
        
        # Generate hardened version
        hardened_result = analyzer.generate_hardened_role(analysis)
        
        result = {
            "success": True,
            "original_analysis": {
                "security_score": analysis.security_score,
                "risk_level": analysis.risk_level.value,
                "issues_found": len(analysis.security_issues)
            },
            "hardened_role": hardened_result,
            "summary": {
                "original_role": analysis.role_name,
                "hardened_role": hardened_result["hardened_role_manifest"]["metadata"]["name"],
                "security_improvement": hardened_result["security_score_improvement"],
                "llm_generated": hardened_result.get("llm_generated", False)
            }
        }
        
        return result
        
    except ValueError as e:
        return {
            "success": False,
            "error": "llm_not_configured",
            "message": str(e)
        }
    except Exception as e:
        logger.error(f"Hardened role generation failed: {e}")
        return {
            "success": False,
            "error": "generation_failed",
            "message": str(e)
        }


@mcp.tool()
async def validate_role_security(request: ValidateRoleRequest) -> Dict[str, Any]:
    """
    Validate if a Role meets security thresholds using LLM analysis.
    
    Performs comprehensive security validation against configurable standards.
    """
    try:
        validate_llm_setup()
        
        analyzer = KubeGuardRoleAnalyzer()
        role_name = request.role_manifest.get('metadata', {}).get('name', 'unknown')
        
        logger.info(f"Validating role: {role_name}")
        
        # Analyze role
        analysis = await analyzer.analyze_role(request.role_manifest)
        
        # Perform validation
        is_secure = analysis.security_score >= request.security_threshold
        validation_result = {
            "success": True,
            "validation_passed": is_secure,
            "security_score": analysis.security_score,
            "threshold": request.security_threshold,
            "status": "PASS" if is_secure else "FAIL",
            "gap": max(0, request.security_threshold - analysis.security_score),
            "critical_issues": [
                issue.description for issue in analysis.security_issues 
                if issue.risk_level.value == "critical"
            ],
            "priority_recommendations": analysis.recommendations[:5],
            "next_steps": [
                "Review critical security issues immediately" if not is_secure else "Role meets security standards",
                "Implement LLM-recommended improvements",
                "Monitor runtime usage patterns",
                "Schedule regular security reviews"
            ],
            "llm_insights": analysis.llm_chain_results
        }
        
        return validation_result
        
    except ValueError as e:
        return {
            "success": False,
            "error": "llm_not_configured",
            "message": str(e)
        }
    except Exception as e:
        logger.error(f"Role validation failed: {e}")
        return {
            "success": False,
            "error": "validation_failed",
            "message": str(e)
        }


@mcp.tool()
async def get_llm_status() -> Dict[str, Any]:
    """
    Get LLM configuration and KubeGuard server status.
    
    Returns current setup, capabilities, and readiness for analysis.
    """
    try:
        validate_llm_setup()
        
        return {
            "llm_configured": True,
            "provider": config.llm.provider,
            "model": config.llm.model,
            "server_info": {
                "name": config.server.name,
                "version": config.server.version,
                "framework": "FastMCP",
                "methodology": "KubeGuard Research Paper"
            },
            "capabilities": {
                "llm_analysis": True,
                "prompt_chain_steps": 5,
                "runtime_correlation": True,
                "hardened_role_generation": True,
                "security_validation": True
            },
            "analysis_features": [
                "Role Understanding",
                "Permission Analysis", 
                "Runtime Correlation",
                "Risk Assessment",
                "Recommendations"
            ],
            "ready_for_analysis": True
        }
        
    except ValueError as e:
        return {
            "llm_configured": False,
            "error": str(e),
            "setup_required": [
                "Set LLM_PROVIDER=openai or anthropic in .env",
                "Add OPENAI_API_KEY or ANTHROPIC_API_KEY",
                "Restart server"
            ],
            "ready_for_analysis": False
        }


# FastMCP Resources
@mcp.resource("kubeguard://methodology")
async def kubeguard_methodology() -> str:
    """KubeGuard LLM methodology from the research paper"""
    return """# KubeGuard LLM Methodology

## Research Paper Implementation
This server implements the exact methodology from:
"LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis"

## 5-Step LLM Prompt Chain

### Step 1: Role Understanding and Structure Analysis
- **Purpose**: Analyze Role structure and infer intended purpose
- **Input**: Raw Kubernetes Role manifest
- **Output**: Structured understanding of permissions, purpose, scope
- **Key Analysis**: Role identity, permission breakdown, initial observations

### Step 2: Deep Permission Security Analysis
- **Purpose**: Comprehensive security assessment of permissions
- **Input**: Step 1 results + security knowledge base
- **Output**: Security issues, excessive permissions, privilege escalation risks
- **Key Analysis**: Wildcard detection, dangerous combinations, attack vectors

### Step 3: Runtime Log Correlation Analysis
- **Purpose**: Correlate static permissions with actual usage
- **Input**: Step 1-2 results + runtime audit logs
- **Output**: Usage patterns, unused permissions, over-privilege assessment
- **Key Analysis**: Permission frequency, necessity validation, removal candidates

### Step 4: Comprehensive Risk Assessment
- **Purpose**: Synthesize overall security risk profile
- **Input**: All previous step results
- **Output**: Security score, risk factors, blast radius, compliance issues
- **Key Analysis**: Risk scoring, threat modeling, impact assessment

### Step 5: Actionable Security Recommendations
- **Purpose**: Generate specific, implementable improvements
- **Input**: Complete analysis from steps 1-4
- **Output**: Prioritized recommendations, hardened config, implementation plan
- **Key Analysis**: Action prioritization, configuration generation, monitoring guidance

## Context Building
Each step builds rich context from previous results, enabling deep analysis.

## LLM Benefits
- Contextual understanding of Role purpose
- Natural language security explanations
- Advanced threat modeling capabilities
- Nuanced risk assessment
- Research-grade analysis quality
"""


@mcp.resource("kubeguard://examples")
async def kubeguard_examples() -> str:
    """Example usage patterns for KubeGuard analysis"""
    examples = {
        "secure_role_example": {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "pod-reader", "namespace": "production"},
            "rules": [{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list", "watch"]
            }],
            "expected_analysis": {
                "security_score": "90-100",
                "risk_level": "low",
                "issues": "minimal or none",
                "recommendations": "monitoring and documentation"
            }
        },
        "risky_role_example": {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role", 
            "metadata": {"name": "dangerous-role", "namespace": "production"},
            "rules": [{
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"]
            }],
            "expected_analysis": {
                "security_score": "0-20",
                "risk_level": "critical",
                "issues": "multiple critical wildcards",
                "recommendations": "immediate remediation required"
            }
        }
    }
    return json.dumps(examples, indent=2)


if __name__ == "__main__":
    logger.info(f"Starting {config.server.name} v{config.server.version}")
    
    try:
        validate_llm_setup()
        logger.info(f"✅ LLM configured: {config.llm.provider} ({config.llm.model})")
        logger.info("🧠 KubeGuard LLM-only analysis ready")
        logger.info("🚀 Server ready for AI agent integration")
        
        mcp.run()
        
    except ValueError as e:
        logger.error(f"❌ LLM configuration required: {e}")
        logger.error("Configure LLM_PROVIDER and API key in .env file")
        exit(1)
    except Exception as e:
        logger.error(f"❌ Server startup failed: {e}")
        exit(1)
    logger.info(f"LLM Analysis: {'Enabled' if config.has_llm_configured else 'Disabled'}")
    
    mcp.run()