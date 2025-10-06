#!/usr/bin/env python3
"""
KubeGuard Hybrid Server
Combines FastMCP server with HTTP API for web access
"""
import uvicorn
import json
import logging
from typing import Any, Dict, List, Optional
import asyncio
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from fastmcp import FastMCP
from .analyzer import KubeGuardRoleAnalyzer
from .config import config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.server.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("kubeguard-hybrid")

# Initialize FastMCP for MCP protocol
mcp = FastMCP(config.server.name)

# Initialize FastAPI for HTTP endpoints
app = FastAPI(
    title="KubeGuard Security Analyzer",
    description="Kubernetes RBAC security analysis via HTTP API and MCP protocol",
    version=config.server.version
)

# Add CORS middleware for web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for HTTP API
class AnalyzeRoleRequest(BaseModel):
    """HTTP request model for role analysis"""
    role_manifest: Dict[str, Any] = Field(..., description="Kubernetes Role manifest")
    runtime_logs: List[str] = Field(default=[], description="Optional audit logs")

class ValidateRoleRequest(BaseModel):
    """HTTP request model for role validation"""
    role_manifest: Dict[str, Any] = Field(..., description="Kubernetes Role manifest")
    security_threshold: float = Field(default=70, description="Security score threshold")

class ChatRequest(BaseModel):
    """HTTP request model for chat-like interactions"""
    message: str = Field(..., description="User message")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional context")

class ServerStatus(BaseModel):
    """Server status response"""
    status: str
    mcp_enabled: bool
    http_enabled: bool
    llm_configured: bool
    llm_provider: str
    llm_model: str
    available_tools: List[str]

# Shared analyzer instance
analyzer = None

def get_analyzer():
    """Get or create analyzer instance"""
    global analyzer
    if analyzer is None:
        analyzer = KubeGuardRoleAnalyzer()
    return analyzer

def validate_llm_setup():
    """Ensure LLM is configured for analysis"""
    if not config.llm.provider or config.llm.provider == "none":
        raise HTTPException(
            status_code=503,
            detail="LLM not configured. Set LLM_PROVIDER and API key in environment."
        )

# HTTP API Endpoints
@app.get("/", response_class=HTMLResponse)
async def serve_web_interface():
    """Serve the web interface"""
    # You can return the HTML content here or serve static files
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>KubeGuard Web Interface</title>
    </head>
    <body>
        <h1>KubeGuard Security Analyzer</h1>
        <p>HTTP API is running. Use /docs for API documentation.</p>
        <p>Available endpoints:</p>
        <ul>
            <li><a href="/docs">/docs - API Documentation</a></li>
            <li><a href="/api/status">/api/status - Server Status</a></li>
            <li>POST /api/analyze - Analyze Role</li>
            <li>POST /api/chat - Chat Interface</li>
        </ul>
    </body>
    </html>
    """

@app.get("/api/status", response_model=ServerStatus)
async def get_server_status():
    """Get server status and capabilities"""
    return ServerStatus(
        status="running",
        mcp_enabled=True,
        http_enabled=True,
        llm_configured=bool(config.llm.provider and config.llm.provider != "none"),
        llm_provider=config.llm.provider,
        llm_model=config.llm.model,
        available_tools=[
            "analyze_role_security",
            "generate_hardened_role", 
            "validate_role_security",
            "get_llm_status"
        ]
    )

@app.post("/api/analyze")
async def analyze_role_http(request: AnalyzeRoleRequest):
    """HTTP endpoint for role analysis"""
    try:
        validate_llm_setup()
        
        analyzer = get_analyzer()
        role_name = request.role_manifest.get('metadata', {}).get('name', 'unknown')
        
        logger.info(f"HTTP: Analyzing role {role_name}")
        
        # Perform analysis
        analysis = await analyzer.analyze_role(request.role_manifest, request.runtime_logs)
        
        # Format response
        return {
            "success": True,
            "analysis_method": "llm_chain",
            "role_security_analysis": analysis.to_dict(),
            "summary": {
                "role_name": analysis.role_name,
                "namespace": analysis.namespace,
                "security_score": analysis.security_score,
                "risk_level": analysis.risk_level.value,
                "total_issues": len(analysis.security_issues),
                "critical_issues": len([i for i in analysis.security_issues if i.risk_level.value == "critical"]),
                "recommendations_count": len(analysis.recommendations)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"HTTP analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate-hardened")
async def generate_hardened_role_http(request: AnalyzeRoleRequest):
    """HTTP endpoint for generating hardened roles"""
    try:
        validate_llm_setup()
        
        analyzer = get_analyzer()
        
        # First analyze the role
        analysis = await analyzer.analyze_role(request.role_manifest, request.runtime_logs)
        
        # Generate hardened version
        hardened_result = analyzer.generate_hardened_role(analysis)
        
        return {
            "success": True,
            "original_analysis": {
                "security_score": analysis.security_score,
                "risk_level": analysis.risk_level.value,
                "issues_found": len(analysis.security_issues)
            },
            "hardened_role": hardened_result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"HTTP hardened role generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/validate")
async def validate_role_http(request: ValidateRoleRequest):
    """HTTP endpoint for role validation"""
    try:
        validate_llm_setup()
        
        analyzer = get_analyzer()
        
        # Analyze role
        analysis = await analyzer.analyze_role(request.role_manifest)
        
        # Perform validation
        is_secure = analysis.security_score >= request.security_threshold
        
        return {
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
            "priority_recommendations": analysis.recommendations[:5]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"HTTP validation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/chat")
async def chat_interface(request: ChatRequest):
    """HTTP endpoint for chat-like interactions"""
    try:
        message = request.message.lower()
        
        # Route message to appropriate analysis
        if "analyze" in message or "security" in message:
            if request.context and "role_manifest" in request.context:
                # Analyze provided role
                analyze_req = AnalyzeRoleRequest(
                    role_manifest=request.context["role_manifest"],
                    runtime_logs=request.context.get("runtime_logs", [])
                )
                result = await analyze_role_http(analyze_req)
                
                return {
                    "response": f"I've analyzed the Kubernetes Role. Security score: {result['summary']['security_score']}/100 ({result['summary']['risk_level']} risk). Found {result['summary']['total_issues']} security issues.",
                    "analysis_result": result,
                    "suggestions": [
                        "Would you like me to generate a hardened version?",
                        "Do you want details about the security issues found?",
                        "Should I explain the security implications?"
                    ]
                }
            else:
                return {
                    "response": "I can analyze Kubernetes Roles for security issues. Please provide a Role manifest in the context or upload a YAML file.",
                    "suggestions": [
                        "Upload a Kubernetes Role YAML file",
                        "Paste a Role configuration in the chat",
                        "Ask me about Kubernetes security best practices"
                    ]
                }
        
        elif "status" in message:
            status = await get_server_status()
            return {
                "response": f"Server is {status.status}. LLM configured: {status.llm_configured} ({status.llm_provider}). Available tools: {', '.join(status.available_tools)}",
                "server_status": status.dict()
            }
        
        elif "help" in message:
            return {
                "response": "I'm KubeGuard, your Kubernetes security analyst. I can help you analyze Roles, generate hardened configurations, and validate security practices.",
                "capabilities": [
                    "Analyze Kubernetes Roles for security vulnerabilities",
                    "Generate hardened Role configurations", 
                    "Validate against security best practices",
                    "Explain security implications and risks"
                ],
                "suggestions": [
                    "Upload a Role YAML to analyze",
                    "Ask me to explain Kubernetes RBAC security",
                    "Request a security analysis of your configuration"
                ]
            }
        
        else:
            return {
                "response": "I can help you with Kubernetes RBAC security analysis. Try asking me to analyze a Role, check server status, or ask for help.",
                "suggestions": [
                    "Analyze this Role for security issues",
                    "Check server status", 
                    "Help with Kubernetes security"
                ]
            }
            
    except Exception as e:
        logger.error(f"Chat interface error: {e}")
        return {
            "response": f"Sorry, I encountered an error: {str(e)}",
            "error": True
        }

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """HTTP endpoint for file upload"""
    try:
        if not file.filename.endswith(('.yaml', '.yml', '.json')):
            raise HTTPException(status_code=400, detail="Only YAML and JSON files are supported")
        
        content = await file.read()
        
        # Try to parse as YAML/JSON
        try:
            import yaml
            role_manifest = yaml.safe_load(content.decode('utf-8'))
        except:
            try:
                role_manifest = json.loads(content.decode('utf-8'))
            except:
                raise HTTPException(status_code=400, detail="Invalid YAML/JSON format")
        
        # Validate it's a Kubernetes Role
        if not all(key in role_manifest for key in ["apiVersion", "kind", "metadata"]):
            raise HTTPException(status_code=400, detail="Not a valid Kubernetes resource")
        
        return {
            "success": True,
            "filename": file.filename,
            "role_manifest": role_manifest,
            "message": f"Successfully uploaded {file.filename}. Ready for analysis."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/guided-prompts")
async def get_guided_prompts():
    """HTTP endpoint for guided prompts"""
    return {
        "prompts": [
            {
                "title": "Security Analysis",
                "prompt": "Analyze this Kubernetes Role for security vulnerabilities",
                "description": "Comprehensive security scan with risk assessment",
                "requires_file": True,
                "example": "Analyze the uploaded Role for potential security issues"
            },
            {
                "title": "Generate Hardened Role",
                "prompt": "Generate a hardened version of this Role configuration",
                "description": "Create a minimal privilege version following security best practices",
                "requires_file": True,
                "example": "Create a secure version of this Role with minimal permissions"
            },
            {
                "title": "Best Practices Validation",
                "prompt": "Validate this Role against Kubernetes security best practices",
                "description": "Check compliance with security standards and guidelines",
                "requires_file": True,
                "example": "Check if this Role follows security best practices"
            },
            {
                "title": "Risk Assessment",
                "prompt": "What are the security risks if this Role is compromised?",
                "description": "Evaluate potential attack vectors and blast radius",
                "requires_file": True,
                "example": "Assess the security impact if this Role is compromised"
            },
            {
                "title": "Permission Explanation",
                "prompt": "Explain the security implications of these permissions",
                "description": "Detailed breakdown of what each permission allows",
                "requires_file": True,
                "example": "Explain what security risks these permissions introduce"
            }
        ]
    }

# MCP Tools (keep existing ones)
@mcp.tool()
async def analyze_role_security(request: AnalyzeRoleRequest) -> Dict[str, Any]:
    """MCP tool for role analysis"""
    # Use the same logic as HTTP endpoint
    http_result = await analyze_role_http(request)
    return http_result

@mcp.tool()
async def generate_hardened_role(request: AnalyzeRoleRequest) -> Dict[str, Any]:
    """MCP tool for hardened role generation"""
    http_result = await generate_hardened_role_http(request)
    return http_result

@mcp.tool()
async def validate_role_security(request: ValidateRoleRequest) -> Dict[str, Any]:
    """MCP tool for role validation"""
    http_result = await validate_role_http(request)
    return http_result

@mcp.tool()
async def get_llm_status() -> Dict[str, Any]:
    """MCP tool for server status"""
    status = await get_server_status()
    return status.dict()

# MCP Resources
@mcp.resource("kubeguard://methodology")
async def kubeguard_methodology() -> str:
    """KubeGuard methodology documentation"""
    return """# KubeGuard Methodology
    
## 5-Step LLM Analysis Chain
1. Role Understanding and Structure Analysis
2. Deep Permission Security Analysis  
3. Runtime Log Correlation Analysis
4. Comprehensive Risk Assessment
5. Actionable Security Recommendations

Each step builds context for comprehensive security analysis."""

@mcp.resource("kubeguard://guided-prompts") 
async def guided_prompts_resource() -> str:
    """Guided prompts for client UIs"""
    prompts = await get_guided_prompts()
    return json.dumps(prompts["prompts"])


async def run_http_api():
    logger.info("🌐 HTTP API available at http://0.0.0.0:8000  (docs: /docs)")
    cfg = uvicorn.Config(app=app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(cfg)
    await server.serve()

async def run_mcp_http():
    logger.info(f"🛰️  MCP over HTTP at http://0.0.0.0:8765")

    # Run FastMCP's event loop in a separate thread
    await asyncio.to_thread(
        mcp.run,
        host="0.0.0.0",
        port=8765,
        transport="streamable-http"
    )


async def run_stdio_mcp():
    logger.info("🔧 MCP protocol available via stdio")
    mcp.run()  # blocks; use this in a branch where you only want stdio


# Server startup
async def run_hybrid_server():
    """Run both MCP and HTTP servers"""
   
    logger.info(f"Starting KubeGuard Hybrid Server v{config.server.version}")
    
    # Validate LLM setup
    try:
        validate_llm_setup()
        logger.info(f"✅ LLM configured: {config.llm.provider} ({config.llm.model})")
    except:
        logger.warning("⚠️ LLM not configured - some features may not work")
    
    #logger.info("🔧 MCP protocol available via stdio")
    logger.info("🌐 HTTP API available at http://localhost:8000")
    logger.info("📚 MCP server is running at http://localhost:8765/mcp")
    
    # # Run HTTP server
    # config_uvicorn = uvicorn.Config(
    #     app=app,
    #     host="0.0.0.0", 
    #     port=8000,
    #     log_level="info"
    # )
    # server = uvicorn.Server(config_uvicorn)
    # await server.serve()
    # Run FastAPI + MCP/HTTP together
    await asyncio.gather(
        run_http_api(),
        run_mcp_http()
    )


if __name__ == "__main__":
    import sys
    
    # Check if running as MCP server (stdio) or HTTP server
    if len(sys.argv) > 1 and sys.argv[1] == "--http":
        # Run HTTP server
        asyncio.run(run_hybrid_server())
    else:
        # Run as MCP server
        logger.info("Starting as MCP server (stdio)")
        mcp.run()