"""
KubeGuard MCP Server
LLM-Assisted Kubernetes Role Security Analysis

Based on the KubeGuard paper: "LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis"
"""
__version__ = "1.0.0"
__description__ = "MCP server for Kubernetes Role security analysis using LLM prompt chaining"

from .models import RoleAnalysis
from .analyzer import KubeGuardRoleAnalyzer
from .config import Config
__all__ = ["RoleAnalysis", "KubeGuardRoleAnalyzer", "Config"]