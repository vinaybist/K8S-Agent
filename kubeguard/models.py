"""
Data models for KubeGuard analysis results
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisMethod(Enum):
    """Analysis method enumeration"""
    RULE_BASED = "rule_based"
    LLM_CHAIN = "llm_chain"
    HYBRID = "hybrid"


@dataclass
class SecurityIssue:
    """Individual security issue found in analysis"""
    issue_type: str
    description: str
    risk_level: RiskLevel
    rule_index: Optional[int] = None
    resource: Optional[str] = None
    verb: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class PermissionUsage:
    """Runtime permission usage data"""
    permission: str  # Format: "verb:resource"
    frequency: int
    last_used: Optional[datetime] = None
    first_used: Optional[datetime] = None
    is_excessive: bool = False


@dataclass
class RoleAnalysis:
    """Complete analysis results for a Kubernetes Role"""
    # Basic role information
    role_name: str
    namespace: str
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    analysis_method: AnalysisMethod = AnalysisMethod.RULE_BASED
    
    # Permission structure
    permissions: List[Dict[str, Any]] = field(default_factory=list)
    total_permissions: int = 0
    
    # Security assessment
    security_score: float = 0.0  # 0-100 scale
    risk_level: RiskLevel = RiskLevel.MEDIUM
    security_issues: List[SecurityIssue] = field(default_factory=list)
    excessive_permissions: List[str] = field(default_factory=list)
    
    # Runtime analysis
    runtime_usage: Dict[str, PermissionUsage] = field(default_factory=dict)
    unused_permissions: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    priority_actions: List[str] = field(default_factory=list)
    
    # LLM chain results (if applicable)
    llm_chain_results: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Calculate derived fields after initialization"""
        self.total_permissions = len(self.permissions)
        self.risk_level = self._calculate_risk_level()
    
    def _calculate_risk_level(self) -> RiskLevel:
        """Calculate risk level based on security score"""
        if self.security_score >= 80:
            return RiskLevel.LOW
        elif self.security_score >= 60:
            return RiskLevel.MEDIUM
        elif self.security_score >= 40:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "role_name": self.role_name,
            "namespace": self.namespace,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "analysis_method": self.analysis_method.value,
            "permissions": self.permissions,
            "total_permissions": self.total_permissions,
            "security_score": self.security_score,
            "risk_level": self.risk_level.value,
            "security_issues": [
                {
                    "issue_type": issue.issue_type,
                    "description": issue.description,
                    "risk_level": issue.risk_level.value,
                    "rule_index": issue.rule_index,
                    "resource": issue.resource,
                    "verb": issue.verb,
                    "recommendation": issue.recommendation
                }
                for issue in self.security_issues
            ],
            "excessive_permissions": self.excessive_permissions,
            "runtime_usage": {
                k: {
                    "permission": v.permission,
                    "frequency": v.frequency,
                    "last_used": v.last_used.isoformat() if v.last_used else None,
                    "first_used": v.first_used.isoformat() if v.first_used else None,
                    "is_excessive": v.is_excessive
                }
                for k, v in self.runtime_usage.items()
            },
            "unused_permissions": self.unused_permissions,
            "recommendations": self.recommendations,
            "priority_actions": self.priority_actions,
            "llm_chain_results": self.llm_chain_results
        }


@dataclass
class HardenedRole:
    """Hardened role configuration result"""
    original_role_name: str
    hardened_role_manifest: Dict[str, Any]
    improvements: List[str]
    removed_permissions: List[str]
    security_score_improvement: float
    validation_passed: bool = True
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "original_role_name": self.original_role_name,
            "hardened_role_manifest": self.hardened_role_manifest,
            "improvements": self.improvements,
            "removed_permissions": self.removed_permissions,
            "security_score_improvement": self.security_score_improvement,
            "validation_passed": self.validation_passed,
            "warnings": self.warnings
        }