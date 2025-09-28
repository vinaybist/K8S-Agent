"""
KubeGuard LLM Prompt Chain Templates
Implementation of the modular prompt-chaining workflows from the KubeGuard paper
"""

import json
from typing import Dict, Any, List
from datetime import datetime


class KubeGuardPrompts:
    """KubeGuard prompt chain templates for security analysis"""
    
    @staticmethod
    def role_understanding(context: Dict[str, Any]) -> str:
        """Step 1: Role Understanding and Structure Analysis"""
        role_manifest = context["role_manifest"]
        
        return f"""You are KubeGuard, an AI security analyst specializing in Kubernetes RBAC analysis.

TASK: Analyze this Kubernetes Role and provide structured understanding of its permissions and purpose.

ROLE MANIFEST:
```yaml
{json.dumps(role_manifest, indent=2)}
```

Please analyze the Role and provide a JSON response with the following structure:

{{
    "role_identity": {{
        "name": "extracted_role_name",
        "namespace": "extracted_namespace", 
        "inferred_purpose": "description of likely use case based on permissions",
        "scope_assessment": "narrow/moderate/broad"
    }},
    "permission_structure": [
        {{
            "rule_index": 0,
            "api_groups": ["core", "apps"],
            "resources": ["pods", "deployments"],
            "verbs": ["get", "list", "create"],
            "resource_scope": "specific/wildcard",
            "verb_scope": "read-only/write/admin",
            "risk_indicators": ["wildcard_usage", "sensitive_resources"]
        }}
    ],
    "initial_security_observations": [
        "High-level security concerns identified",
        "Positive security practices noted"
    ]
}}

Focus on understanding the Role's intended purpose and identifying any obvious security concerns."""

    @staticmethod
    def permission_analysis(context: Dict[str, Any]) -> str:
        """Step 2: Deep Permission Security Analysis"""
        role_understanding = context["chain_results"].get("step_1", {})
        
        return f"""TASK: Perform comprehensive security analysis of the permissions identified in Step 1.

PREVIOUS ANALYSIS:
{json.dumps(role_understanding, indent=2)}

SECURITY ANALYSIS FRAMEWORK:
1. **Excessive Permissions**: Identify overly broad access patterns
   - Wildcard (*) usage in verbs, resources, or apiGroups
   - Access beyond apparent use case requirements
   
2. **Privilege Escalation Risks**: Assess potential for privilege escalation
   - Access to RBAC resources (roles, rolebindings, clusterroles)
   - Dangerous subresources (pods/exec, pods/portforward)
   
3. **Sensitive Resource Access**: Evaluate access to sensitive resources
   - Secrets, configmaps, serviceaccounts
   - Critical cluster resources
   
4. **Attack Surface Analysis**: Assess potential attack vectors

SECURITY KNOWLEDGE BASE:
- Wildcard (*) permissions are high risk
- pods/exec and pods/portforward enable container escape
- Access to secrets/configmaps may expose sensitive data
- Write access to RBAC objects enables privilege escalation
- Broad resource access violates least privilege principle

Provide JSON response:
{{
    "excessive_permissions": [
        {{
            "rule_index": 0,
            "issue_type": "wildcard_resource_access",
            "risk_level": "high",
            "description": "Rule grants access to all resources via wildcard",
            "affected_permissions": ["*:*"],
            "potential_impact": "Complete namespace access"
        }}
    ],
    "privilege_escalation_risks": [
        {{
            "risk_type": "rbac_modification",
            "likelihood": "medium",
            "impact": "high",
            "description": "Can modify Role/RoleBinding objects"
        }}
    ],
    "sensitive_resource_exposure": [
        "secrets", "configmaps", "serviceaccounts"
    ],
    "attack_vectors": [
        {{
            "vector": "container_escape",
            "entry_point": "pods/exec permission",
            "escalation_path": "Execute commands in any pod"
        }}
    ],
    "security_score": 45,
    "critical_issues": [
        "Wildcard permissions present",
        "Unrestricted secret access"
    ]
}}"""

    @staticmethod
    def runtime_correlation(context: Dict[str, Any]) -> str:
        """Step 3: Runtime Log Correlation Analysis"""
        permission_analysis = context["chain_results"].get("step_2", {})
        runtime_logs = context.get("runtime_logs", [])
        
        # Limit logs for prompt size management
        logs_sample = "\n".join(runtime_logs[:20]) if runtime_logs else "No runtime logs provided"
        
        return f"""TASK: Correlate static permissions with actual runtime usage patterns.

STATIC PERMISSION ANALYSIS:
{json.dumps(permission_analysis, indent=2)}

RUNTIME AUDIT LOGS SAMPLE:
```
{logs_sample}
```

CORRELATION ANALYSIS:
Analyze the gap between granted permissions and actual usage:

1. **Usage Patterns**: Which permissions are actively used?
2. **Frequency Analysis**: How often is each permission exercised?
3. **Unused Permissions**: What permissions are granted but never used?
4. **Over-Privileged Access**: Where are permissions excessive relative to usage?

For each permission, consider:
- Frequency of use (daily, weekly, never)
- Context of use (normal operations vs edge cases)
- Necessity for core functionality

Provide JSON response:
{{
    "usage_analysis": {{
        "actively_used_permissions": [
            {{
                "permission": "get:pods",
                "frequency": "high",
                "usage_pattern": "continuous_monitoring",
                "necessity": "core_functionality"
            }}
        ],
        "rarely_used_permissions": [
            {{
                "permission": "delete:configmaps", 
                "frequency": "monthly",
                "usage_pattern": "cleanup_operations",
                "necessity": "maintenance"
            }}
        ],
        "unused_permissions": [
            {{
                "permission": "create:secrets",
                "granted": true,
                "used": false,
                "recommendation": "remove"
            }}
        ]
    }},
    "over_privilege_assessment": {{
        "severity": "high",
        "unused_permission_count": 5,
        "high_risk_unused": ["delete:*", "create:secrets"],
        "potential_removal_impact": "low"
    }},
    "usage_recommendations": [
        "Remove unused wildcard permissions",
        "Restrict secret access to read-only",
        "Monitor usage patterns over longer period"
    ]
}}"""

    @staticmethod
    def risk_assessment(context: Dict[str, Any]) -> str:
        """Step 4: Comprehensive Risk Assessment"""
        permission_analysis = context["chain_results"].get("step_2", {})
        runtime_correlation = context["chain_results"].get("step_3", {})
        
        return f"""TASK: Synthesize comprehensive security risk assessment combining static and runtime analysis.

STATIC ANALYSIS RESULTS:
{json.dumps(permission_analysis, indent=2)}

RUNTIME ANALYSIS RESULTS:
{json.dumps(runtime_correlation, indent=2)}

RISK ASSESSMENT METHODOLOGY:
Calculate overall risk score (0-100, where 100 is most secure) considering:

SCORING CRITERIA:
- Base score: 100
- Wildcard permissions: -20 points each
- Unused high-risk permissions: -15 points each
- Excessive privileges: -10 points each
- Sensitive resource access: -10 points per resource type
- Critical security issues: -25 points each

RISK FACTORS TO EVALUATE:
1. **Immediate Risks**: Current exploitable vulnerabilities
2. **Potential Risks**: Permissions that could be misused
3. **Compliance Issues**: Violations of security best practices
4. **Blast Radius**: Scope of potential damage from compromise

Provide JSON response:
{{
    "overall_risk_assessment": {{
        "security_score": 35,
        "risk_level": "high",
        "confidence": "high"
    }},
    "risk_breakdown": {{
        "immediate_risks": [
            {{
                "risk": "wildcard_resource_access",
                "severity": "critical", 
                "exploitability": "high",
                "impact": "complete_namespace_compromise"
            }}
        ],
        "potential_risks": [
            {{
                "risk": "unused_privileged_permissions",
                "severity": "medium",
                "condition": "if_compromised",
                "impact": "lateral_movement"
            }}
        ]
    }},
    "compliance_issues": [
        "violates_least_privilege_principle",
        "excessive_permissions_granted",
        "no_permission_justification"
    ],
    "blast_radius": {{
        "scope": "namespace_wide",
        "affected_resources": ["all_pods", "all_secrets", "all_configmaps"],
        "escalation_potential": "high"
    }},
    "recommendations_priority": [
        {{
            "priority": "critical",
            "action": "remove_wildcard_permissions",
            "timeline": "immediate"
        }},
        {{
            "priority": "high", 
            "action": "audit_unused_permissions",
            "timeline": "within_24_hours"
        }}
    ]
}}"""

    @staticmethod
    def recommendation_generation(context: Dict[str, Any]) -> str:
        """Step 5: Generate Actionable Security Recommendations"""
        risk_assessment = context["chain_results"].get("step_4", {})
        runtime_correlation = context["chain_results"].get("step_3", {})
        
        return f"""TASK: Generate specific, actionable security recommendations based on comprehensive analysis.

RISK ASSESSMENT:
{json.dumps(risk_assessment, indent=2)}

RUNTIME USAGE ANALYSIS:
{json.dumps(runtime_correlation, indent=2)}

RECOMMENDATION FRAMEWORK:
Generate recommendations across these categories:
1. **Immediate Actions** (Critical/High priority)
2. **Permission Refinements** (Specific changes)
3. **Hardened Configuration** (Minimal viable permissions)
4. **Monitoring & Alerting** (Ongoing security)
5. **Implementation Plan** (Step-by-step execution)

For each recommendation, provide:
- Specific action to take
- Technical implementation details  
- Risk mitigation achieved
- Potential operational impact

Provide JSON response:
{{
    "immediate_actions": [
        {{
            "priority": "critical",
            "action": "remove_wildcard_permissions",
            "implementation": "Replace * with specific resource names",
            "risk_mitigation": "Eliminates unrestricted access",
            "operational_impact": "low"
        }}
    ],
    "permission_refinements": [
        {{
            "current_permission": {{
                "apiGroups": [""],
                "resources": ["*"], 
                "verbs": ["*"]
            }},
            "recommended_permission": {{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }},
            "justification": "Based on runtime usage patterns"
        }}
    ],
    "hardened_role_manifest": {{
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {{
            "name": "hardened-role",
            "namespace": "target-namespace"
        }},
        "rules": [
            {{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }}
        ]
    }},
    "monitoring_recommendations": [
        "Set up alerts for privilege escalation attempts",
        "Monitor access to sensitive resources",
        "Regular permission usage audits"
    ],
    "implementation_plan": [
        {{
            "step": 1,
            "action": "Create hardened Role in test environment",
            "validation": "Verify application functionality"
        }},
        {{
            "step": 2,
            "action": "Deploy hardened Role to production",
            "monitoring": "Watch for access denied errors"
        }}
    ]
}}"""

    @staticmethod
    def get_prompt_chain() -> List[callable]:
        """Return the complete KubeGuard security analysis prompt chain"""
        return [
            KubeGuardPrompts.role_understanding,
            KubeGuardPrompts.permission_analysis,
            KubeGuardPrompts.runtime_correlation,
            KubeGuardPrompts.risk_assessment,
            KubeGuardPrompts.recommendation_generation
        ]