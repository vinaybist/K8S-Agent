# KubeGuard MCP Server

A Model Context Protocol (MCP) server for Kubernetes Role security analysis using LLM-assisted prompt chaining, based on the KubeGuard research paper: "LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis."

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## TestRun:
MCP server (http):
$K8S_Agent> python -m kubeguard.main --http

Standalone Test:
$python .\examples\fastmcp_demo.py

## Citation

If you use KubeGuard in your research, please cite the original paper:

```bibtex
@article{kubeguard2025,
  title={KubeGuard: LLM-Assisted Kubernetes Hardening via Configuration Files and Runtime Logs Analysis},
  journal={arXiv preprint arXiv:2509.04191},
  year={2025}
}
```

## Prompt Chaining:
# How It Works

## Execution Flow

### 1. Server Initialization
- Loads configuration from `.env`
- Validates LLM setup
- Starts FastMCP server

### 2. Client Connects (via MCP protocol)
- AI agents (like Claude Desktop, IDEs with MCP support)
- Connect to the server using MCP protocol

### 3. Analysis Request
```python
# Client calls the tool
analyze_role_security({
    "role_manifest": {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "example", "namespace": "default"},
        "rules": [...]
    },
    "runtime_logs": ["log1", "log2"]  # optional
})

4. 5-Step LLM Chain Execution

Step 1: Role understanding → LLM call
Step 2: Permission analysis → LLM call (uses Step 1 results)
Step 3: Runtime correlation → LLM call (uses Step 1-2 results)
Step 4: Risk assessment → LLM call (uses Step 1-3 results)
Step 5: Recommendations → LLM call (uses all previous results)

5. Results Returned

Security score (0-100)
Risk level (low/medium/high/critical)
Security issues found
Recommendations
```

# Prompt Chaining in detail

```
1. Role Understanding (Step 1)
```
f"""You are KubeGuard, an AI security analyst specializing in Kubernetes RBAC analysis.

TASK: Analyze this Kubernetes Role and provide structured understanding of its permissions and purpose.

ROLE MANIFEST:
```yaml
{json.dumps(role_manifest, indent=2)}
```
2. Permission Analysis (Step 2)
```python
f"""TASK: Perform comprehensive security analysis of the permissions identified in Step 1.

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
    "excessive_permissions": [...],
    "privilege_escalation_risks": [...],
    "sensitive_resource_exposure": [...],
    "attack_vectors": [...],
    "security_score": 45,
    "critical_issues": [...]
}}"""
```

3.Runtime Correlation (Step 3)
```
f"""TASK: Correlate static permissions with actual runtime usage patterns.

STATIC PERMISSION ANALYSIS:
{json.dumps(permission_analysis, indent=2)}

RUNTIME AUDIT LOGS SAMPLE:
{logs_sample}
CORRELATION ANALYSIS:
Analyze the gap between granted permissions and actual usage:

1. **Usage Patterns**: Which permissions are actively used?
2. **Frequency Analysis**: How often is each permission exercised?
3. **Unused Permissions**: What permissions are granted but never used?
4. **Over-Privileged Access**: Where are permissions excessive relative to usage?

[... continues with detailed instructions ...]"""

```
4. Risk Assessment (Step 4)

```
f"""TASK: Synthesize comprehensive security risk assessment combining static and runtime analysis.

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

[... continues with risk factors and JSON structure ...]"""
```
5. Recommendation Generation (Step 5)
```
f"""TASK: Generate specific, actionable security recommendations based on comprehensive analysis.

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

[... continues with detailed structure for recommendations ...]"""
