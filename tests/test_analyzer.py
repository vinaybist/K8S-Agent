"""
Test suite for KubeGuardRoleAnalyzer
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from kubeguard.analyzer import KubeGuardRoleAnalyzer, LLMClient
from kubeguard.models import RiskLevel, AnalysisMethod


@pytest.fixture
def analyzer():
    """Create analyzer instance for testing"""
    return KubeGuardRoleAnalyzer()


@pytest.fixture
def secure_role():
    """Example secure Role manifest"""
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "name": "secure-role",
            "namespace": "test-namespace"
        },
        "rules": [{
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["get", "list", "watch"]
        }]
    }


@pytest.fixture
def insecure_role():
    """Example insecure Role manifest"""
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1", 
        "kind": "Role",
        "metadata": {
            "name": "insecure-role",
            "namespace": "test-namespace"
        },
        "rules": [{
            "apiGroups": ["*"],
            "resources": ["*"],
            "verbs": ["*"]
        }]
    }


@pytest.fixture
def runtime_logs():
    """Example runtime audit logs"""
    return [
        '{"verb":"get","resource":"pods","user":"system:serviceaccount:test:app","timestamp":"2024-01-15T10:00:00Z"}',
        '{"verb":"list","resource":"pods","user":"system:serviceaccount:test:app","timestamp":"2024-01-15T10:01:00Z"}',
        '{"verb":"watch","resource":"pods","user":"system:serviceaccount:test:app","timestamp":"2024-01-15T10:02:00Z"}'
    ]


class TestKubeGuardRoleAnalyzer:
    """Test cases for KubeGuardRoleAnalyzer"""
    
    @pytest.mark.asyncio
    async def test_analyze_secure_role(self, analyzer, secure_role):
        """Test analysis of secure Role"""
        analysis = await analyzer.analyze_role(secure_role)
        
        assert analysis.role_name == "secure-role"
        assert analysis.namespace == "test-namespace"
        assert analysis.analysis_method == AnalysisMethod.RULE_BASED
        assert analysis.security_score >= 80  # Should be high score for secure role
        assert analysis.risk_level == RiskLevel.LOW
        assert len(analysis.security_issues) == 0  # No issues expected
    
    @pytest.mark.asyncio
    async def test_analyze_insecure_role(self, analyzer, insecure_role):
        """Test analysis of insecure Role with wildcard permissions"""
        analysis = await analyzer.analyze_role(insecure_role)
        
        assert analysis.role_name == "insecure-role"
        assert analysis.security_score < 50  # Should be low score
        assert analysis.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert len(analysis.security_issues) > 0  # Should find issues
        
        # Check for wildcard issues
        issue_types = [issue.issue_type for issue in analysis.security_issues]
        assert "wildcard_verbs" in issue_types
        assert "wildcard_resources" in issue_types
    
    @pytest.mark.asyncio
    async def test_analyze_with_runtime_logs(self, analyzer, secure_role, runtime_logs):
        """Test analysis with runtime logs"""
        analysis = await analyzer.analyze_role(secure_role, runtime_logs)
        
        assert len(analysis.runtime_usage) > 0
        assert "get:pods" in analysis.runtime_usage
        assert "list:pods" in analysis.runtime_usage
        assert "watch:pods" in analysis.runtime_usage
    
    def test_identify_excessive_permissions(self, analyzer):
        """Test identification of excessive permissions"""
        api_groups = ["*"]
        resources = ["*"] 
        verbs = ["*"]
        
        excessive = analyzer._identify_excessive_permissions(api_groups, resources, verbs)
        
        assert len(excessive) > 0
        assert any("wildcard" in perm.lower() for perm in excessive)
    
    def test_analyze_rule_security_wildcards(self, analyzer):
        """Test security analysis of rule with wildcards"""
        issues = analyzer._analyze_rule_security(0, ["*"], ["*"], ["*"])
        
        assert len(issues) >= 3  # Should find wildcard issues for verbs, resources, api groups
        issue_types = [issue.issue_type for issue in issues]
        assert "wildcard_verbs" in issue_types
        assert "wildcard_resources" in issue_types
        assert "wildcard_api_groups" in issue_types
    
    def test_analyze_rule_security_dangerous_permissions(self, analyzer):
        """Test detection of dangerous permissions"""
        issues = analyzer._analyze_rule_security(
            0, 
            [""], 
            ["pods/exec", "secrets"], 
            ["create", "delete"]
        )
        
        assert len(issues) > 0
        # Should detect dangerous subresource and sensitive resource access
        issue_types = [issue.issue_type for issue in issues]
        assert any("dangerous" in issue_type for issue_type in issue_types)
    
    def test_calculate_security_score(self, analyzer):
        """Test security score calculation"""
        from kubeguard.models import SecurityIssue
        
        # Test with no issues
        score_perfect = analyzer._calculate_security_score([], 1)
        assert score_perfect == 100.0
        
        # Test with critical issues
        critical_issues = [
            SecurityIssue("test", "test", RiskLevel.CRITICAL),
            SecurityIssue("test", "test", RiskLevel.HIGH)
        ]
        score_with_issues = analyzer._calculate_security_score(critical_issues, 1)
        assert score_with_issues < 100.0
        assert score_with_issues >= 0.0
    
    def test_generate_hardened_role(self, analyzer, insecure_role):
        """Test hardened role generation"""
        # First analyze the insecure role
        analysis = asyncio.run(analyzer.analyze_role(insecure_role))
        
        # Generate hardened version
        hardened = analyzer.generate_hardened_role(analysis)
        
        assert hardened.original_role_name == "insecure-role"
        assert len(hardened.improvements) > 0
        assert hardened.security_score_improvement > 0
        
        # Check that hardened role has specific permissions instead of wildcards
        hardened_rules = hardened.hardened_role_manifest["rules"]
        for rule in hardened_rules:
            assert "*" not in rule.get("verbs", [])  # Should remove wildcard verbs
            # Note: In a real implementation, wildcard resources should also be removed
    
    def test_simulate_runtime_usage(self, analyzer):
        """Test runtime usage simulation"""
        rules = [{
            "apiGroups": [""],
            "resources": ["pods", "secrets"],
            "verbs": ["get", "list", "delete"]
        }]
        
        usage = analyzer._simulate_runtime_usage(rules)
        
        assert len(usage) > 0
        assert "get:pods" in usage
        assert "delete:secrets" in usage
        
        # Check that usage patterns make sense
        get_usage = usage["get:pods"]
        delete_usage = usage["delete:secrets"]
        
        assert get_usage.frequency > delete_usage.frequency  # Reads more frequent than deletes
        assert delete_usage.is_excessive  # Delete on secrets should be marked excessive


class TestLLMClient:
    """Test cases for LLM client"""
    
    def test_llm_client_initialization(self):
        """Test LLM client initialization"""
        with patch('kubeguard.config.config') as mock_config:
            mock_config.llm.provider = "openai"
            mock_config.llm.model = "gpt-4o-mini"
            mock_config.llm.api_key = "test-key"
            
            client = LLMClient()
            assert client.provider == "openai"
            assert client.model == "gpt-4o-mini"
            assert client.api_key == "test-key"
    
    @pytest.mark.asyncio
    async def test_unsupported_llm_provider(self):
        """Test error handling for unsupported LLM provider"""
        with patch('kubeguard.config.config') as mock_config:
            mock_config.llm.provider = "unsupported"
            
            client = LLMClient()
            
            with pytest.raises(ValueError, match="Unsupported LLM provider"):
                await client.call("test prompt")


class TestAnalysisIntegration:
    """Integration tests for complete analysis workflow"""
    
    @pytest.mark.asyncio
    async def test_full_analysis_workflow(self, secure_role, runtime_logs):
        """Test complete analysis workflow"""
        analyzer = KubeGuardRoleAnalyzer()
        
        # Perform analysis
        analysis = await analyzer.analyze_role(secure_role, runtime_logs)
        
        # Verify analysis completeness
        assert analysis.role_name is not None
        assert analysis.namespace is not None
        assert analysis.security_score >= 0
        assert analysis.risk_level is not None
        assert isinstance(analysis.recommendations, list)
        
        # Generate hardened role
        hardened = analyzer.generate_hardened_role(analysis)
        
        # Verify hardened role
        assert hardened.original_role_name == analysis.role_name
        assert "hardened" in hardened.hardened_role_manifest["metadata"]["name"]
    
    @pytest.mark.asyncio 
    async def test_analysis_with_mock_llm(self, secure_role):
        """Test analysis with mocked LLM client"""
        
        # Create mock LLM client
        mock_llm = Mock(spec=LLMClient)
        mock_llm.call = Mock(return_value='{"test": "response"}')
        
        analyzer = KubeGuardRoleAnalyzer(llm_client=mock_llm)
        
        # This should fallback to rule-based analysis due to JSON parsing issues
        analysis = await analyzer.analyze_role(secure_role)
        
        assert analysis.analysis_method == AnalysisMethod.RULE_BASED
    
    def test_analysis_serialization(self, secure_role):
        """Test that analysis results can be serialized to JSON"""
        analyzer = KubeGuardRoleAnalyzer()
        analysis = asyncio.run(analyzer.analyze_role(secure_role))
        
        # Should be able to convert to dict without errors
        analysis_dict = analysis.to_dict()
        assert isinstance(analysis_dict, dict)
        assert "role_name" in analysis_dict
        assert "security_score" in analysis_dict
        
        # Should be JSON serializable
        import json
        json_str = json.dumps(analysis_dict)
        assert isinstance(json_str, str)
        
        # Should be able to parse back
        parsed = json.loads(json_str)
        assert parsed["role_name"] == analysis.role_name


if __name__ == "__main__":
    pytest.main([__file__, "-v"])