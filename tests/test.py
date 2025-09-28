#!/usr/bin/env python3
"""
Simple KubeGuard Test - Single Role Analysis
"""

import asyncio
import sys
from pathlib import Path
import logging

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Setup simple logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from kubeguard.analyzer import KubeGuardRoleAnalyzer
from kubeguard.config import config


def get_test_role():
    """Get a single test role"""
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "name": "test-pod-reader",
            "namespace": "default"
        },
        "rules": [{
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["get", "list", "watch"]
        }]
    }


async def test_single_role():
    """Test analysis of a single role"""
    print("🔍 Simple KubeGuard Test")
    print("=" * 30)
    
    # Check config
    print(f"Provider: {config.llm.provider}")
    print(f"Model: {config.llm.model}")
    print(f"API Key: {'Yes' if config.llm.api_key else 'No'}")
    print()
    
    # Get test role
    role_manifest = get_test_role()
    print(f"Testing role: {role_manifest['metadata']['name']}")
    
    try:
        # Initialize analyzer
        analyzer = KubeGuardRoleAnalyzer()
        
        # Analyze the role
        print("Running analysis...")
        analysis = await analyzer.analyze_role(role_manifest)
        
        # Show results
        print("\n📊 Results:")
        print(f"Security Score: {analysis.security_score}/100")
        print(f"Risk Level: {analysis.risk_level.value}")
        print(f"Issues Found: {len(analysis.security_issues)}")
        print(f"Analysis Method: {analysis.analysis_method.value}")
        
        # Show LLM chain results with raw data
        if analysis.llm_chain_results:
            print(f"\n🔗 LLM Chain Details:")
            for step, result in analysis.llm_chain_results.items():
                status = "✅" if not result.get("error") else "❌"
                print(f"\n{step}: {status}")
                
                # Print the result content (this is the LLM's parsed JSON output)
                if not result.get("error"):
                    print(f"Output keys: {list(result.keys())}")
                    # Print first few fields to see what the LLM returned
                    for key, value in list(result.items())[:3]:
                        if isinstance(value, dict):
                            print(f"  {key}: {list(value.keys())}")
                        elif isinstance(value, list):
                            print(f"  {key}: [{len(value)} items]")
                        else:
                            print(f"  {key}: {str(value)[:100]}...")
                else:
                    print(f"Error: {result.get('error')}")
                    if 'raw_response' in result:
                        print(f"Raw response: {result['raw_response'][:200]}...")
        
        # Show any issues
        if analysis.security_issues:
            print("\n🚨 Security Issues:")
            for issue in analysis.security_issues:
                print(f"  - {issue.description} ({issue.risk_level.value})")
        
        # Show recommendations
        if analysis.recommendations:
            print("\n💡 Recommendations:")
            for rec in analysis.recommendations[:3]:
                print(f"  - {rec}")
        
        return analysis
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    asyncio.run(test_single_role())