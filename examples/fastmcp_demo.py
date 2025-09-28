#!/usr/bin/env python3
"""
KubeGuard FastMCP Demo
Demonstrates how to use the FastMCP-based KubeGuard server with built-in test data
"""

import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Setup logging inline to avoid import issues
import os
import logging
from logging.handlers import RotatingFileHandler

def setup_debug_logging(log_dir="logs"):
    """Setup logging with maximum verbosity for debugging"""
    os.makedirs(log_dir, exist_ok=True)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'kubeguard.log'),
        maxBytes=10485760,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)  # Show API calls on console
    console_handler.setFormatter(formatter)
    
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger

logger = setup_debug_logging()

# Import with proper variable name
from kubeguard.analyzer import KubeGuardRoleAnalyzer, UniversalLLMClient
from kubeguard.config import config, Config


def get_test_roles():
    """Get predefined test roles for demonstration"""
    return {
        "secure_role": {
            "name": "Secure Pod Reader",
            "manifest": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {
                    "name": "secure-pod-reader",
                    "namespace": "demo-app"
                },
                "rules": [{
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["get", "list", "watch"]
                }]
            },
            "expected_score": "90+",
            "expected_risk": "low"
        },
        "risky_role": {
            "name": "Dangerous Wildcard Role",
            "manifest": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {
                    "name": "dangerous-wildcard-role",
                    "namespace": "demo-app"
                },
                "rules": [{
                    "apiGroups": ["*"],
                    "resources": ["*"],
                    "verbs": ["*"]
                }]
            },
            "expected_score": "0-20",
            "expected_risk": "critical"
        },
        "mixed_role": {
            "name": "Mixed Risk Role",
            "manifest": {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {
                    "name": "mixed-permissions-role",
                    "namespace": "demo-app"
                },
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods"],
                        "verbs": ["get", "list", "watch"]
                    },
                    {
                        "apiGroups": [""],
                        "resources": ["secrets"],
                        "verbs": ["*"]
                    }
                ]
            },
            "expected_score": "40-60",
            "expected_risk": "medium"
        }
    }


def get_sample_runtime_logs():
    """Get sample runtime logs for demonstration"""
    return [
        '{"verb":"get","resource":"pods","user":"system:serviceaccount:demo-app:worker","timestamp":"2024-01-15T10:00:00Z"}',
        '{"verb":"list","resource":"pods","user":"system:serviceaccount:demo-app:worker","timestamp":"2024-01-15T10:01:00Z"}',
        '{"verb":"watch","resource":"pods","user":"system:serviceaccount:demo-app:worker","timestamp":"2024-01-15T10:02:00Z"}',
        '{"verb":"get","resource":"configmaps","user":"system:serviceaccount:demo-app:worker","timestamp":"2024-01-15T10:03:00Z"}'
    ]


def validate_llm_configuration():
    """Validate that LLM is properly configured for KubeGuard analysis"""
    if not config.has_llm_configured:
        raise ValueError(
            "KubeGuard requires LLM configuration for security analysis.\n"
            "This is a pure LLM-based implementation with no rule-based fallbacks.\n\n"
            "Required configuration:\n"
            "1. Set LLM_PROVIDER (openai, anthropic, groq, etc.) in .env file\n"
            "2. Add corresponding API key (OPENAI_API_KEY, ANTHROPIC_API_KEY, GROQ_API_KEY, etc.)\n"
            "3. Optionally set LLM_MODEL if not using defaults\n\n"
            "Example .env file:\n"
            "LLM_PROVIDER=groq\n"
            "GROQ_API_KEY=gsk-your-key-here\n"
            "LLM_MODEL=llama-3.3-70b-versatile"
        )


async def demo_basic_analysis():
    """Demonstrate basic role analysis functionality"""
    print("\n🔍 KubeGuard Analysis Demo")
    print("=" * 50)
    
    try:
        # Validate LLM configuration first
        print("🔧 Validating LLM configuration...")
        validate_llm_configuration()
        
        # Initialize analyzer with real LLM
        print("🚀 Initializing KubeGuard analyzer...")
        analyzer = KubeGuardRoleAnalyzer()
        llm_info = analyzer.get_llm_info()
        print(f"   ✅ LLM configured: {llm_info['provider']} ({llm_info['model']})")
        print(f"   🧠 Analysis method: Pure LLM-based (5-step prompt chain)")
        print()
        
        # Get test data
        test_roles = get_test_roles()
        runtime_logs = get_sample_runtime_logs()
        
        print(f"📋 Testing with {len(test_roles)} predefined roles:")
        for role_key, role_data in test_roles.items():
            print(f"   • {role_data['name']} (expected: {role_data['expected_score']}, {role_data['expected_risk']})")
        print()
        
        # Analyze each role
        results = {}
        for role_key, role_data in test_roles.items():
            print(f"🚀 Starting analysis of {role_data['name']}...")
            result = await analyze_single_role(analyzer, role_data, runtime_logs)
            results[role_key] = result
            print(f"✅ Completed analysis of {role_data['name']}")
            print()
        
        # Summary
        print_summary(results)
        return results
        
    except ValueError as e:
        print(f"❌ LLM Configuration Error:")
        print(f"   {str(e)}")
        print("\n💡 To run in testing mode with mock responses:")
        print("   Use: KubeGuardRoleAnalyzer(use_mock=True)")
        print("   Note: Mock mode provides fake responses for testing only")
        return {}
        
    except Exception as e:
        print(f"❌ demo_basic_analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return {}


async def demo_mock_mode():
    """Demonstrate mock mode for testing without LLM configuration"""
    print("\n🧪 Mock Mode Demo (Testing Only)")
    print("=" * 50)
    print("⚠️  IMPORTANT: Mock mode provides fake responses for testing")
    print("    Real security analysis requires LLM configuration")
    print()
    
    try:
        # Initialize analyzer with mock client
        analyzer = KubeGuardRoleAnalyzer(use_mock=True)
        llm_info = analyzer.get_llm_info()
        print(f"🔧 Using mock LLM client: {llm_info}")
        
        # Test with one role
        test_roles = get_test_roles()
        secure_role = test_roles["secure_role"]
        
        print(f"🧪 Testing mock analysis with: {secure_role['name']}")
        result = await analyze_single_role(analyzer, secure_role, [])
        
        if result.get("success"):
            print("✅ Mock analysis completed")
            print("⚠️  Remember: These are fake results for testing only")
        
        return {"mock_test": result}
        
    except Exception as e:
        print(f"❌ Mock demo failed: {e}")
        return {}


async def analyze_single_role(analyzer, role_data, runtime_logs):
    """Analyze a single role and display results"""
    print(f"🔍 Analyzing: {role_data['name']}")
    print("-" * 40)
    
    manifest = role_data['manifest']
    role_name = manifest['metadata']['name']
    
    try:
        # Perform analysis
        print("   📊 Running LLM security analysis...")
        analysis = await analyzer.analyze_role(manifest, runtime_logs)
        
        # Display basic results
        print(f"   ✅ Analysis completed")
        print(f"   📈 Security Score: {analysis.security_score:.1f}/100")
        print(f"   ⚠️  Risk Level: {analysis.risk_level.value.upper()}")
        print(f"   🔍 Issues Found: {len(analysis.security_issues)}")
        print(f"   🧠 Method: {analysis.analysis_method.value}")
        
        # Show LLM chain completion
        if analysis.llm_chain_results:
            completed_steps = len([k for k, v in analysis.llm_chain_results.items() if not v.get("error")])
            print(f"   🔗 Prompt chain: {completed_steps}/5 steps completed")
        
        # Show critical issues if any
        critical_issues = [i for i in analysis.security_issues if i.risk_level.value == "critical"]
        if critical_issues:
            print(f"   🚨 Critical Issues:")
            for issue in critical_issues[:2]:  # Show first 2
                print(f"      • {issue.description}")
        
        # Show top recommendations
        if analysis.recommendations:
            print(f"   💡 Top Recommendations:")
            for rec in analysis.recommendations[:2]:  # Show first 2
                print(f"      • {rec}")
        
        # Generate hardened role if needed
        hardened_info = None
        if analysis.security_score < 80:
            print(f"   🔧 Generating hardened version...")
            hardened_result = analyzer.generate_hardened_role(analysis)
            hardened_info = {
                "improvement": hardened_result.get("security_score_improvement", 0),
                "improvements_count": len(hardened_result.get("improvements", [])),
                "llm_generated": hardened_result.get("llm_generated", False)
            }
            print(f"      📈 Improvement: +{hardened_info['improvement']:.1f} points")
            print(f"      🔧 LLM Generated: {hardened_info['llm_generated']}")
        
        return {
            "success": True,
            "role_name": role_name,
            "security_score": analysis.security_score,
            "risk_level": analysis.risk_level.value,
            "issues_count": len(analysis.security_issues),
            "critical_issues_count": len(critical_issues),
            "recommendations_count": len(analysis.recommendations),
            "hardened_info": hardened_info,
            "analysis": analysis
        }
        
    except Exception as e:
        print(f"   ❌ Analysis failed: {e}")
        return {
            "success": False,
            "role_name": role_name,
            "error": str(e)
        }


def print_summary(results):
    """Print analysis summary"""
    print("📊 Analysis Summary")
    print("=" * 50)
    
    successful = [r for r in results.values() if r.get("success")]
    failed = [r for r in results.values() if not r.get("success")]
    
    print(f"✅ Successful analyses: {len(successful)}")
    print(f"❌ Failed analyses: {len(failed)}")
    
    if successful:
        avg_score = sum(r["security_score"] for r in successful) / len(successful)
        print(f"📈 Average security score: {avg_score:.1f}/100")
        
        risk_levels = {}
        for result in successful:
            risk = result["risk_level"]
            risk_levels[risk] = risk_levels.get(risk, 0) + 1
        
        print(f"⚠️  Risk distribution:")
        for risk, count in risk_levels.items():
            print(f"   • {risk.upper()}: {count} role(s)")
        
        total_issues = sum(r["issues_count"] for r in successful)
        critical_issues = sum(r["critical_issues_count"] for r in successful)
        print(f"🔍 Total issues found: {total_issues} ({critical_issues} critical)")
        
        hardened_count = len([r for r in successful if r.get("hardened_info")])
        if hardened_count > 0:
            print(f"🔧 Roles requiring hardening: {hardened_count}")


async def interactive_demo():
    """Allow user to input their own role or select from examples"""
    print("\n🎮 Interactive Demo Mode")
    print("=" * 30)
    
    # Check LLM configuration first
    try:
        validate_llm_configuration()
        print("✅ LLM configured - ready for real analysis")
    except ValueError:
        print("⚠️  No LLM configured - only mock mode available")
    
    print("\nChoose an option:")
    print("1. Analyze a predefined example role")
    print("2. Input your own Kubernetes Role YAML/JSON")
    print("3. Load from file")
    print("4. Demo mock mode (testing only)")
    print("5. Skip interactive demo")
    
    try:
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == "1":
            await demo_predefined_roles()
        elif choice == "2":
            await demo_user_input()
        elif choice == "3":
            await demo_file_input()
        elif choice == "4":
            await demo_mock_mode()
        else:
            print("Skipping interactive demo...")
    
    except (KeyboardInterrupt, EOFError):
        print("\nSkipping interactive demo...")


async def demo_predefined_roles():
    """Let user select from predefined roles"""
    test_roles = get_test_roles()
    
    print("\nAvailable predefined roles:")
    for i, (key, role_data) in enumerate(test_roles.items(), 1):
        print(f"{i}. {role_data['name']} (expected: {role_data['expected_risk']} risk)")
    
    try:
        choice = int(input(f"\nSelect role (1-{len(test_roles)}): ")) - 1
        role_keys = list(test_roles.keys())
        
        if 0 <= choice < len(role_keys):
            selected_role = test_roles[role_keys[choice]]
            
            # Validate LLM configuration
            validate_llm_configuration()
            analyzer = KubeGuardRoleAnalyzer()
            runtime_logs = get_sample_runtime_logs()
            
            print(f"\n🔍 Analyzing selected role: {selected_role['name']}")
            result = await analyze_single_role(analyzer, selected_role, runtime_logs)
            
            if result.get("success"):
                print(f"\n✅ Analysis completed for {result['role_name']}")
                print("Full analysis object available for further inspection.")
        else:
            print("Invalid selection.")
    
    except ValueError as llm_error:
        print(f"❌ {llm_error}")
        print("💡 Try option 4 for mock mode demo instead")
    except (ValueError, KeyboardInterrupt):
        print("Invalid input or cancelled.")


async def demo_user_input():
    """Allow user to input their own role"""
    try:
        validate_llm_configuration()
    except ValueError as e:
        print(f"❌ {e}")
        return
    
    print("\nPaste your Kubernetes Role YAML/JSON (press Enter twice when done):")
    print("Example format:")
    print(json.dumps({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "my-role", "namespace": "default"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]
    }, indent=2))
    print("\nYour input:")
    
    lines = []
    empty_lines = 0
    
    try:
        while empty_lines < 2:
            line = input()
            if line.strip() == "":
                empty_lines += 1
            else:
                empty_lines = 0
            lines.append(line)
        
        user_input = "\n".join(lines[:-2])  # Remove last two empty lines
        
        # Try to parse as JSON
        try:
            role_manifest = json.loads(user_input)
        except json.JSONDecodeError:
            print("❌ Invalid JSON format. Please check your input.")
            return
        
        # Validate basic structure
        if not all(key in role_manifest for key in ["apiVersion", "kind", "metadata", "rules"]):
            print("❌ Missing required fields. Role must have apiVersion, kind, metadata, and rules.")
            return
        
        print(f"\n🔍 Analyzing your role: {role_manifest['metadata'].get('name', 'unnamed')}")
        
        analyzer = KubeGuardRoleAnalyzer()
        analysis = await analyzer.analyze_role(role_manifest)
        
        print(f"✅ Analysis completed!")
        print(f"📊 Security Score: {analysis.security_score:.1f}/100")
        print(f"⚠️  Risk Level: {analysis.risk_level.value.upper()}")
        print(f"🔍 Issues: {len(analysis.security_issues)}")
        
        if analysis.recommendations:
            print("💡 Recommendations:")
            for rec in analysis.recommendations[:3]:
                print(f"   • {rec}")
    
    except (KeyboardInterrupt, EOFError):
        print("\nInput cancelled.")


async def demo_file_input():
    """Allow user to load role from file"""
    try:
        validate_llm_configuration()
    except ValueError as e:
        print(f"❌ {e}")
        return
    
    print("\nEnter path to YAML/JSON file containing Kubernetes Role:")
    
    try:
        file_path = input("File path: ").strip()
        
        if not Path(file_path).exists():
            print(f"❌ File not found: {file_path}")
            return
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Try JSON first, then YAML
        try:
            import json
            role_manifest = json.loads(content)
        except json.JSONDecodeError:
            try:
                import yaml
                role_manifest = yaml.safe_load(content)
            except ImportError:
                print("❌ YAML support requires 'pyyaml' package: pip install pyyaml")
                return
            except yaml.YAMLError:
                print("❌ Invalid YAML/JSON format")
                return
        
        print(f"\n🔍 Analyzing role from file: {role_manifest['metadata'].get('name', 'unnamed')}")
        
        analyzer = KubeGuardRoleAnalyzer()
        analysis = await analyzer.analyze_role(role_manifest)
        
        print(f"✅ Analysis completed!")
        print(f"📊 Security Score: {analysis.security_score:.1f}/100")
        print(f"⚠️  Risk Level: {analysis.risk_level.value.upper()}")
        
    except (KeyboardInterrupt, EOFError):
        print("\nFile input cancelled.")
    except Exception as e:
        print(f"❌ Error reading file: {e}")


def print_getting_started():
    """Print getting started information"""
    print("\n🚀 Getting Started with KubeGuard FastMCP")
    print("=" * 50)
    
    print("📋 Prerequisites:")
    print("1. Configure LLM provider in .env file:")
    print("   LLM_PROVIDER=groq  # or openai, anthropic, etc.")
    print("   GROQ_API_KEY=gsk_your_key_here")
    print("   LLM_MODEL=llama-3.3-70b-versatile  # optional")
    print()
    
    print("🚀 Start the FastMCP server:")
    print("   python -m kubeguard.main")
    print()
    
    print("🔧 Connect with an MCP client to use tools:")
    print("   • analyze_role_security - Full LLM-based security analysis")
    print("   • generate_hardened_role - Create improved role configuration")
    print("   • validate_role_security - Check against security thresholds")
    print("   • get_llm_status - Check LLM configuration status")
    print()
    
    print("📚 Access resources for documentation:")
    print("   • kubeguard://methodology - 5-step LLM prompt chain details")
    print("   • kubeguard://examples - Example roles and expected results")
    print()
    
    print("⚠️  Important Notes:")
    print("   • KubeGuard requires LLM configuration for real analysis")
    print("   • This is a pure LLM implementation with no rule-based fallbacks")
    print("   • Mock mode is available for testing but provides fake results")
    print(f"   • Debug logs saved to: {os.path.abspath('logs/kubeguard.log')}")


async def main():
    """Run the complete demo"""
    print("🛡️  KubeGuard FastMCP Demo")
    print("Pure LLM-based Kubernetes RBAC Security Analysis")
    print("=" * 60)
    
    # Check imports
    print("\n🔧 Checking system status...")
    try:
        from kubeguard.analyzer import KubeGuardRoleAnalyzer, UniversalLLMClient
        from kubeguard.config import config
        print("   ✅ All imports successful")
        
        # Debug config object
        print(f"   📝 Config object type: {type(config)}")
        print(f"   📝 Config attributes: {[attr for attr in dir(config) if not attr.startswith('_')]}")
        print(f"   📝 Has LLM configured: {hasattr(config, 'has_llm_configured')} = {getattr(config, 'has_llm_configured', 'N/A')}")
        
        # Check LLM configuration
        try:
            validate_llm_configuration()
            print(f"   ✅ LLM configured: {config.llm.provider} ({config.llm.model})")
            llm_ready = True
        except ValueError as e:
            print(f"   ⚠️  LLM not configured")
            print(f"\n📝 Configuration Error:")
            print(f"{str(e)}")
            print("\nChoose an option:")
            print("1. Exit and configure LLM for real analysis")
            print("2. Continue with mock mode demo (fake results)")
            
            try:
                choice = input("\nEnter choice (1-2): ").strip()
                if choice == "1":
                    print("\n👋 Configure LLM and run the demo again for real analysis!")
                    return
                elif choice == "2":
                    print("\n🧪 Continuing with mock mode...")
                    llm_ready = False
                else:
                    print("\n❌ Invalid choice. Exiting...")
                    return
            except (KeyboardInterrupt, EOFError):
                print("\n👋 Demo cancelled by user")
                return
        
    except Exception as e:
        print(f"   ❌ Import failed: {e}")
        return
    
    try:
        if llm_ready:
            # Step 1: Run real LLM analysis
            print("\n🚀 STEP 1: LLM-Based Analysis of Test Roles")
            print("-" * 50)
            results = await demo_basic_analysis()
        else:
            # Step 1: Show mock mode instead
            print("\n🧪 STEP 1: Mock Mode Demo (LLM Not Configured)")
            print("-" * 50)
            print("Running mock analysis to demonstrate functionality...")
            results = await demo_mock_mode()
        
        # Step 2: Interactive demo (optional)
        print("\n🚀 STEP 2: Interactive Demo")
        print("-" * 50)
        await interactive_demo()
        
        # Step 3: Getting started info
        print("\n🚀 STEP 3: Getting Started Guide")
        print("-" * 50)
        print_getting_started()
        
        print("\n" + "=" * 60)
        if llm_ready:
            print("✅ Demo completed successfully with real LLM analysis!")
        else:
            print("✅ Demo completed with mock data!")
            print("🔧 Configure LLM provider for real security analysis")
        
        print("\n💡 This demo showcases KubeGuard's pure LLM-based approach.")
        print("   The FastMCP server provides robust security analysis via MCP tools.")
        
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())