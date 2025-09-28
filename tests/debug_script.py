import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from kubeguard.analyzer import KubeGuardRoleAnalyzer
from kubeguard.prompts import KubeGuardPrompts

async def debug_llm_steps():
    role_manifest = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "test-pod-reader", "namespace": "default"},
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}]
    }
    
    # Initialize context like the analyzer does
    context = {
        "role_manifest": role_manifest,
        "runtime_logs": [],
        "chain_results": {}
    }
    
    # Get the prompt chain
    prompt_chain = KubeGuardPrompts.get_prompt_chain()
    analyzer = KubeGuardRoleAnalyzer()
    
    for i, prompt_func in enumerate(prompt_chain, 1):
        step_name = f"step_{i}"
        print(f"\n{'='*60}")
        print(f"STEP {i}: {prompt_func.__name__}")
        print(f"{'='*60}")
        
        # Generate prompt
        prompt = prompt_func(context)
        print(f"INPUT PROMPT:\n{prompt}\n")
        
        # Call LLM
        response = await analyzer.llm_client.call(prompt)
        print(f"RAW OUTPUT:\n{response}\n")
        
        # Parse response
        parsed = analyzer._parse_llm_response(response, step_name)
        print(f"PARSED JSON:\n{json.dumps(parsed, indent=2)}\n")
        
        # Store for next step
        context["chain_results"][step_name] = parsed

if __name__ == "__main__":
    asyncio.run(debug_llm_steps())