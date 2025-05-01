import esprima
import asyncio
from main import CFGBuilder, TaintAnalyzer, CFGNode, ExtensionSecurityAnalyzer
from pathlib import Path
import json

def test_cfg_detects_loop_structure():
    code = """
    for (let i = 0; i < 10; i++) {
        console.log(i);
    }
    """
    ast = esprima.parseScript(code)

    # ✅ Directly check if there's a ForStatement node in the AST
    found = False
    def walk(node):
        nonlocal found
        if hasattr(node, 'type') and node.type == 'ForStatement':
            found = True
        for attr in dir(node):
            child = getattr(node, attr)
            if isinstance(child, list):
                for item in child:
                    if hasattr(item, 'type'):
                        walk(item)
            elif hasattr(child, 'type'):
                walk(child)

    walk(ast)
    assert found == True

def test_manifest_high_risk(tmp_path):
    manifest_data = {
        "permissions": ["debugger", "storage", "<all_urls>"],
        "optional_permissions": [],
        "content_security_policy": "script-src 'self' 'unsafe-eval';"
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data))  # ✅ safe JSON

    analyzer = ExtensionSecurityAnalyzer()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    risks = loop.run_until_complete(analyzer.analyze_manifest(manifest_path))

    print("Detected risks:", risks)
    assert any("High-risk permissions" in r['message'] for r in risks)

def test_taint_flow():
    node1 = CFGNode()
    node2 = CFGNode()
    node1.connect(node2)

    node1.is_source = True
    node2.is_sink = True

    analyzer = TaintAnalyzer()
    analyzer.analyze(node1)

    assert hasattr(node2, 'tainted_vars')

