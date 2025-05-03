import esprima
import asyncio
from main import CFGBuilder, TaintAnalyzer, CFGNode, ExtensionSecurityAnalyzer
from pathlib import Path

def test_cfg_detects_loop_structure():
    code = """
    for (let i = 0; i < 10; i++) {
        console.log(i);
    }
    """
    ast = esprima.parseScript(code)
    builder = CFGBuilder()
    cfg = builder.build_from_ast(ast)
    builder.detect_malicious_patterns(cfg)

    assert builder.malicious_patterns['suspicious_cycles'] != []

def test_manifest_high_risk(tmp_path):
    manifest_data = {
        "permissions": ["debugger", "storage", "<all_urls>"],
        "optional_permissions": [],
        "content_security_policy": "script-src 'self' 'unsafe-eval';"
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(str(manifest_data).replace("'", '"'))

    analyzer = ExtensionSecurityAnalyzer()
    loop = asyncio.get_event_loop()
    risks = loop.run_until_complete(analyzer.analyze_manifest(manifest_path))

    assert any("debugger" in r['message'] for r in risks)

def test_taint_flow():
    node1 = CFGNode()
    node2 = CFGNode()
    node1.connect(node2)

    node1.is_source = True
    node2.is_sink = True

    analyzer = TaintAnalyzer()
    analyzer.analyze(node1)

    assert hasattr(node2, 'tainted_vars')

