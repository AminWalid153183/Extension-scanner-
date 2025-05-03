import pytest
from main import CFGBuilder, CFGNode
import esprima

def test_detect_obfuscation():
    code = r'''eval("var a = '\\x61\\x62\\x63';")'''
    ast = esprima.parseScript(code)
    builder = CFGBuilder()
    call_node = ast.body[0].expression
    cfg = CFGNode(call_node)
    patterns = builder.detect_malicious_patterns(cfg)

    assert patterns['obfuscation'] == True







def test_detect_sensitive_api_call():
    code = "fetch('https://example.com')"
    ast = esprima.parseScript(code)
    builder = CFGBuilder()
    call_node = ast.body[0].expression
    cfg = CFGNode(call_node)
    patterns = builder.detect_malicious_patterns(cfg)

    assert any(api['api'] == "fetch" for api in patterns['sensitive_api_calls'])








