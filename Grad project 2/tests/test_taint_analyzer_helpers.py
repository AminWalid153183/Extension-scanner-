import esprima
import asyncio
from pathlib import Path
import json
from main import CFGNode, TaintAnalyzer, TaintLabel

# Step 2
def test_merge_predecessors_merges_taint():
    node = CFGNode()
    parent = CFGNode()
    parent.tainted_vars.add("a")
    node.predecessors = [parent]
    analyzer = TaintAnalyzer()
    analyzer._merge_predecessors(node)
    assert "a" in node.tainted_vars

# Step 3
class FakeArg:
    def __init__(self, name):
        self.type = 'Identifier'
        self.name = name

class FakeAST:
    def __init__(self):
        self.arguments = [FakeArg("input1"), FakeArg("input2")]
        self.type = 'CallExpression'

def test_mark_tainted_adds_identifiers():
    node = CFGNode()
    node.ast_node = FakeAST()
    analyzer = TaintAnalyzer()
    analyzer._mark_tainted(node)
    assert "input1" in node.tainted_vars
    assert "input2" in node.tainted_vars

# Step 4
def test_get_priority_returns_correct_value():
    analyzer = TaintAnalyzer()

    src = CFGNode()
    src.is_source = True

    sink = CFGNode()
    sink.is_sink = True

    call_node = CFGNode()
    call_node.ast_node = type("AST", (), {"type": "CallExpression"})()

    normal = CFGNode()
    normal.tainted_vars.add("x")

    assert analyzer._get_priority(sink) == 100
    assert analyzer._get_priority(src) == 80
    assert analyzer._get_priority(call_node) == 50
    assert analyzer._get_priority(normal) == 1