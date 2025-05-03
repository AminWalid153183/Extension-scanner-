import esprima
import asyncio
from pathlib import Path
import json
from main import CFGNode, TaintAnalyzer, TaintLabel

def test_basic_taint_propagation():
    entry = CFGNode()
    next_node = CFGNode()

    entry.connect(next_node)
    entry.is_source = True

    analyzer = TaintAnalyzer()
    analyzer.analyze(entry)

    assert next_node.tainted_vars == entry.tainted_vars

def test_no_taint_when_no_source():
    node1 = CFGNode()
    node2 = CFGNode()
    node1.connect(node2)

    analyzer = TaintAnalyzer()
    analyzer.analyze(node1)

    assert not node1.tainted_vars
    assert not node2.tainted_vars

class FakeArg:
    def __init__(self, name):
        self.type = 'Identifier'
        self.name = name

class FakeAST:
    def __init__(self):
        self.type = 'CallExpression'
        self.arguments = [FakeArg('userInput')]
        def source():
            return 'sendData(userInput)'
        self.source = source

def test_sink_detects_taint():
    src = CFGNode()
    sink = CFGNode()

    src.connect(sink)         # ✅ Create CFG flow from source to sink
    src.is_source = True      # ✅ Mark as taint source
    sink.is_sink = True       # ✅ Mark as sink

    analyzer = TaintAnalyzer()
    analyzer.analyze(src)     # ✅ Run taint analysis

    # ✅ Check if taint reached sink
    assert 'userInput' in sink.tainted_vars

