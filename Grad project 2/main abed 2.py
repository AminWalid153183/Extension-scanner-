import os
import json
import re
import asyncio
import platform
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from collections import defaultdict
from heapq import heappush, heappop
import hashlib
import yara
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import esprima
import wasmtime
from networkx import DiGraph, dfs_edges
import networkx as nx
from zapv2 import ZAPv2
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware 
from dotenv import load_dotenv
from starlette.middleware.base import BaseHTTPMiddleware



os.environ['ZAP_PROXY'] = "http://localhost:8090"
os.environ['ZAP_API_KEY'] = "nvg78cnu8ok6sur6bvkb63jq0n"


HIGH_RISK_PERMISSIONS = {
    "debugger", "desktopCapture", "nativeMessaging",
    "proxy", "webRequest", "webRequestBlocking",
    "<all_urls>", "unlimitedStorage"
}

YARA_RULES = yara.compile(source='''
rule SuspiciousPatterns {
    strings:
        $eval = /eval\\s*\\(/ nocase
        $func_ctor = /new\\s+Function\\s*\\(/ nocase
        $wasm_loader = /WebAssembly\.(instantiate|compile)/ nocase
        $opcode_pattern = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? 00 00 00 }
    condition:
        any of them
}

rule CryptoMining {
    strings:
        $coinimp = "coinimp.com" nocase
        $cryptonight = "cryptonight" wide
        $webmine = "webmine.pro" nocase
    condition:
        any of them
}
''')

app = FastAPI()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
class AnalysisConfig:
    def __init__(self):
        self.max_taint_depth = 1000
        self.custom_sinks = set()
        self.custom_sanitizers = set()
        self.risk_thresholds = {'high': 25, 'medium': 15, 'low': 5}
        self.complexity_threshold = 20
        self.scan_level = 'medium'
        self.zap_proxy = os.getenv('ZAP_PROXY', 'http://localhost:8090')
        self.zap_api_key = os.getenv('ZAP_API_KEY', 'nvg78cnu8ok6sur6bvkb63jq0n')

class TaintLabel:
    def __init__(self, source: str, sanitizers: Set[str] = None):
        self.source = source
        self.sanitizers = sanitizers or set()

class CFGNode:
    def __init__(self, ast_node=None):
        self.ast_node = ast_node
        self.predecessors: List[CFGNode] = []
        self.successors: List[CFGNode] = []
        self.tainted_vars: Set[str] = set()
        self.taint_labels: Dict[str, Set[TaintLabel]] = defaultdict(set)
        self.is_source = False
        self.is_sink = False
        self.sanitizers: Set[str] = set()
        self.max_visits = 1

    def connect(self, node):
        self.successors.append(node)
        node.predecessors.append(self)

class CFGBuilder:
    def __init__(self, config: AnalysisConfig = None):
        self.config = config or AnalysisConfig()
        self.current_node = CFGNode()
        self.function_defs = {}
        self.loop_stack = []
        self.malicious_patterns = {
            'obfuscation': False,
            'sensitive_api_calls': [],
            'suspicious_cycles': []
        }

    def build_from_ast(self, ast) -> CFGNode:
        entry_node = CFGNode()
        self.current_node = entry_node
        self._visit(ast)
        return entry_node

    def detect_malicious_patterns(self, entry_node: CFGNode):
        # Reset patterns for each analysis
        self.malicious_patterns = {
            'obfuscation': False,
            'sensitive_api_calls': [],
            'suspicious_cycles': []
        }
        for node in self._dfs_nodes(entry_node):
            self._detect_code_obfuscation(node)
            self._find_sensitive_api_calls(node)
            self._analyze_loop_structures(node)
        return self.malicious_patterns

    def _dfs_nodes(self, node: CFGNode):
        """Helper to yield all nodes in depth-first order."""
        stack = [node]
        visited = set()

        while stack:
            current = stack.pop()
            if id(current) in visited:
                continue
            visited.add(id(current))
            yield current
            stack.extend(reversed(current.successors))  # Visit successors


    def _visit(self, node):
        # Accept both dict and esprima AST node
        if isinstance(node, dict) and 'type' in node:
            method_name = f'_visit_{node["type"]}'
            visitor = getattr(self, method_name, self._generic_visit)
            return visitor(node)
        else:
            return self._generic_visit(node)

    def _visit_Program(self, node):
        prev_node = self.current_node
        for stmt in node.get('body', []):
            if stmt.get('type') != 'EmptyStatement':
                stmt_node = CFGNode(stmt)
                prev_node.connect(stmt_node)

                self.current_node = stmt_node
                self._visit(stmt)

                # SPECIAL HANDLING for ExpressionStatement → extract expression (e.g., CallExpression)
                if stmt.get('type') == 'ExpressionStatement' and 'expression' in stmt:
                    expr = stmt['expression']
                    if expr.get('type') == 'CallExpression':
                        expr_node = CFGNode(expr)
                        stmt_node.connect(expr_node)
                        self._detect_code_obfuscation(expr_node)
                        self._find_sensitive_api_calls(expr_node)
                        self._analyze_loop_structures(expr_node)
                        prev_node = expr_node
                    else:
                        # fallback to just the stmt_node
                        self._detect_code_obfuscation(stmt_node)
                        self._find_sensitive_api_calls(stmt_node)
                        self._analyze_loop_structures(stmt_node)
                        prev_node = stmt_node
                else:
                    self._detect_code_obfuscation(stmt_node)
                    self._find_sensitive_api_calls(stmt_node)
                    self._analyze_loop_structures(stmt_node)
                    prev_node = stmt_node

    def _generic_visit(self, node):
        # Accept both dict and esprima AST node
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, dict):
                    self._visit(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            self._visit(item)


    def _visit_IfStatement(self, node):
        test_node = CFGNode(node.test)
        self.current_node.connect(test_node)
        
        consequent_entry = CFGNode()
        test_node.connect(consequent_entry)
        self.current_node = consequent_entry
        self._visit(node.consequent)
        consequent_exit = self.current_node
        
        if node.alternate:
            alternate_entry = CFGNode()
            test_node.connect(alternate_entry)
            self.current_node = alternate_entry
            self._visit(node.alternate)
            alternate_exit = self.current_node
            merge_node = CFGNode()
            consequent_exit.connect(merge_node)
            alternate_exit.connect(merge_node)
            self.current_node = merge_node
        else:
            test_node.connect(self.current_node)

    def _visit_WhileStatement(self, node):
        test_node = CFGNode(node.test)
        self.current_node.connect(test_node)
        
        body_entry = CFGNode()
        test_node.connect(body_entry)
        self.current_node = body_entry
        self.loop_stack.append(test_node)
        self._visit(node.body)
        self.loop_stack.pop()
        
        self.current_node.connect(test_node)
        exit_node = CFGNode()
        test_node.connect(exit_node)
        self.current_node = exit_node

    def _visit_ForStatement(self, node):
        init_node = CFGNode(node.init) if node.init else CFGNode()
        self.current_node.connect(init_node)
        self.current_node = init_node
        
        test_node = CFGNode(node.test) if node.test else CFGNode()
        self.current_node.connect(test_node)
        
        body_entry = CFGNode()
        test_node.connect(body_entry)
        self.current_node = body_entry
        self.loop_stack.append(test_node)
        self._visit(node.body)
        self.loop_stack.pop()
        
        if node.update:
            update_node = CFGNode(node.update)
            self.current_node.connect(update_node)
            self.current_node = update_node
        
        self.current_node.connect(test_node)
        exit_node = CFGNode()
        test_node.connect(exit_node)
        self.current_node = exit_node

    def _visit_TryStatement(self, node):
        try_node = CFGNode(node)
        self.current_node.connect(try_node)
        self.current_node = try_node
        self._visit(node.block)
        try_exit = self.current_node
        
        if node.handler:
            catch_node = CFGNode(node.handler)
            try_node.connect(catch_node)
            self.current_node = catch_node
            self._visit(node.handler.body)
            catch_exit = self.current_node
        else:
            catch_exit = try_exit
        
        if node.finalizer:
            finally_node = CFGNode(node.finalizer)
            try_exit.connect(finally_node)
            catch_exit.connect(finally_node)
            self.current_node = finally_node
            self._visit(node.finalizer)
            finally_exit = self.current_node
            self.current_node = finally_exit
        else:
            merge_node = CFGNode()
            try_exit.connect(merge_node)
            catch_exit.connect(merge_node)
            self.current_node = merge_node

    def _visit_CallExpression(self, node):
        call_node = CFGNode(node)
        self.current_node.connect(call_node)
        self.current_node = call_node

        callee = node.get('callee', {})
        if callee.get('type') == 'MemberExpression' and callee.get('property', {}).get('name') in ['addListener', 'on']:
            self._process_event_listener(node)

    def _process_event_listener(self, node):
        for arg in node.get('arguments', []):
            if arg.get('type') in ['FunctionExpression', 'ArrowFunctionExpression']:
                callback_entry = CFGNode(arg)
                self.current_node.connect(callback_entry)
                prev_node = self.current_node
                self.current_node = callback_entry
                self._visit(arg.get('body'))
                self.current_node = prev_node

    def _detect_code_obfuscation(self, node: CFGNode):
        ast_node = node.ast_node
        if isinstance(ast_node, dict) and ast_node.get('type') == 'CallExpression':
            callee = ast_node.get('callee', {})
            callee_name = self._get_callee_name(callee)
            if callee_name in ['Function', 'eval', 'setTimeout']:
                args = []
                for arg in ast_node.get('arguments', []):
                    value = arg.get('value')
                    name = arg.get('name')
                    if isinstance(value, str):
                        args.append(value)
                    elif isinstance(name, str):
                        args.append(name)
                if any(re.search(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', arg) for arg in args if isinstance(arg, str)):
                    self.malicious_patterns['obfuscation'] = True

    def _find_sensitive_api_calls(self, node: CFGNode):
        sensitive_apis = {
            'chrome.runtime.sendMessage',
            'chrome.webRequest.onBeforeRequest',
            'chrome.tabs.executeScript',
            'XMLHttpRequest.open',
            'fetch'
        }
        ast_node = node.ast_node
        if isinstance(ast_node, dict) and ast_node.get('type') == 'CallExpression':
            callee = ast_node.get('callee', {})
            callee_name = self._get_callee_name(callee)
            if callee_name in sensitive_apis:
                loc = ast_node.get('loc', {}).get('start', {}).get('line', -1)
                self.malicious_patterns['sensitive_api_calls'].append({
                    'api': callee_name,
                    'location': loc
                })

    def _analyze_loop_structures(self, node: CFGNode):
        if len(self.loop_stack) >= 1:
            self.malicious_patterns['suspicious_cycles'].append({
                'depth': len(self.loop_stack),
                'location': node.ast_node.loc.start.line if node.ast_node.loc else -1
            })

    def _get_callee_name(self, callee_node):
        # Accept both dict and esprima AST node
        if not isinstance(callee_node, dict):
            return 'unknown'
        if callee_node.get('type') == 'Identifier':
            return callee_node.get('name')
        elif callee_node.get('type') == 'MemberExpression':
            # Recursively build the full property chain
            parts = []
            obj = callee_node
            while obj and obj.get('type') == 'MemberExpression':
                if obj.get('property') and obj['property'].get('name'):
                    parts.append(obj['property']['name'])
                obj = obj.get('object')
            if obj and obj.get('type') == 'Identifier' and obj.get('name'):
                parts.append(obj['name'])
            return '.'.join(reversed(parts))
        return 'unknown'


class TaintAnalyzer:

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or AnalysisConfig()
        self.worklist = []
        self.visited = set()

    def analyze(self, entry_node: CFGNode):
        self.visited = set()
        self.worklist = []

        heappush(self.worklist, (-self._get_priority(entry_node), id(entry_node), entry_node))
        current_depth = 0

        while self.worklist and current_depth < self.config.max_taint_depth:
            _, _, node = heappop(self.worklist)
            if id(node) in self.visited:
                continue
            self.visited.add(id(node))

            old_tainted = node.tainted_vars.copy()

            self._merge_predecessors(node)

            # ✅ Use real taint extraction
            if node.is_source:
                self._mark_tainted(node)

            self._process_node(node)

            if node.tainted_vars != old_tainted:
                for succ in node.successors:
                    priority = self._get_priority(succ)
                    heappush(self.worklist, (-priority, id(succ), succ))

            current_depth += 1

    def _get_priority(self, node: CFGNode) -> int:
        if not node:
            return 0

        try:
            if node.is_sink:
                return 100
            if node.is_source:
                return 80
            if node.ast_node and getattr(node.ast_node, 'type', None) == 'CallExpression':
                return 50
            return len(node.tainted_vars) if hasattr(node, 'tainted_vars') else 1
        except AttributeError:
            return 0

    
    def _merge_predecessors(self, node: CFGNode):
        if not node or not hasattr(node, 'predecessors'):
            return

        try:
            for pred in node.predecessors:
                if not pred or not hasattr(pred, 'tainted_vars'):
                    continue
                    
                # Merge tainted vars
                if hasattr(node, 'tainted_vars'):
                    node.tainted_vars.update(pred.tainted_vars)
                
                # Merge taint labels
                if hasattr(pred, 'taint_labels'):
                    for var, labels in pred.taint_labels.items():
                        if var not in node.taint_labels:
                            node.taint_labels[var] = set()
                        node.taint_labels[var].update(labels)
        except AttributeError as e:
            print(f"Merge error: {str(e)}")

    def _process_node(self, node: CFGNode):
        if not node or not node.ast_node or not hasattr(node.ast_node, 'type'):
            return

        try:
            node_type = node.ast_node.type
            if node_type == 'AssignmentExpression':
                self._handle_assignment(node)
            elif node_type == 'CallExpression':
                self._handle_call(node)
        except AttributeError as e:
            print(f"Node processing failed: {str(e)}")

    def _handle_assignment(self, node: CFGNode):
        if not node or not node.ast_node:
            return

        try:
            lhs_node = node.ast_node.left
            rhs_node = node.ast_node.right
            
            if not lhs_node or not hasattr(lhs_node, 'name'):
                return
                
            lhs = lhs_node.name
            rhs_vars = self._get_rhs_vars(rhs_node) if rhs_node else []

            tainted_vars = [var for var in rhs_vars if hasattr(node, 'tainted_vars') and var in node.tainted_vars]
            
            if tainted_vars:
                node.tainted_vars.add(lhs)
                for var in tainted_vars:
                    if var in node.taint_labels:
                        node.taint_labels[lhs].update(node.taint_labels[var])
            elif hasattr(node, 'tainted_vars') and lhs in node.tainted_vars:
                node.tainted_vars.remove(lhs)
        except AttributeError:
            pass

    def _handle_call(self, node: CFGNode):
        if not node:
            return

        try:
            if node.is_sink:
                self._check_vulnerability(node) #source
            elif node.is_source:
                self._mark_tainted(node) #sink 
        except AttributeError as e:
            print(f"Call handling failed: {str(e)}")

    def _check_vulnerability(self, node: CFGNode):
        if not node or not hasattr(node, 'tainted_vars'):
            return

        try:
            for var in list(node.tainted_vars):
                labels = node.taint_labels.get(var, set())
                if labels and not any(hasattr(l, 'sanitizers') and l.sanitizers for l in labels):
                    source = node.ast_node.source() if node.ast_node and hasattr(node.ast_node, 'source') else 'unknown'
                    print(f"Vulnerability found: {var} -> {source}")
        except AttributeError as e:
            print(f"Vulnerability check failed: {str(e)}")

    def _mark_tainted(self, node: CFGNode):
        if not node or not hasattr(node, 'ast_node'):
            return
        try:
            if node.ast_node and hasattr(node.ast_node, 'arguments'):
                for arg in node.ast_node.arguments:
                    if getattr(arg, 'type', None) == 'Identifier' and hasattr(arg, 'name'):
                        node.tainted_vars.add(arg.name)
        except Exception as e:
            print(f"Taint marking failed: {e}")

    def _get_rhs_vars(self, node) -> List[str]:
        if not node:
            return []
            
        try:
            if hasattr(node, 'type') and node.type == 'Identifier':
                return [node.name] if hasattr(node, 'name') else []
                
            vars = []
            children = node.children() if hasattr(node, 'children') else []
            for child in children:
                if child:
                    vars.extend(self._get_rhs_vars(child))
            return vars
        except AttributeError:
            return []

class ChromeAdaptor:
    SOURCES = {
        'chrome.runtime.onMessage.addListener',
        'chrome.storage.local.get',
        'window.addEventListener'
    }
    
    SINKS = {
        'eval', 'document.write', 'innerHTML', 'outerHTML',
        'Function', 'setTimeout', 'setInterval', 'element.setAttribute',
        'location.assign', 'location.replace', 'window.open',
        'XMLHttpRequest.open', 'fetch', 'crypto.subtle.digest'
    }

    def __init__(self, config: AnalysisConfig = None):
        self.config = config or AnalysisConfig()
        self.SINKS.update(self.config.custom_sinks)

    def adapt(self, cfg_node: CFGNode):
        code = cfg_node.ast_node.source() if cfg_node.ast_node else ''
        cfg_node.is_source = any(src in code for src in self.SOURCES)
        cfg_node.is_sink = any(sink in code for sink in self.SINKS)
        
        if cfg_node.ast_node and cfg_node.ast_node.type == 'CallExpression':
            self._check_string_args(cfg_node)

    def _check_string_args(self, node: CFGNode):
        callee = node.ast_node.callee.source()
        args = node.ast_node.arguments
        
        if callee in ['setTimeout', 'setInterval'] and args:
            if args[0].type == 'Literal' and isinstance(args[0].value, str):
                node.is_sink = True
            elif (args[0].type == 'Identifier' and 
                  args[0].name in node.tainted_vars):
                node.is_sink = True

class ZAPScanner:
    def __init__(self, config: AnalysisConfig):
        if not config.zap_api_key:
            raise ValueError("ZAP_API_KEY environment variable not set!")
        
        try:
            self.zap = ZAPv2(apikey=config.zap_api_key, proxies={'http': config.zap_proxy})
            # Test connection
            print("ZAP Version:", self.zap.core.version)
            print("API Key Valid:", bool(self.zap.core.alerts()))
        except Exception as e:
            raise ConnectionError(f"ZAP connection failed: {str(e)}")

    async def scan(self, target_url: str):
        print(f'Starting ZAP scan for {target_url}')
        scan_id = self.zap.spider.scan(target_url)
        while int(self.zap.spider.status(scan_id)) < 100:
            await asyncio.sleep(1)
        
        ascan_id = self.zap.ascan.scan(target_url)
        while int(self.zap.ascan.status(ascan_id)) < 100:
            await asyncio.sleep(1)
        
        return self.zap.core.alerts()

class ExtensionHTTPServer:
    def __init__(self, path: Path, port: int = 8081):
        self.path = path
        self.port = port
        self.server = None
        self.thread = None

    async def start(self):
        # Create a Handler class that knows about the directory
        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(self.server.path), **kwargs)

        # Attach the path to the server instance
        Handler.server = self
        
        self.server = HTTPServer(('localhost', self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        await asyncio.sleep(1)

    async def stop(self):
        if self.server:
            self.server.shutdown()
            self.thread.join()

class ExtensionSecurityAnalyzer:
    def __init__(self, config: AnalysisConfig = None):
        self.config = config or AnalysisConfig()
        self.cfg_builder = CFGBuilder(self.config)
        self.taint_analyzer = TaintAnalyzer(self.config)
        self.chrome_adaptor = ChromeAdaptor(self.config)
        self.zap_scanner = ZAPScanner(self.config) if self.config.scan_level == 'aggressive' else None

    async def full_analysis(self, extension_path: Path, scan_level: str) -> Dict:
        results = {
            "extension_id": extension_path.parent.name,
            "version": extension_path.name,
            "manifest_risks": [],
            "js_risks": [],
            "wasm_risks": [],
            "yara_findings": [],
            "dynamic_risks": [],
            "risk_score": 0,
            "risk_level": "low",
            "scan_progress": {
                "current": 0,
                "total": sum(1 for _ in extension_path.rglob("*") if _.is_file()),
                "status": "initializing"
            }
        }

        # Always analyze manifest and YARA rules
        # Manifest analysis
        manifest_path = extension_path.parent / "manifest.json"
        if (manifest_path.exists()):
            results["manifest_risks"] = await self.analyze_manifest(manifest_path)
            results["scan_progress"]["current"] += 1

        # File processing based on scan level
        processed_files = 0
        for file_path in extension_path.rglob("*"):
            if file_path.is_file():
                processed_files += 1
                results["scan_progress"]["current"] = processed_files
                results["scan_progress"]["status"] = f"Processing {file_path.name}"
                
                content = await self.read_file(file_path)
                if content:
                    results["yara_findings"].extend(self.yara_scan(content, file_path))
                    
                    if scan_level in ['medium', 'aggressive'] and file_path.suffix == ".js":
                        js_results = await self.analyze_js(content, file_path, scan_level)
                        results["js_risks"].extend(js_results["vulnerabilities"])
                    
                    if scan_level == 'aggressive' and file_path.suffix == ".wasm":
                        results["wasm_risks"].extend(await self.analyze_wasm(file_path))

        # Dynamic analysis
        if scan_level == 'aggressive':
            results["scan_progress"]["status"] = "Running dynamic analysis"
            results["dynamic_risks"] = await self.dynamic_analysis(extension_path)

        # Final calculation
        results["risk_score"] = self.calculate_risk_score(results, scan_level)
        results["risk_level"] = self.determine_risk_level(results["risk_score"])
        results["scan_progress"]["status"] = "complete"
        return results

    async def read_file(self, path: Path) -> Optional[str]:
        try:
            if path.suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.zip', '.pdf']:
                return None
            return await asyncio.to_thread(path.read_text, errors='ignore')
        except Exception as e:
            print(f"Error reading {path}: {str(e)}")
            return None

    async def analyze_manifest(self, manifest_path: Path) -> List[Dict]:
        risks = []
        try:
            content = await self.read_file(manifest_path)
            if not content:
                return [{"message": "Failed to read manifest", "level": "high"}]
                
            manifest = json.loads(content)
            permissions = set(manifest.get("permissions", []) + manifest.get("optional_permissions", []))
            dangerous = HIGH_RISK_PERMISSIONS.intersection(permissions)
            if dangerous:
                risks.append(f"High-risk permissions: {', '.join(sorted(dangerous))}")

            if (csp := manifest.get("content_security_policy")):
                if "unsafe-eval" in csp:
                    risks.append("CSP contains unsafe-eval")

        except json.JSONDecodeError:
            risks.append("Invalid JSON in manifest")
        return [{"message": msg, "level": "high"} for msg in risks]

    async def analyze_wasm(self, wasm_path: Path) -> List[Dict]:
        risks = []
        try:
            store = wasmtime.Store()
            with open(wasm_path, 'rb') as f:
                with wasmtime.Module.from_file(store.engine, f) as module:
                    if any(exp.type == 'memory' for exp in module.exports):
                        risks.append("WASM exports raw memory access")
                    
                    for imp in module.imports:
                        if imp.kind == 'function' and 'eval' in imp.name.lower():
                            risks.append(f"Suspicious function import: {imp.name}")
                    
                    if any(exp.name in ['mine', 'hash', 'compute'] for exp in module.exports):
                        risks.append("Potential cryptojacking detected")
                        
        except Exception as e:
            risks.append(f"WASM analysis error: {str(e)}")
        return [{"message": msg, "level": "high"} for msg in risks]

    async def analyze_js(self, code: str, file_path: Path, scan_level: str) -> Dict:
        analysis = {"vulnerabilities": [], "errors": []}
        try:
            # Preprocess modern JS features
            code = re.sub(r'\?\.', '_safe_.', code)
            
            parsed = esprima.parseScript(code, {'loc': True, 'tolerant': True})
            cfg = self.cfg_builder.build_from_ast(parsed)
            
            # Basic checks for all levels
            cfg_patterns = self.cfg_builder.detect_malicious_patterns(cfg)
            if cfg_patterns['obfuscation']:
                analysis["vulnerabilities"].append({
                    "type": "obfuscation",
                    "line": -1,
                    "file": str(file_path)
                })

            # Detailed analysis for aggressive
            if scan_level == 'aggressive':
                for node in nx.dfs_preorder_nodes(cfg):
                    self.chrome_adaptor.adapt(node)
                self.taint_analyzer.analyze(cfg)
                analysis["vulnerabilities"].extend(self._collect_vulnerabilities(cfg, file_path))

            # Sensitive APIs for medium+
            for api in cfg_patterns['sensitive_api_calls']:
                analysis["vulnerabilities"].append({
                    "type": "sensitive_api",
                    "api": api['api'],
                    "line": api['location'],
                    "file": str(file_path)
                })

        except Exception as e:
            analysis["errors"].append(str(e))
        return analysis

    async def dynamic_analysis(self, extension_path: Path) -> List[Dict]:
        try:
            server = ExtensionHTTPServer(extension_path)
            await server.start()
            
            target_url = f'http://localhost:{server.port}'
            alerts = await self.zap_scanner.scan(target_url)
            
            await server.stop()
            return [{
                "name": alert.get('name'),
                "risk": alert.get('risk'),
                "description": alert.get('description'),
                "url": alert.get('url')
            } for alert in alerts]
        except Exception as e:
            return [{"error": f"Dynamic analysis failed: {str(e)}"}]

    def calculate_risk_score(self, results: Dict, scan_level: str) -> float:
        score = 0
        # Base components
        score += len(results["manifest_risks"]) * 2
        score += len(results["yara_findings"]) * 1.5
        
        # JS analysis
        if scan_level in ['medium', 'aggressive']:
            score += len(results["js_risks"]) * 1.2
            score += sum(1 for vuln in results["js_risks"] if 'eval' in vuln.get('api', '')) * 2
        
        # Aggressive components
        if scan_level == 'aggressive':
            score += len(results["wasm_risks"]) * 3
            score += sum(1 for alert in results["dynamic_risks"] if alert.get('risk') == 'High') * 4
        
        return min(score, 100)

    def determine_risk_level(self, score: float) -> str:
        if score >= self.config.risk_thresholds['high']:
            return 'high'
        elif score >= self.config.risk_thresholds['medium']:
            return 'medium'
        return 'low'

    def yara_scan(self, content: str, file_path: Path) -> List[Dict]:
        matches = []
        try:
            for match in YARA_RULES.match(data=content):
                matches.append({
                    "file": str(file_path),
                    "rule": match.rule,
                    "strings": [str(s) for s in match.strings],
                    "meta": match.meta
                })
        except Exception as e:
            print(f"YARA error in {file_path}: {str(e)}")
        return matches

    def _collect_vulnerabilities(self, cfg: CFGNode, file_path: Path) -> List[Dict]:
        vulns = []
        for node in nx.dfs_preorder_nodes(cfg):
            if node.is_sink and node.tainted_vars:
                for var in node.tainted_vars:
                    labels = node.taint_labels.get(var, set())
                    vulns.append({
                        "type": "taint_flow",
                        "source": var,
                        "sink": self.cfg_builder._get_callee_name(node.ast_node.callee) if node.ast_node else "unknown",
                        "file": str(file_path),
                        "line": node.ast_node.loc.start.line if node.ast_node.loc else -1
                    })
        return vulns


@app.get("/scan-installed")
@limiter.limit("10/minute")
async def scan_installed(request: Request, scan_level: str = 'medium'):
    if scan_level not in ['low', 'medium', 'aggressive']:
        raise HTTPException(400, "Invalid scan level. Use 'low', 'medium', or 'aggressive'")

    extensions_path = Path(get_extensions_path())
    if not extensions_path.exists():
        raise HTTPException(404, "Extensions directory not found")

    config = AnalysisConfig()
    config.scan_level = scan_level
    analyzer = ExtensionSecurityAnalyzer(config)
    
    extensions = [d for d in extensions_path.iterdir() if d.is_dir()]
    total = len(extensions)
    results = []
    
    for idx, ext_dir in enumerate(extensions, 1):
        try:
            version_dirs = sorted(ext_dir.glob("*"), reverse=True)
            if version_dirs:
                analysis = await analyzer.full_analysis(version_dirs[0], scan_level)
                results.append({
                    "extension_id": analysis["extension_id"],
                    "version": analysis["version"],
                    "risk_score": analysis["risk_score"],
                    "risk_level": analysis["risk_level"],
                    "progress": f"{idx}/{total}"
                })
        except Exception as e:
            results.append({
                "extension_id": ext_dir.name,
                "error": str(e),
                "progress": f"{idx}/{total}"
            })

    return JSONResponse(content={"extensions": results})

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": f"Internal server error: {str(exc)}"}
    )

def get_extensions_path() -> str:
    system = platform.system()
    if system == "Linux":
        return os.path.expanduser("~/.config/google-chrome/Default/Extensions")
    elif system == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/Extensions")
    elif system == "Windows":
        return os.path.expandvars(r"%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Extensions")
    raise OSError(f"Unsupported OS: {system}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)