import pytest
from pathlib import Path
from main import ExtensionSecurityAnalyzer, AnalysisConfig ,CFGBuilder, TaintAnalyzer, CFGNode

@pytest.fixture
def analyzer():
    config = AnalysisConfig()
    return ExtensionSecurityAnalyzer(config)

@pytest.mark.asyncio
async def test_analyze_manifest_high_risk(analyzer):
    manifest_content = '{"permissions": ["debugger", "storage"], "optional_permissions": [], "content_security_policy": ""}'
    manifest_path = Path("test_manifest.json")
    manifest_path.write_text(manifest_content)
    risks = await analyzer.analyze_manifest(manifest_path)
    assert any("High-risk permissions" in r["message"] for r in risks)
    manifest_path.unlink()

@pytest.mark.asyncio
async def test_analyze_manifest_invalid_json(analyzer):
    manifest_path = Path("test_invalid_manifest.json")
    manifest_path.write_text("{invalid json}")
    risks = await analyzer.analyze_manifest(manifest_path)
    assert any("Invalid JSON" in r["message"] for r in risks)
    manifest_path.unlink()

@pytest.mark.asyncio
async def test_read_file_nonexistent(analyzer):
    result = await analyzer.read_file(Path("nonexistent.file"))
    assert result is None

@pytest.mark.asyncio
async def test_analyze_js_obfuscation(analyzer, tmp_path):
    # JS code with obfuscation pattern (eval with hex escape)
    js_code = 'eval("\\x61\\x62\\x63");'
    js_path = tmp_path / "test.js"
    js_path.write_text(js_code)
    result = await analyzer.analyze_js(js_code, js_path, scan_level="medium")
    print("Obfuscation vulnerabilities:", result["vulnerabilities"])
    assert any(v.get("type") == "obfuscation" for v in result["vulnerabilities"]), (
        f"Expected obfuscation vulnerability, got: {result['vulnerabilities']}"
    )

@pytest.mark.asyncio
async def test_analyze_js_sensitive_api(analyzer, tmp_path):
    # JS code with sensitive API call
    js_code = 'chrome.runtime.sendMessage("test");'
    js_path = tmp_path / "test2.js"
    js_path.write_text(js_code)
    result = await analyzer.analyze_js(js_code, js_path, scan_level="medium")
    print("Sensitive API vulnerabilities:", result["vulnerabilities"])
    assert any(v.get("type") == "sensitive_api" for v in result["vulnerabilities"]), (
        f"Expected sensitive_api vulnerability, got: {result['vulnerabilities']}"
    )

@pytest.mark.asyncio
async def test_yara_scan_detects_eval(analyzer, tmp_path):
    # JS code with 'eval(' to trigger YARA rule
    js_code = 'eval("alert(1)");'
    js_path = tmp_path / "test3.js"
    js_path.write_text(js_code)
    findings = analyzer.yara_scan(js_code, js_path)
    assert any(f["rule"] == "SuspiciousPatterns" for f in findings)

@pytest.mark.asyncio
@pytest.mark.skipif("wasmtime" not in globals(), reason="wasmtime not installed")
async def test_analyze_wasm_handles_error(analyzer, tmp_path):
    # Provide invalid WASM file to trigger error handling
    wasm_path = tmp_path / "invalid.wasm"
    wasm_path.write_bytes(b"not a real wasm")
    results = await analyzer.analyze_wasm(wasm_path)
    assert any("error" in r["message"].lower() or "wasm" in r["message"].lower() for r in results)

# Add more tests for analyze_js, analyze_wasm, etc. as needed
