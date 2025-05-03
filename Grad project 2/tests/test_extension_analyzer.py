# tests/test_extension_analyzer.py

import json
import pytest
import asyncio
from pathlib import Path
from main import ExtensionSecurityAnalyzer, AnalysisConfig  # Make sure 'main' is your file name


@pytest.fixture
def analyzer():
    config = AnalysisConfig()
    config.scan_level = "medium"
    return ExtensionSecurityAnalyzer(config)


@pytest.mark.asyncio
async def test_analyze_manifest_detects_risks(tmp_path, analyzer):
    # Create dummy manifest.json with risky permissions and unsafe CSP
    manifest_data = {
        "permissions": ["debugger", "storage"],
        "optional_permissions": ["webRequest"],
        "content_security_policy": "script-src 'self' 'unsafe-eval';"
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data))

    results = await analyzer.analyze_manifest(manifest_path)

    assert any("debugger" in r["message"] for r in results)
    assert any("unsafe-eval" in r["message"] for r in results)
    assert all(r["level"] == "high" for r in results)


def test_determine_risk_level(analyzer):
    assert analyzer.determine_risk_level(30) == "high"
    assert analyzer.determine_risk_level(20) == "medium"
    assert analyzer.determine_risk_level(4) == "low"


def test_calculate_risk_score(analyzer):
    dummy_results = {
        "manifest_risks": [{} for _ in range(2)],     # 2 x 2 = 4
        "yara_findings": [{} for _ in range(3)],      # 3 x 1.5 = 4.5
        "js_risks": [{"api": "eval"}, {"api": "fetch"}],  # 2 x 1.2 + 1 x 2 = 4.4
        "wasm_risks": [],
        "dynamic_risks": []
    }
    score = analyzer.calculate_risk_score(dummy_results, scan_level="medium")
    assert round(score, 1) == 12.9


def test_yara_scan_detects_eval(analyzer, tmp_path):
    # Simulate a JS file with suspicious "eval(" usage
    file_path = tmp_path / "suspicious.js"
    file_path.write_text('var a = eval("2+2");')

    with open(file_path, 'r') as f:
        content = f.read()

    matches = analyzer.yara_scan(content, file_path)

    assert any("SuspiciousPatterns" == m["rule"] for m in matches)
    assert any("eval" in str(s).lower() for m in matches for s in m["strings"])


from unittest.mock import patch

@pytest.mark.asyncio
async def test_analyze_js_detects_sensitive_api_mocked(analyzer, tmp_path):
    js_code = "fetch('https://example.com/data');"
    file_path = tmp_path / "api.js"
    file_path.write_text(js_code)

    # Patch the method that detects sensitive APIs to return fake data
    with patch.object(analyzer.cfg_builder, 'detect_malicious_patterns') as mock_detect:
        mock_detect.return_value = {
            'obfuscation': False,
            'sensitive_api_calls': [
                {"api": "fetch", "location": 1}
            ],
            'suspicious_cycles': []
        }

        result = await analyzer.analyze_js(js_code, file_path, scan_level="medium")

    print("✅ Mocked JS Result:", result)

    assert "vulnerabilities" in result
    assert any(v.get("type") == "sensitive_api" for v in result["vulnerabilities"])
    assert any("fetch" in v.get("api", "") for v in result["vulnerabilities"])

def test_basic_setup():
    config = AnalysisConfig()
    analyzer = ExtensionSecurityAnalyzer(config)
    assert analyzer is not None
