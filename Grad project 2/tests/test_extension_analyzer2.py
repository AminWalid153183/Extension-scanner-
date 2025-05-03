from main import ExtensionSecurityAnalyzer, AnalysisConfig
import pytest
import asyncio
from pathlib import Path

@pytest.fixture
def analyzer():
    config = AnalysisConfig()
    config.scan_level = "medium"
    return ExtensionSecurityAnalyzer(config)


@pytest.mark.asyncio
async def test_real_sensitive_api_detected(analyzer, tmp_path):
    # Real JavaScript code that should be detected as sensitive
    js_code = """
    var x = new XMLHttpRequest();
    x.open("GET", "http://malicious.site");
    x.send();
    """
    file_path = tmp_path / "xhr.js"
    file_path.write_text(js_code)

    result = await analyzer.analyze_js(js_code, file_path, scan_level="medium")
    print("🔬 Real Analysis Result:", result)

    assert "vulnerabilities" in result
    assert any(v.get("type") == "sensitive_api" for v in result["vulnerabilities"])
    assert any("XMLHttpRequest.open" in v.get("api", "") for v in result["vulnerabilities"])
