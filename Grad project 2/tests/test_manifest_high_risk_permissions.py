import json
import pytest
from main import ExtensionSecurityAnalyzer

@pytest.mark.asyncio
async def test_manifest_high_risk_permissions(tmp_path):
    manifest_data = {
        "permissions": ["debugger", "<all_urls>", "storage"],
        "content_security_policy": "script-src 'self';"
    }

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_data))

    analyzer = ExtensionSecurityAnalyzer()
    risks = await analyzer.analyze_manifest(manifest_path)

    assert any("High-risk permissions" in r['message'] for r in risks)

